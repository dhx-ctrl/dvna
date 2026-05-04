#!/usr/bin/env bash
# import_scans.sh — Import/reimport security scan results into DefectDojo.
#
# Multi-target design
# ───────────────────
# All target-specific variables are loaded from $RUN_OUTPUT_DIR/scan_meta.env
# which the CI workflow writes.  You never hard-code app names or product IDs
# here.  To scan a different Node.js app, change the CI inputs — this script
# does not need to be touched.
#
# Scan enable/disable
# ───────────────────
# Each scanner has two controls:
#   ENABLE_<SCANNER>=false  → skip silently (scanner was not run in CI)
#   REQUIRE_<SCANNER>=true  → if the output file is missing/empty, abort the
#                             whole import (use for scanners that must not be
#                             silently absent)
#
# Test-title namespacing
# ──────────────────────
# Every DefectDojo test title is prefixed with APP_NAME, e.g.:
#   "juice-shop - Semgrep SAST"
#   "dvna - Trivy Filesystem"
# This prevents findings from different apps colliding inside the same
# DefectDojo product when DOJO_PRODUCT_ID is shared, and makes the Tests
# list human-readable.

set -euo pipefail

# ── 1. Load scan metadata written by CI ────────────────────────────────────
META_FILE="${RUN_OUTPUT_DIR}/scan_meta.env"
if [[ ! -f "$META_FILE" ]]; then
  echo "ERROR: $META_FILE not found — was the CI setup step skipped?"
  exit 1
fi
# Strip leading whitespace that heredoc indentation may have added, then source.
sed 's/^[[:space:]]*//' "$META_FILE" > /tmp/_scan_meta_clean.env
# shellcheck disable=SC1091
source /tmp/_scan_meta_clean.env
rm -f /tmp/_scan_meta_clean.env

# ── 2. Validate required env vars (always needed) ──────────────────────────
required_always=(
  DOJO_URL DOJO_TOKEN DOJO_PRODUCT_ID
  DOJO_ENGAGEMENT_NAME DOJO_ENGAGEMENT_LEAD_USERNAME
  SCAN_TYPE_TRIVY_FS SCAN_TYPE_TRIVY_IMAGE SCAN_TYPE_ZAP SCAN_TYPE_SEMGREP
  BUILD_ID COMMIT_HASH BRANCH_TAG REPO_URI TEST_STRATEGY
  RUN_OUTPUT_DIR APP_NAME
)
for v in "${required_always[@]}"; do
  if [[ -z "${!v:-}" ]]; then
    echo "ERROR: Required env var missing or empty: $v"
    exit 1
  fi
done

# ── 3. Enable/disable defaults (true unless CI explicitly set false) ────────
ENABLE_SEMGREP="${ENABLE_SEMGREP:-true}"
ENABLE_TRIVY_FS="${ENABLE_TRIVY_FS:-true}"
ENABLE_TRIVY_IMAGE="${ENABLE_TRIVY_IMAGE:-true}"
ENABLE_ZAP="${ENABLE_ZAP:-true}"

# Set any of these to "true" to make a missing output file a hard failure.
REQUIRE_SEMGREP="${REQUIRE_SEMGREP:-false}"
REQUIRE_TRIVY_FS="${REQUIRE_TRIVY_FS:-false}"
REQUIRE_TRIVY_IMAGE="${REQUIRE_TRIVY_IMAGE:-false}"
REQUIRE_ZAP="${REQUIRE_ZAP:-false}"

echo "════════════════════════════════════════════════════════════════"
echo " DefectDojo import — target: ${APP_NAME}  product: ${DOJO_PRODUCT_ID}"
echo " Scanners → semgrep=${ENABLE_SEMGREP}  trivy_fs=${ENABLE_TRIVY_FS}  trivy_image=${ENABLE_TRIVY_IMAGE}  zap=${ENABLE_ZAP}"
echo "════════════════════════════════════════════════════════════════"

# ── Helpers ────────────────────────────────────────────────────────────────

urlencode() {
  python3 -c "import sys; from urllib.parse import quote; print(quote(sys.argv[1]))" "$1"
}

extract_first_id() {
  python3 -c "
import json, sys
raw = sys.stdin.read().strip()
if not raw:
    sys.exit(0)
try:
    payload = json.loads(raw)
except json.JSONDecodeError as e:
    print('ERROR: invalid JSON: ' + str(e), file=sys.stderr)
    sys.exit(1)
results = payload.get('results') or []
print(results[0].get('id', '') if results else '')
"
}

extract_id() {
  python3 -c "
import json, sys
raw = sys.stdin.read().strip()
if not raw:
    sys.exit(0)
try:
    payload = json.loads(raw)
except json.JSONDecodeError as e:
    print('ERROR: invalid JSON: ' + str(e), file=sys.stderr)
    sys.exit(1)
print(payload.get('id', ''))
"
}

metadata_json() {
  BUILD_ID="$BUILD_ID" COMMIT_HASH="$COMMIT_HASH" BRANCH_TAG="$BRANCH_TAG" \
  REPO_URI="$REPO_URI" TEST_STRATEGY="$TEST_STRATEGY" \
  python3 -c "
import json, os
print(json.dumps({
    'build_id':                    os.environ['BUILD_ID'],
    'commit_hash':                 os.environ['COMMIT_HASH'],
    'branch_tag':                  os.environ['BRANCH_TAG'],
    'source_code_management_uri':  os.environ['REPO_URI'],
    'test_strategy':               os.environ['TEST_STRATEGY'],
    'deduplication_on_engagement': False,
}))
"
}

log_import_response() {
  local label="$1"
  local response="$2"
  local tmp
  tmp=$(mktemp /tmp/dojo_resp_XXXXXX.json)
  printf '%s' "$response" > "$tmp"
  python3 "$(dirname "$0")/dojo_log_response.py" "$label" "$tmp"
  rm -f "$tmp"
}

# ── Connectivity check ────────────────────────────────────────────────────

echo "Checking DefectDojo connectivity..."
http_code=$(curl -o /tmp/dojo_check.txt -sS -w "%{http_code}" \
  -H "Authorization: Token ${DOJO_TOKEN}" \
  "${DOJO_URL}/api/v2/users/?limit=1")

if [[ "$http_code" != "200" ]]; then
  echo "ERROR: DefectDojo returned HTTP $http_code — check DOJO_URL and DOJO_TOKEN"
  cat /tmp/dojo_check.txt
  exit 1
fi
echo "DefectDojo reachable (HTTP $http_code)"

# ── Engagement: get or create ─────────────────────────────────────────────

get_or_create_engagement() {
  local encoded_name
  encoded_name=$(urlencode "$DOJO_ENGAGEMENT_NAME")

  local existing
  existing=$(curl --fail-with-body -sS \
    -H "Authorization: Token ${DOJO_TOKEN}" \
    "${DOJO_URL}/api/v2/engagements/?name=${encoded_name}&product=${DOJO_PRODUCT_ID}&limit=1") \
    || { echo "ERROR: engagement lookup failed" >&2; exit 1; }

  local engagement_id
  engagement_id=$(echo "$existing" | extract_first_id)

  if [[ -n "$engagement_id" ]]; then
    echo "Updating existing engagement ${engagement_id} metadata..." >&2
    curl --fail-with-body -sS -X PATCH \
      "${DOJO_URL}/api/v2/engagements/${engagement_id}/" \
      -H "Authorization: Token ${DOJO_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "$(metadata_json)" > /dev/null \
      || { echo "ERROR: engagement metadata patch failed" >&2; exit 1; }
    echo "$engagement_id"
    return 0
  fi

  # Create new engagement
  local encoded_lead
  encoded_lead=$(urlencode "$DOJO_ENGAGEMENT_LEAD_USERNAME")

  local lead_payload lead_id
  lead_payload=$(curl --fail-with-body -sS \
    -H "Authorization: Token ${DOJO_TOKEN}" \
    "${DOJO_URL}/api/v2/users/?username=${encoded_lead}&limit=1") \
    || { echo "ERROR: user lookup failed" >&2; exit 1; }

  lead_id=$(echo "$lead_payload" | extract_first_id)
  if [[ -z "$lead_id" ]]; then
    echo "ERROR: DefectDojo user not found: ${DOJO_ENGAGEMENT_LEAD_USERNAME}" >&2
    exit 1
  fi

  local target_start target_end
  target_start=$(date -u +%Y-%m-%d)
  target_end=$(date -u -d "+7 days" +%Y-%m-%d)

  local payload created
  payload=$(
    TARGET_START="$target_start" TARGET_END="$target_end" LEAD_ID="$lead_id" \
    BUILD_ID="$BUILD_ID" COMMIT_HASH="$COMMIT_HASH" BRANCH_TAG="$BRANCH_TAG" \
    REPO_URI="$REPO_URI" TEST_STRATEGY="$TEST_STRATEGY" \
    python3 -c "
import json, os
print(json.dumps({
    'name':                        os.environ['DOJO_ENGAGEMENT_NAME'],
    'product':                     int(os.environ['DOJO_PRODUCT_ID']),
    'status':                      'In Progress',
    'engagement_type':             'CI/CD',
    'target_start':                os.environ['TARGET_START'],
    'target_end':                  os.environ['TARGET_END'],
    'lead':                        int(os.environ['LEAD_ID']),
    'build_id':                    os.environ['BUILD_ID'],
    'commit_hash':                 os.environ['COMMIT_HASH'],
    'branch_tag':                  os.environ['BRANCH_TAG'],
    'source_code_management_uri':  os.environ['REPO_URI'],
    'test_strategy':               os.environ['TEST_STRATEGY'],
    'deduplication_on_engagement': False,
}))")

  created=$(curl --fail-with-body -sS -X POST "${DOJO_URL}/api/v2/engagements/" \
    -H "Authorization: Token ${DOJO_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$payload") || { echo "ERROR: engagement creation failed: $created" >&2; exit 1; }

  echo "$created" | extract_id
}

# ── Test lookup ───────────────────────────────────────────────────────────
# Title includes APP_NAME so tests from different apps never collide even
# when they share the same engagement or product.
find_existing_test() {
  local scan_type="$1"
  local test_title="$2"
  local encoded_type encoded_title
  encoded_type=$(urlencode "$scan_type")
  encoded_title=$(urlencode "$test_title")

  local result
  result=$(curl --fail-with-body -sS \
    -H "Authorization: Token ${DOJO_TOKEN}" \
    "${DOJO_URL}/api/v2/tests/?engagement=${DOJO_ENGAGEMENT_ID}&test_type_name=${encoded_type}&title=${encoded_title}&limit=1") \
    || { echo "ERROR: test lookup failed for [${test_title}]" >&2; exit 1; }

  echo "$result" | extract_first_id
}

# ── Import or reimport a single scan ─────────────────────────────────────
# Args:
#   $1  scan_type   — DefectDojo parser name (e.g. "Trivy Scan")
#   $2  file_path   — absolute path to the scan output file
#   $3  min_sev     — minimum severity to import (e.g. "Low")
#   $4  mime        — MIME type of the file
#   $5  label       — human-readable label used in the test title
#                     (will be prefixed with APP_NAME automatically)
import_or_reimport() {
  local scan_type="$1"
  local file_path="$2"
  local min_sev="$3"
  local mime="$4"
  local label="$5"

  # Namespace the title with the app name so tests from different apps
  # are always distinct inside DefectDojo.
  local test_title="${APP_NAME} - ${label}"

  local test_id
  test_id=$(find_existing_test "$scan_type" "$test_title")

  local response
  if [[ -n "$test_id" ]]; then
    echo "Reimporting (test ${test_id}) [${test_title}]: ${scan_type} <- ${file_path}"
    response=$(curl --fail-with-body -sS -X POST "${DOJO_URL}/api/v2/reimport-scan/" \
      -H "Authorization: Token ${DOJO_TOKEN}" \
      -F "active=true" \
      -F "verified=false" \
      -F "close_old_findings=true" \
      -F "deduplication_on_engagement=false" \
      -F "test=${test_id}" \
      -F "scan_type=${scan_type}" \
      -F "test_title=${test_title}" \
      -F "minimum_severity=${min_sev}" \
      -F "product=${DOJO_PRODUCT_ID}" \
      -F "engagement=${DOJO_ENGAGEMENT_ID}" \
      -F "file=@${file_path};type=${mime}") \
      || { echo "ERROR: reimport-scan curl failed for [${test_title}]" >&2; exit 1; }
  else
    echo "Importing (first run) [${test_title}]: ${scan_type} <- ${file_path}"
    response=$(curl --fail-with-body -sS -X POST "${DOJO_URL}/api/v2/import-scan/" \
      -H "Authorization: Token ${DOJO_TOKEN}" \
      -F "active=true" \
      -F "verified=false" \
      -F "close_old_findings=false" \
      -F "deduplication_on_engagement=false" \
      -F "scan_type=${scan_type}" \
      -F "test_title=${test_title}" \
      -F "minimum_severity=${min_sev}" \
      -F "product=${DOJO_PRODUCT_ID}" \
      -F "engagement=${DOJO_ENGAGEMENT_ID}" \
      -F "file=@${file_path};type=${mime}") \
      || { echo "ERROR: import-scan curl failed for [${test_title}]" >&2; exit 1; }
  fi

  log_import_response "${test_title}" "$response"
}

# ── Gate: check a scan file before importing ─────────────────────────────
# Returns 0 (proceed) or 1 (skip / abort).
check_scan_file() {
  local scanner="$1"   # human label for messages
  local file="$2"      # absolute path
  local enabled="$3"   # "true" | "false"
  local required="$4"  # "true" | "false"

  if [[ "$enabled" != "true" ]]; then
    echo "SKIP [${scanner}]: disabled via ENABLE flag"
    return 1
  fi

  if [[ ! -s "$file" ]]; then
    if [[ "$required" == "true" ]]; then
      echo "ERROR [${scanner}]: output file missing or empty: ${file}"
      echo "       Scanner is marked REQUIRE_${scanner^^}=true — aborting."
      exit 1
    else
      echo "WARN [${scanner}]: output file missing or empty: ${file} — skipping"
      return 1
    fi
  fi

  echo "OK [${scanner}]: $(wc -c < "$file") bytes — proceeding with import"
  return 0
}

# ── Resolve / create engagement ───────────────────────────────────────────

echo "RUN_OUTPUT_DIR=${RUN_OUTPUT_DIR}"
if [[ ! -d "${RUN_OUTPUT_DIR}" ]]; then
  echo "ERROR: RUN_OUTPUT_DIR does not exist: ${RUN_OUTPUT_DIR}"
  exit 1
fi

DOJO_ENGAGEMENT_ID=$(get_or_create_engagement)
if [[ -z "$DOJO_ENGAGEMENT_ID" ]]; then
  echo "ERROR: Failed to resolve engagement ID"
  exit 1
fi
export DOJO_ENGAGEMENT_ID
echo "Engagement ID: ${DOJO_ENGAGEMENT_ID}"

ls -la "${RUN_OUTPUT_DIR}"

# ── Import each scanner's output ─────────────────────────────────────────
# check_scan_file returns 1 (skip) when disabled or file absent;
# the `|| true` lets the script continue to the next scanner.

check_scan_file "semgrep" "${RUN_OUTPUT_DIR}/semgrep.json" "$ENABLE_SEMGREP" "$REQUIRE_SEMGREP" \
  && import_or_reimport "${SCAN_TYPE_SEMGREP}" "${RUN_OUTPUT_DIR}/semgrep.json" "Low" "application/json" "Semgrep SAST" \
  || true

check_scan_file "trivy_fs" "${RUN_OUTPUT_DIR}/trivy_fs.json" "$ENABLE_TRIVY_FS" "$REQUIRE_TRIVY_FS" \
  && import_or_reimport "${SCAN_TYPE_TRIVY_FS}" "${RUN_OUTPUT_DIR}/trivy_fs.json" "Low" "application/json" "Trivy Filesystem" \
  || true

check_scan_file "trivy_image" "${RUN_OUTPUT_DIR}/trivy_image.json" "$ENABLE_TRIVY_IMAGE" "$REQUIRE_TRIVY_IMAGE" \
  && import_or_reimport "${SCAN_TYPE_TRIVY_IMAGE}" "${RUN_OUTPUT_DIR}/trivy_image.json" "Low" "application/json" "Trivy Image" \
  || true

check_scan_file "zap" "${RUN_OUTPUT_DIR}/zap.xml" "$ENABLE_ZAP" "$REQUIRE_ZAP" \
  && import_or_reimport "${SCAN_TYPE_ZAP}" "${RUN_OUTPUT_DIR}/zap.xml" "Low" "text/xml" "ZAP Baseline" \
  || true

echo ""
echo "All enabled scans processed successfully for app: ${APP_NAME}"
