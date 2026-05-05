#!/usr/bin/env bash
# import_scans.sh — Import/reimport security scan results into DefectDojo.
#
# Multi-target design
# ───────────────────
# All target-specific variables are loaded from $RUN_OUTPUT_DIR/scan_meta.env
# which the CI workflow writes.  To scan a different app, change the CI inputs.
#
# Scan enable/disable
# ───────────────────
# ENABLE_<SCANNER>=false  → skip silently
# REQUIRE_<SCANNER>=true  → abort if output file is missing/empty
#
# Test-title namespacing
# ──────────────────────
# Every DefectDojo test title is prefixed with APP_NAME:
#   "nodegoat - Semgrep SAST", "dvna - Trivy Filesystem", etc.
#
# Engagement lookup — fix for HTTP 400
# ──────────────────────────────────────
# Some DefectDojo versions reject simultaneous use of `name=` + `product=`
# query parameters on /api/v2/engagements/ and return HTTP 400.
# The lookup uses a two-step approach:
#   Step A — combined name+product filter (fast path, most DD versions)
#   Step B — if Step A returns 4xx, fall back to product-only filter
#             and match the name client-side in Python.
# Every curl call captures the response body before checking HTTP status,
# so DD error messages are always visible in CI logs.

set -euo pipefail

# ── 1. Load scan metadata written by CI ────────────────────────────────────
META_FILE="${RUN_OUTPUT_DIR}/scan_meta.env"
if [[ ! -f "$META_FILE" ]]; then
  echo "ERROR: $META_FILE not found — was the CI setup step skipped?"
  exit 1
fi
sed 's/^[[:space:]]*//' "$META_FILE" > /tmp/_scan_meta_clean.env
# shellcheck disable=SC1091
source /tmp/_scan_meta_clean.env
rm -f /tmp/_scan_meta_clean.env

# ── 2. Validate required env vars ──────────────────────────────────────────
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

# ── 3. Scanner enable/disable defaults ─────────────────────────────────────
ENABLE_SEMGREP="${ENABLE_SEMGREP:-true}"
ENABLE_TRIVY_FS="${ENABLE_TRIVY_FS:-true}"
ENABLE_TRIVY_IMAGE="${ENABLE_TRIVY_IMAGE:-true}"
ENABLE_ZAP="${ENABLE_ZAP:-true}"

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

# curl_dd <label> [curl args...]
# ─────────────────────────────────────────────────────────────────────────────
# Wraps every DefectDojo API call with consistent error handling.
#
# Problem with --fail-with-body (the old approach):
#   curl exits with code 22 on HTTP 4xx/5xx and DISCARDS the response body
#   before this script can read it, making errors completely opaque in CI logs.
#
# This wrapper instead:
#   1. Writes the full response body to a temp file
#   2. Captures the HTTP status code via -w "%{http_code}"
#   3. On HTTP >= 400, prints the label, URL, status code, AND the full body
#      to stderr before returning non-zero — so you always see what DD said.
#   4. On success, writes the body to stdout for the caller to parse.
curl_dd() {
  local label="$1"; shift
  local tmp http_code body

  tmp=$(mktemp /tmp/dojo_curl_XXXXXX.json)

  # Capture HTTP status; body goes to tmp file; network errors still exit 1.
  http_code=$(curl -sS -w "%{http_code}" -o "$tmp" "$@") || {
    echo "ERROR [${label}]: curl network/TLS error (exit $?)" >&2
    echo "  Args: $*" >&2
    rm -f "$tmp"
    return 1
  }

  body=$(cat "$tmp"); rm -f "$tmp"

  if [[ "${http_code}" -ge 400 ]]; then
    echo "ERROR [${label}]: DefectDojo returned HTTP ${http_code}" >&2
    echo "  Response body : ${body:0:1000}" >&2
    echo "  Hint          : Check DOJO_URL, DOJO_TOKEN, DOJO_PRODUCT_ID," >&2
    echo "                  and that the product exists and the token has" >&2
    echo "                  permission to read/write it." >&2
    return 1
  fi

  printf '%s' "$body"
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

# find_engagement_by_name <product_id> <engagement_name>
# ─────────────────────────────────────────────────────────────────────────────
# Returns the engagement ID (printed to stdout), or empty string if not found.
#
# Step A — combined name+product filter: fast and correct on most DD versions.
#           Some versions reject this with HTTP 400 (unrecognised `name=` param).
#
# Step B — if Step A gets a 4xx, fall back to product-only filter (paginated
#           up to 200 results) and match the engagement name client-side.
#           Prints a visible WARN so you know which path was taken.
find_engagement_by_name() {
  local product_id="$1"
  local eng_name="$2"
  local encoded_name encoded_product tmp http_code body

  encoded_name=$(urlencode "$eng_name")
  encoded_product=$(urlencode "$product_id")

  # ── Step A ──────────────────────────────────────────────────────────────
  tmp=$(mktemp /tmp/dojo_eng_XXXXXX.json)
  http_code=$(curl -sS -w "%{http_code}" -o "$tmp" \
    -H "Authorization: Token ${DOJO_TOKEN}" \
    "${DOJO_URL}/api/v2/engagements/?name=${encoded_name}&product=${encoded_product}&limit=1")
  body=$(cat "$tmp"); rm -f "$tmp"

  if [[ "${http_code}" == "200" ]]; then
    printf '%s' "$body" | extract_first_id
    return 0
  fi

  # ── Step B ──────────────────────────────────────────────────────────────
  echo "WARN [find_engagement]: combined name+product filter returned HTTP ${http_code}." >&2
  echo "     DD body (first 400 chars): ${body:0:400}" >&2
  echo "     Falling back to product-only filter + client-side name match..." >&2

  tmp=$(mktemp /tmp/dojo_eng_XXXXXX.json)
  http_code=$(curl -sS -w "%{http_code}" -o "$tmp" \
    -H "Authorization: Token ${DOJO_TOKEN}" \
    "${DOJO_URL}/api/v2/engagements/?product=${encoded_product}&limit=200")
  body=$(cat "$tmp"); rm -f "$tmp"

  if [[ "${http_code}" -ge 400 ]]; then
    echo "ERROR [find_engagement]: product-only fallback also returned HTTP ${http_code}" >&2
    echo "  Body: ${body:0:800}" >&2
    return 1
  fi

  printf '%s' "$body" | ENG_NAME="$eng_name" python3 -c "
import json, sys, os
target = os.environ['ENG_NAME']
raw = sys.stdin.read().strip()
try:
    payload = json.loads(raw)
except json.JSONDecodeError as e:
    print('ERROR: invalid JSON from product-only filter: ' + str(e), file=sys.stderr)
    sys.exit(1)
results = payload.get('results') or []
match = next((r for r in results if r.get('name') == target), None)
print(match['id'] if match else '')
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
  echo "Response body:"
  cat /tmp/dojo_check.txt
  exit 1
fi
echo "DefectDojo reachable (HTTP $http_code)"

# ── Engagement: get or create ─────────────────────────────────────────────

get_or_create_engagement() {
  local engagement_id
  engagement_id=$(find_engagement_by_name "$DOJO_PRODUCT_ID" "$DOJO_ENGAGEMENT_NAME") \
    || { echo "ERROR: engagement lookup failed — see errors above" >&2; exit 1; }

  if [[ -n "$engagement_id" ]]; then
    echo "Updating existing engagement ${engagement_id} metadata..." >&2
    curl_dd "engagement-patch" -X PATCH \
      "${DOJO_URL}/api/v2/engagements/${engagement_id}/" \
      -H "Authorization: Token ${DOJO_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "$(metadata_json)" > /dev/null \
      || { echo "ERROR: engagement metadata patch failed" >&2; exit 1; }
    echo "$engagement_id"
    return 0
  fi

  # Create a new engagement
  local encoded_lead lead_payload lead_id
  encoded_lead=$(urlencode "$DOJO_ENGAGEMENT_LEAD_USERNAME")

  lead_payload=$(curl_dd "user-lookup" \
    -H "Authorization: Token ${DOJO_TOKEN}" \
    "${DOJO_URL}/api/v2/users/?username=${encoded_lead}&limit=1") \
    || { echo "ERROR: user lookup failed" >&2; exit 1; }

  lead_id=$(echo "$lead_payload" | extract_first_id)
  if [[ -z "$lead_id" ]]; then
    echo "ERROR: DefectDojo user not found: ${DOJO_ENGAGEMENT_LEAD_USERNAME}" >&2
    exit 1
  fi

  local target_start target_end payload created
  target_start=$(date -u +%Y-%m-%d)
  target_end=$(date -u -d "+7 days" +%Y-%m-%d)

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

  created=$(curl_dd "engagement-create" -X POST \
    "${DOJO_URL}/api/v2/engagements/" \
    -H "Authorization: Token ${DOJO_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$payload") || { echo "ERROR: engagement creation failed" >&2; exit 1; }

  echo "$created" | extract_id
}

# ── Test lookup ───────────────────────────────────────────────────────────

find_existing_test() {
  local scan_type="$1"
  local test_title="$2"
  local encoded_type encoded_title result

  encoded_type=$(urlencode "$scan_type")
  encoded_title=$(urlencode "$test_title")

  result=$(curl_dd "test-lookup [${test_title}]" \
    -H "Authorization: Token ${DOJO_TOKEN}" \
    "${DOJO_URL}/api/v2/tests/?engagement=${DOJO_ENGAGEMENT_ID}&test_type_name=${encoded_type}&title=${encoded_title}&limit=1") \
    || { echo "ERROR: test lookup failed for [${test_title}]" >&2; exit 1; }

  echo "$result" | extract_first_id
}

# ── Import or reimport a single scan ─────────────────────────────────────

import_or_reimport() {
  local scan_type="$1"
  local file_path="$2"
  local min_sev="$3"
  local mime="$4"
  local label="$5"

  local test_title="${APP_NAME} - ${label}"
  local test_id response

  test_id=$(find_existing_test "$scan_type" "$test_title")

  if [[ -n "$test_id" ]]; then
    echo "Reimporting (test ${test_id}) [${test_title}]: ${scan_type} <- ${file_path}"
    response=$(curl_dd "reimport [${test_title}]" -X POST \
      "${DOJO_URL}/api/v2/reimport-scan/" \
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
      || { echo "ERROR: reimport-scan failed for [${test_title}]" >&2; exit 1; }
  else
    echo "Importing (first run) [${test_title}]: ${scan_type} <- ${file_path}"
    response=$(curl_dd "import [${test_title}]" -X POST \
      "${DOJO_URL}/api/v2/import-scan/" \
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
      || { echo "ERROR: import-scan failed for [${test_title}]" >&2; exit 1; }
  fi

  log_import_response "${test_title}" "$response"
}

# ── Gate: check scan file before importing ───────────────────────────────

check_scan_file() {
  local scanner="$1"
  local file="$2"
  local enabled="$3"
  local required="$4"

  if [[ "$enabled" != "true" ]]; then
    echo "SKIP [${scanner}]: disabled via ENABLE flag"
    return 1
  fi

  if [[ ! -s "$file" ]]; then
    if [[ "$required" == "true" ]]; then
      echo "ERROR [${scanner}]: output file missing or empty: ${file}"
      echo "       Scanner is marked REQUIRE=true — aborting."
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

check_scan_file "semgrep"     "${RUN_OUTPUT_DIR}/semgrep.json"     "$ENABLE_SEMGREP"     "$REQUIRE_SEMGREP" \
  && import_or_reimport "${SCAN_TYPE_SEMGREP}"     "${RUN_OUTPUT_DIR}/semgrep.json"     "Low" "application/json" "Semgrep SAST" \
  || true

check_scan_file "trivy_fs"    "${RUN_OUTPUT_DIR}/trivy_fs.json"    "$ENABLE_TRIVY_FS"    "$REQUIRE_TRIVY_FS" \
  && import_or_reimport "${SCAN_TYPE_TRIVY_FS}"    "${RUN_OUTPUT_DIR}/trivy_fs.json"    "Low" "application/json" "Trivy Filesystem" \
  || true

check_scan_file "trivy_image" "${RUN_OUTPUT_DIR}/trivy_image.json" "$ENABLE_TRIVY_IMAGE" "$REQUIRE_TRIVY_IMAGE" \
  && import_or_reimport "${SCAN_TYPE_TRIVY_IMAGE}" "${RUN_OUTPUT_DIR}/trivy_image.json" "Low" "application/json" "Trivy Image" \
  || true

check_scan_file "zap"         "${RUN_OUTPUT_DIR}/zap.xml"          "$ENABLE_ZAP"         "$REQUIRE_ZAP" \
  && import_or_reimport "${SCAN_TYPE_ZAP}"         "${RUN_OUTPUT_DIR}/zap.xml"          "Low" "text/xml"         "ZAP Baseline" \
  || true

echo ""
echo "All enabled scans processed successfully for app: ${APP_NAME}"
