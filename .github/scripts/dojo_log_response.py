#!/usr/bin/env python3
"""
dojo_log_response.py  —  Parse and log a DefectDojo import/reimport-scan response.

Usage: python3 dojo_log_response.py <label> <json_file>

Reads the JSON response written to <json_file>, extracts the key metrics
(test_id, total findings imported, active findings, duplicates), and prints
a one-line summary.  Also dumps the top-level response keys so the structure
is visible in CI logs — useful for diagnosing unknown DD versions.

Intentionally generic: it does not know about APP_NAME, scan types, or
target apps.  The caller passes a human-readable <label> (which already
includes the namespaced test title, e.g. "juice-shop - Semgrep SAST").
"""
import json
import sys

if len(sys.argv) < 3:
    print("Usage: dojo_log_response.py <label> <json_file>")
    sys.exit(1)

label    = sys.argv[1]
tmp_path = sys.argv[2]

with open(tmp_path) as fh:
    raw = fh.read().strip()

# ── Parse ──────────────────────────────────────────────────────────────────
try:
    d = json.loads(raw)
except Exception as e:
    print(f"[{label}] ERROR parsing DD response: {e}")
    print(f"RAW (first 800 chars): {raw[:800]}")
    sys.exit(0)

# Always show top-level keys — helps identify response schema across DD versions
top_keys = list(d.keys()) if isinstance(d, dict) else type(d).__name__
print(f"[{label}] DEBUG response keys: {top_keys}")

# ── Error check ────────────────────────────────────────────────────────────
# Collect whichever error field DD chose to populate (varies by version).
errors = (
    d.get("error")
    or d.get("message")
    or d.get("detail")
    or d.get("non_field_errors")
)
if errors:
    print(f"[{label}] WARNING DD reported: {errors}")
    sys.exit(0)

# ── test_id ────────────────────────────────────────────────────────────────
test_val = d.get("test")
tid = test_val.get("id") if isinstance(test_val, dict) else test_val

# ── Findings counts ───────────────────────────────────────────────────────
# Three response shapes are handled, from newest to oldest:
#
#   Current DD  — d["statistics"] is a flat dict:
#                   { "total": N, "active": N, "duplicate": N, … }
#
#   Legacy DD   — d["statistics"]["after"]["findings"]["total"]
#
#   Oldest DD   — d["total_imported_findings"] / d["new_findings"]

stats = d.get("statistics") or {}

if isinstance(stats, dict) and "total" in stats:
    total_f  = stats.get("total", "?")
    active_f = stats.get("active", "?")
    dupe_f   = stats.get("duplicate", "?")
elif isinstance(stats, dict) and "after" in stats:
    after      = stats.get("after") or {}
    findings_s = after.get("findings") or {}
    total_f  = findings_s.get("total")  or after.get("total")  or "?"
    active_f = findings_s.get("opened") or after.get("opened") or "?"
    dupe_f   = "?"
else:
    total_f  = d.get("total_imported_findings") or d.get("findings_count") or "?"
    active_f = d.get("new_findings") or "?"
    dupe_f   = "?"

print(f"[{label}] OK  test_id={tid} | total={total_f} | active={active_f} | dupes={dupe_f}")
