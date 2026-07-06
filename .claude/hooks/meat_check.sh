#!/usr/bin/env bash
# Stop hook: gate meat exploit-analysis cases before the session ends.
# Runs `meat check` on any case updated in the last ~2h; if a case has invariant
# violations (value not conserved, missing provenance, money-out tx not fetched
# in full), it blocks Stop with the reason so a wrong conclusion cannot be called
# "done". Fails open (exit 0) on any infrastructure problem so it never wedges a
# session for unrelated work.
set -u

REPO="/Users/martinetlee/Project/Personal/meat-evm"
CASES_DIR="$REPO/cases"
PY="$REPO/.venv/bin/python3"

[ -x "$PY" ] || exit 0
[ -d "$CASES_DIR" ] || exit 0

# Find cases whose case.json changed in the last 120 minutes.
recent=$(find "$CASES_DIR" -maxdepth 2 -name case.json -mmin -120 2>/dev/null)
[ -n "$recent" ] || exit 0

problems=""
while IFS= read -r cj; do
    [ -n "$cj" ] || continue
    case_dir=$(dirname "$cj")
    name=$(basename "$case_dir")
    report=$(cd "$REPO" && "$PY" -m meat check "$name" 2>/dev/null)
    [ -n "$report" ] || continue
    passed=$(printf '%s' "$report" | "$PY" -c 'import json,sys; print(json.load(sys.stdin).get("passed"))' 2>/dev/null)
    if [ "$passed" = "False" ]; then
        details=$(printf '%s' "$report" | "$PY" -c '
import json,sys
r=json.load(sys.stdin)
for v in r.get("violations",[]):
    print("  - ["+v.get("invariant","")+"] "+v.get("detail",""))
' 2>/dev/null)
        problems="${problems}\nCase '${name}' fails meat check:\n${details}"
    fi
done <<< "$recent"

if [ -n "$problems" ]; then
    reason=$(printf 'meat check found unresolved invariant violations. Do not conclude the analysis until these are resolved (identify/label who moved the money, record provenance for attacker/victim labels, or explicitly waive):%b\n\nRun `python3 -m meat check <case>` to see the full report.' "$problems")
    "$PY" - "$reason" <<'PYEOF'
import json,sys
print(json.dumps({"decision":"block","reason":sys.argv[1]}))
PYEOF
    exit 0
fi

exit 0
