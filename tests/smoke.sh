#!/usr/bin/env sh
set -eu

BASE_URL="${1:-http://localhost:18080}"

TOKEN="$(curl -sS "$BASE_URL/sample_token" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
DEC_RESULT="$(curl -sS -X POST "$BASE_URL/decrypt" -H 'Content-Type: application/json' -d "{\"token\":\"$TOKEN\"}")"
printf "%s\n" "$DEC_RESULT" | grep -q '"result":"ok"'

echo "Smoke test passed for $BASE_URL"
