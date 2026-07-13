#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
mkdir -p data results

ROUNDS="${ABLATION_ROUNDS:-500}"
STAMP="$(date +%Y%m%d-%H%M%S)"
RUN_A="${RUN_A:-ablation-A-$STAMP}"
RUN_B="${RUN_B:-ablation-B-$STAMP}"
WAF_OFF_OVERRIDE="$ROOT_DIR/results/compose-waf-off.yml"
WAF_ON_OVERRIDE="$ROOT_DIR/results/compose-waf-on.yml"

cat > "$WAF_OFF_OVERRIDE" <<'YAML'
services:
  vuln-web:
    environment:
      WAF_ENABLED: "false"
YAML

cat > "$WAF_ON_OVERRIDE" <<'YAML'
services:
  vuln-web:
    environment:
      WAF_ENABLED: "true"
YAML

check_waf_state() {
  expected="$1"
  actual="$(
    docker compose exec -T vuln-web python -c \
      'import json, urllib.request; print(str(json.load(urllib.request.urlopen("http://localhost:5000/config"))["waf_enabled"]).lower())'
  )"
  if [[ "$actual" != "$expected" ]]; then
    echo "Expected WAF state $expected, got $actual" >&2
    exit 3
  fi
  echo "Verified WAF state: $actual"
}

docker compose up -d --build kafka consumer dashboard

echo "Scenario A: exposed endpoint, WAF disabled"
docker compose -f docker-compose.yml -f "$WAF_OFF_OVERRIDE" up -d --build --force-recreate vuln-web
check_waf_state false
docker compose -f docker-compose.yml -f "$WAF_OFF_OVERRIDE" --profile demo run --rm --no-deps producer python -m producer.producer \
  --rounds "$ROUNDS" --probe sql_injection --run-id "$RUN_A" --scenario "A_no_waf" \
  --interval 0 --cycle-pause 0
docker compose --profile tools run --rm tools python -m tools.wait_for_records \
  --run-id "$RUN_A" --expected "$ROUNDS" --timeout 300

echo "Scenario B: simulated WAF enabled"
docker compose -f docker-compose.yml -f "$WAF_ON_OVERRIDE" up -d --build --force-recreate vuln-web
check_waf_state true
docker compose -f docker-compose.yml -f "$WAF_ON_OVERRIDE" --profile demo run --rm --no-deps producer python -m producer.producer \
  --rounds "$ROUNDS" --probe sql_injection --run-id "$RUN_B" --scenario "B_waf_enabled" \
  --interval 0 --cycle-pause 0
docker compose --profile tools run --rm tools python -m tools.wait_for_records \
  --run-id "$RUN_B" --expected "$ROUNDS" --timeout 300

docker compose --profile tools run --rm tools python -m tools.export_results \
  --run-id "$RUN_A" --compare-run-id "$RUN_B"
docker compose --profile tools run --rm tools python -m tools.export_results \
  --run-id "$RUN_B" --compare-run-id "$RUN_A"

echo "Completed $((ROUNDS * 2)) SQL observations. Results are in $ROOT_DIR/results"
