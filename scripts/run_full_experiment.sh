#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
mkdir -p data results

ROUNDS="${ROUNDS:-365}"
RUN_ID="${RUN_ID:-full-$(date +%Y%m%d-%H%M%S)}"
SCENARIO="${SCENARIO:-baseline_no_waf}"
WAF_ENABLED="${WAF_ENABLED:-false}"
EXPECTED=$((ROUNDS * 5))
export WAF_ENABLED

echo "Starting full experiment: run_id=$RUN_ID rounds=$ROUNDS expected_events=$EXPECTED waf=$WAF_ENABLED"
docker compose up -d --build kafka vuln-web consumer dashboard
docker compose --profile demo run --rm \
  -e SCENARIO="$SCENARIO" \
  producer python -m producer.producer \
  --rounds "$ROUNDS" --probe all --run-id "$RUN_ID" --scenario "$SCENARIO"

docker compose --profile tools run --rm tools \
  python -m tools.wait_for_records --run-id "$RUN_ID" --expected "$EXPECTED" --timeout 600
docker compose --profile tools run --rm tools \
  python -m tools.export_results --run-id "$RUN_ID"

echo "Completed. Results are in $ROOT_DIR/results"
