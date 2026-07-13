#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
mkdir -p data results

TOTAL="${STRESS_TOTAL:-1000}"
THREADS="${STRESS_THREADS:-10}"

docker compose up -d --build kafka consumer
docker compose --profile tools run --rm stress-test python -m experiments.stress_test \
  --total "$TOTAL" --threads "$THREADS" --persistence-timeout 180

echo "Stress-test results are in $ROOT_DIR/results"
