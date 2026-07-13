#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ "${1:-}" != "--yes" ]]; then
  echo "This removes local experiment databases and generated results."
  echo "Re-run as: $0 --yes"
  exit 2
fi

docker compose down --remove-orphans
find "$ROOT_DIR/data" -maxdepth 1 -type f ! -name '.gitkeep' -delete
find "$ROOT_DIR/results" -maxdepth 1 -type f ! -name '.gitkeep' -delete
echo "Experiment data reset."

