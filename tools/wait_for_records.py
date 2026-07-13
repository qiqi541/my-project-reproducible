from __future__ import annotations

import argparse
import sqlite3
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Wait until a run has the expected durable record count")
    parser.add_argument("--db", type=Path, default=Path("/data/passwords.db"))
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--expected", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=300.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    deadline = time.monotonic() + args.timeout
    count = 0
    while time.monotonic() < deadline:
        try:
            connection = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True, timeout=2)
            count = connection.execute(
                "SELECT COUNT(*) FROM attack_logs WHERE run_id=?", (args.run_id,)
            ).fetchone()[0]
            connection.close()
            print(f"run_id={args.run_id} persisted={count}/{args.expected}", flush=True)
            if count >= args.expected:
                return 0
        except sqlite3.Error as exc:
            print(f"database not ready: {exc}", flush=True)
        time.sleep(1)
    print(f"timeout: run_id={args.run_id} persisted={count}/{args.expected}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

