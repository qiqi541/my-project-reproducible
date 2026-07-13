from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sqlite3
import statistics
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from kafka import KafkaProducer


LOGGER = logging.getLogger("stress-test")


def percentile(values: list[float], probability: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def run_coupled(total: int, threads: int, db_path: Path) -> dict[str, Any]:
    if db_path.exists():
        db_path.unlink()
    connection = sqlite3.connect(db_path)
    connection.execute(
        "CREATE TABLE test_logs (event_id TEXT PRIMARY KEY, timestamp REAL, attack_type TEXT, risk_level TEXT)"
    )
    connection.commit()
    connection.close()

    barrier = threading.Barrier(threads)
    lock = threading.Lock()
    lock_errors = 0
    other_errors = 0
    latencies: list[float] = []
    per_thread = total // threads
    remainder = total % threads

    def worker(worker_id: int, count: int) -> None:
        nonlocal lock_errors, other_errors
        local_connection = sqlite3.connect(db_path, timeout=0.01)
        barrier.wait()
        for index in range(count):
            started = time.perf_counter()
            try:
                local_connection.execute(
                    "INSERT INTO test_logs VALUES (?, ?, ?, ?)",
                    (str(uuid.uuid4()), time.time(), f"stress_{worker_id}_{index}", "HIGH"),
                )
                local_connection.commit()
            except sqlite3.OperationalError as exc:
                local_connection.rollback()
                if "locked" in str(exc).lower():
                    with lock:
                        lock_errors += 1
                else:
                    with lock:
                        other_errors += 1
            except Exception:
                local_connection.rollback()
                with lock:
                    other_errors += 1
            finally:
                with lock:
                    latencies.append((time.perf_counter() - started) * 1000.0)
        local_connection.close()

    started = time.perf_counter()
    worker_threads = []
    for worker_id in range(threads):
        count = per_thread + (1 if worker_id < remainder else 0)
        thread = threading.Thread(target=worker, args=(worker_id, count), daemon=True)
        worker_threads.append(thread)
        thread.start()
    for thread in worker_threads:
        thread.join()
    elapsed = time.perf_counter() - started

    connection = sqlite3.connect(db_path)
    persisted = connection.execute("SELECT COUNT(*) FROM test_logs").fetchone()[0]
    connection.close()
    lost = max(total - persisted, 0)
    return {
        "architecture": "direct_sqlite_coupled",
        "planned": total,
        "producer_acked": persisted,
        "persisted": persisted,
        "lost": lost,
        "loss_rate_percent": round(lost / total * 100.0, 3),
        "elapsed_seconds": round(elapsed, 6),
        "database_lock_errors": lock_errors,
        "other_errors": other_errors,
        "latency_average_ms": round(statistics.fmean(latencies), 3) if latencies else 0.0,
        "latency_p95_ms": round(percentile(latencies, 0.95), 3),
        "latency_p99_ms": round(percentile(latencies, 0.99), 3),
    }


def create_producer(broker: str) -> KafkaProducer:
    return KafkaProducer(
        bootstrap_servers=[broker],
        value_serializer=lambda value: json.dumps(value).encode("utf-8"),
        acks="all",
        retries=10,
        linger_ms=5,
        request_timeout_ms=30_000,
        max_block_ms=60_000,
    )


def wait_for_persistence(db_path: Path, run_id: str, expected: int, timeout: float) -> tuple[int, float]:
    deadline = time.monotonic() + timeout
    last_count = 0
    while time.monotonic() < deadline:
        try:
            connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2)
            last_count = connection.execute(
                "SELECT COUNT(*) FROM attack_logs WHERE run_id=?", (run_id,)
            ).fetchone()[0]
            connection.close()
            if last_count >= expected:
                return last_count, time.time()
        except sqlite3.Error:
            pass
        time.sleep(0.1)
    return last_count, time.time()


def run_decoupled(
    total: int,
    threads: int,
    broker: str,
    topic: str,
    db_path: Path,
    timeout: float,
) -> tuple[dict[str, Any], str]:
    run_id = f"stress-kafka-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    producer = create_producer(broker)
    send_latencies: list[float] = []
    send_errors: list[str] = []
    first_started_at = time.time()
    wall_started = time.perf_counter()

    def send_one(sequence_no: int) -> None:
        request_started_at = time.time()
        event_id = str(uuid.uuid4())
        event = {
            "schema_version": 2,
            "event_id": event_id,
            "run_id": run_id,
            "scenario": "kafka_stress",
            "sequence_no": sequence_no,
            "round_no": 0,
            "attempt_no": 1,
            "attack_type": "stress_test",
            "target": "kafka://performance_test_topic",
            "payload": f"stress-{sequence_no}",
            "request_started_at": request_started_at,
            "response_received_at": request_started_at,
            "emitted_at": time.time(),
            "http_status": 0,
            "ground_truth_success": True,
            "response_excerpt": "synthetic performance event",
            "error": None,
        }
        started = time.perf_counter()
        future = producer.send(topic, key=event_id.encode("utf-8"), value=event)
        future.get(timeout=30)
        send_latencies.append((time.perf_counter() - started) * 1000.0)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(send_one, sequence_no) for sequence_no in range(1, total + 1)]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as exc:
                send_errors.append(f"{type(exc).__name__}: {exc}")

    producer.flush(timeout=30)
    producer.close(timeout=30)
    acked_at = time.time()
    producer_acked = total - len(send_errors)
    persisted, persisted_at = wait_for_persistence(db_path, run_id, producer_acked, timeout)
    elapsed = time.perf_counter() - wall_started
    lost = max(total - persisted, 0)
    summary = {
        "architecture": "kafka_decoupled",
        "run_id": run_id,
        "planned": total,
        "producer_acked": producer_acked,
        "persisted": persisted,
        "lost": lost,
        "loss_rate_percent": round(lost / total * 100.0, 3),
        "elapsed_seconds": round(elapsed, 6),
        "send_errors": len(send_errors),
        "first_started_at": first_started_at,
        "all_producer_acked_at": acked_at,
        "all_persisted_or_timeout_at": persisted_at,
        "latency_average_ms": round(statistics.fmean(send_latencies), 3) if send_latencies else 0.0,
        "latency_p95_ms": round(percentile(send_latencies, 0.95), 3),
        "latency_p99_ms": round(percentile(send_latencies, 0.99), 3),
        "error_examples": send_errors[:5],
    }
    return summary, run_id


def write_results(results_dir: Path, coupled: dict[str, Any], decoupled: dict[str, Any]) -> Path:
    results_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    json_path = results_dir / f"stress-{stamp}.json"
    csv_path = results_dir / f"stress-{stamp}.csv"
    report_path = results_dir / f"stress-{stamp}.md"
    json_path.write_text(
        json.dumps({"generated_at": time.time(), "results": [coupled, decoupled]}, indent=2),
        encoding="utf-8",
    )
    fields = sorted(set(coupled).union(decoupled) - {"error_examples"})
    with csv_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerow({key: coupled.get(key, "") for key in fields})
        writer.writerow({key: decoupled.get(key, "") for key in fields})
    report_path.write_text(
        "\n".join(
            [
                "# End-to-end stress-test report",
                "",
                "> Values below were measured in this run; they are not expected constants.",
                "",
                "| Architecture | Planned | Producer acked | Durable unique rows | Lock errors | Elapsed (s) | Loss rate |",
                "|---|---:|---:|---:|---:|---:|---:|",
                f"| Direct SQLite | {coupled['planned']} | {coupled['producer_acked']} | {coupled['persisted']} | "
                f"{coupled['database_lock_errors']} | {coupled['elapsed_seconds']:.6f} | {coupled['loss_rate_percent']:.3f}% |",
                f"| Kafka decoupled | {decoupled['planned']} | {decoupled['producer_acked']} | {decoupled['persisted']} | "
                f"N/A | {decoupled['elapsed_seconds']:.6f} | {decoupled['loss_rate_percent']:.3f}% |",
                "",
                f"Kafka run ID: `{decoupled['run_id']}`.",
                "",
                "A zero-loss claim is valid for this run only when Durable unique rows equals Planned.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    LOGGER.info("wrote %s, %s and %s", json_path, csv_path, report_path)
    return json_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="End-to-end SQLite versus Kafka stress test")
    parser.add_argument("--total", type=int, default=1000)
    parser.add_argument("--threads", type=int, default=10)
    parser.add_argument("--broker", default=os.getenv("KAFKA_BROKER", "kafka:29092"))
    parser.add_argument("--topic", default=os.getenv("PERFORMANCE_TOPIC", "performance_test_topic"))
    parser.add_argument("--db-path", type=Path, default=Path(os.getenv("DB_FILE", "/data/passwords.db")))
    parser.add_argument("--coupled-db", type=Path, default=Path("/data/coupled_test.db"))
    parser.add_argument("--results-dir", type=Path, default=Path("/results"))
    parser.add_argument("--persistence-timeout", type=float, default=120.0)
    return parser.parse_args()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = parse_args()
    if args.total <= 0 or args.threads <= 0:
        raise ValueError("--total and --threads must be positive")
    coupled = run_coupled(args.total, args.threads, args.coupled_db)
    LOGGER.info("coupled result: %s", coupled)
    decoupled, _ = run_decoupled(
        args.total,
        args.threads,
        args.broker,
        args.topic,
        args.db_path,
        args.persistence_timeout,
    )
    LOGGER.info("decoupled result: %s", decoupled)
    output = write_results(args.results_dir, coupled, decoupled)
    print(output)
    return 0 if decoupled["persisted"] == args.total else 2


if __name__ == "__main__":
    raise SystemExit(main())
