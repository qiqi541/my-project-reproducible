from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

from kafka import KafkaConsumer
from kafka.errors import NoBrokersAvailable

from common.risk_model import RiskModel


LOGGER = logging.getLogger("risk-consumer")
KAFKA_BROKER = os.getenv("KAFKA_BROKER", "kafka:29092")
EVIDENCE_TOPIC = os.getenv("EVIDENCE_TOPIC", "evidence_topic")
PERFORMANCE_TOPIC = os.getenv("PERFORMANCE_TOPIC", "performance_test_topic")
GROUP_ID = os.getenv("KAFKA_GROUP_ID", "risk-decision-v2")
DB_FILE = Path(os.getenv("DB_FILE", "/data/passwords.db"))
RISK_CONFIG = Path(os.getenv("RISK_CONFIG", "/app/config/risk_model.json"))


SCHEMA = """
CREATE TABLE IF NOT EXISTS attack_logs (
    event_id TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL,
    run_id TEXT NOT NULL,
    scenario TEXT NOT NULL,
    sequence_no INTEGER NOT NULL,
    round_no INTEGER NOT NULL,
    attempt_no INTEGER NOT NULL,
    attack_type TEXT NOT NULL,
    target TEXT NOT NULL,
    payload TEXT NOT NULL,
    request_started_at REAL NOT NULL,
    response_received_at REAL NOT NULL,
    emitted_at REAL NOT NULL,
    kafka_received_at REAL NOT NULL,
    persisted_at REAL NOT NULL,
    http_status INTEGER NOT NULL,
    ground_truth_success INTEGER NOT NULL,
    response_excerpt TEXT NOT NULL,
    error TEXT,
    dynamic_factor INTEGER NOT NULL,
    impact REAL NOT NULL,
    attack_complexity REAL NOT NULL,
    risk_level TEXT NOT NULL,
    risk_score REAL NOT NULL,
    kafka_topic TEXT NOT NULL,
    kafka_partition INTEGER NOT NULL,
    kafka_offset INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attack_logs_run_id ON attack_logs(run_id);
CREATE INDEX IF NOT EXISTS idx_attack_logs_type ON attack_logs(attack_type);
CREATE INDEX IF NOT EXISTS idx_attack_logs_persisted ON attack_logs(persisted_at);
"""


INSERT_SQL = """
INSERT OR IGNORE INTO attack_logs (
    event_id, schema_version, run_id, scenario, sequence_no, round_no,
    attempt_no, attack_type, target, payload, request_started_at,
    response_received_at, emitted_at, kafka_received_at, persisted_at,
    http_status, ground_truth_success, response_excerpt, error,
    dynamic_factor, impact, attack_complexity, risk_level, risk_score,
    kafka_topic, kafka_partition, kafka_offset
) VALUES (
    :event_id, :schema_version, :run_id, :scenario, :sequence_no, :round_no,
    :attempt_no, :attack_type, :target, :payload, :request_started_at,
    :response_received_at, :emitted_at, :kafka_received_at, :persisted_at,
    :http_status, :ground_truth_success, :response_excerpt, :error,
    :dynamic_factor, :impact, :attack_complexity, :risk_level, :risk_score,
    :kafka_topic, :kafka_partition, :kafka_offset
)
"""


def connect_db() -> sqlite3.Connection:
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_FILE, timeout=30)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute("PRAGMA busy_timeout=10000")
    connection.executescript(SCHEMA)
    connection.commit()
    return connection


def connect_consumer() -> KafkaConsumer:
    while True:
        try:
            consumer = KafkaConsumer(
                EVIDENCE_TOPIC,
                PERFORMANCE_TOPIC,
                bootstrap_servers=[KAFKA_BROKER],
                group_id=GROUP_ID,
                enable_auto_commit=False,
                auto_offset_reset="earliest",
                value_deserializer=lambda raw: json.loads(raw.decode("utf-8")),
                max_poll_records=100,
            )
            LOGGER.info("connected to Kafka broker=%s group_id=%s", KAFKA_BROKER, GROUP_ID)
            return consumer
        except NoBrokersAvailable:
            LOGGER.warning("Kafka is not ready at %s; retrying in 3 seconds", KAFKA_BROKER)
            time.sleep(3)


def normalize_event(message: Any, model: RiskModel) -> dict[str, Any]:
    raw = message.value
    required = {
        "event_id",
        "run_id",
        "scenario",
        "attack_type",
        "request_started_at",
        "response_received_at",
        "emitted_at",
        "ground_truth_success",
    }
    missing = sorted(required.difference(raw))
    if missing:
        raise ValueError(f"event is missing required fields: {', '.join(missing)}")

    success = bool(raw["ground_truth_success"])
    risk = model.score(str(raw["attack_type"]), success)
    received_at = time.time()
    event = {
        "event_id": str(raw["event_id"]),
        "schema_version": int(raw.get("schema_version", 2)),
        "run_id": str(raw["run_id"]),
        "scenario": str(raw["scenario"]),
        "sequence_no": int(raw.get("sequence_no", 0)),
        "round_no": int(raw.get("round_no", 0)),
        "attempt_no": int(raw.get("attempt_no", 1)),
        "attack_type": str(raw["attack_type"]),
        "target": str(raw.get("target", "")),
        "payload": str(raw.get("payload", "")),
        "request_started_at": float(raw["request_started_at"]),
        "response_received_at": float(raw["response_received_at"]),
        "emitted_at": float(raw["emitted_at"]),
        "kafka_received_at": received_at,
        "persisted_at": time.time(),
        "http_status": int(raw.get("http_status", 0)),
        "ground_truth_success": int(success),
        "response_excerpt": str(raw.get("response_excerpt", ""))[:500],
        "error": raw.get("error"),
        "dynamic_factor": risk.dynamic_factor,
        "impact": risk.impact,
        "attack_complexity": risk.attack_complexity,
        "risk_level": risk.level,
        "risk_score": risk.score,
        "kafka_topic": message.topic,
        "kafka_partition": message.partition,
        "kafka_offset": message.offset,
    }
    return event


def run() -> None:
    model = RiskModel.from_file(RISK_CONFIG)
    connection = connect_db()
    consumer = connect_consumer()
    LOGGER.info("consumer started db=%s topics=%s,%s", DB_FILE, EVIDENCE_TOPIC, PERFORMANCE_TOPIC)

    for message in consumer:
        try:
            event = normalize_event(message, model)
            connection.execute(INSERT_SQL, event)
            connection.commit()
            # Commit the Kafka offset only after the durable SQLite commit. The
            # event_id primary key makes replay idempotent after a crash.
            consumer.commit()
            LOGGER.info(
                "persisted event=%s run=%s type=%s score=%.1f offset=%s",
                event["event_id"],
                event["run_id"],
                event["attack_type"],
                event["risk_score"],
                message.offset,
            )
        except Exception:
            connection.rollback()
            LOGGER.exception(
                "failed to process topic=%s partition=%s offset=%s; offset not committed",
                message.topic,
                message.partition,
                message.offset,
            )
            # Recreate the consumer from the last committed offset. Continuing
            # this iterator could later commit past the failed record.
            consumer.close()
            connection.close()
            raise


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    while True:
        try:
            run()
        except KeyboardInterrupt:
            return 0
        except Exception:
            LOGGER.exception("consumer crashed; restarting in 5 seconds")
            time.sleep(5)


if __name__ == "__main__":
    raise SystemExit(main())
