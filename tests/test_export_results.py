from __future__ import annotations

import unittest

from tools.export_results import percentile, summarize


def row(event_id: str, attack_type: str, success: bool, risk_score: float, risk_level: str, latency_ms: float):
    started = 1000.0
    return {
        "event_id": event_id,
        "run_id": "test-run",
        "scenario": "test",
        "attack_type": attack_type,
        "ground_truth_success": int(success),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "request_started_at": started,
        "response_received_at": started + latency_ms / 2000.0,
        "emitted_at": started + latency_ms / 1500.0,
        "persisted_at": started + latency_ms / 1000.0,
    }


class ExportTests(unittest.TestCase):
    def test_percentile_interpolates(self) -> None:
        self.assertEqual(percentile([1, 2, 3, 4], 0.5), 2.5)

    def test_summary_uses_real_rows(self) -> None:
        summary = summarize(
            [
                row("a", "sql_injection", True, 8.9, "HIGH", 100.0),
                row("b", "sql_injection", False, 0.0, "INFO", 200.0),
            ]
        )
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["success"], 1)
        self.assertEqual(summary["average_risk_score"], 4.45)
        self.assertEqual(summary["latency"]["average_ms"], 150.0)


if __name__ == "__main__":
    unittest.main()

