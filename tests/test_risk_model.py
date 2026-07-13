from __future__ import annotations

import json
import unittest
from pathlib import Path

from common.risk_model import RiskModel, consistency_ratio, principal_eigenvector


ROOT = Path(__file__).resolve().parents[1]


class RiskModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.model = RiskModel.from_file(ROOT / "config" / "risk_model.json")

    def test_ahp_weights_match_documented_values(self) -> None:
        config = json.loads((ROOT / "config" / "risk_model.json").read_text(encoding="utf-8"))
        weights, eigenvalue = principal_eigenvector(config["criteria"]["pairwise_matrix"])
        self.assertAlmostEqual(weights[0], 0.6, places=6)
        self.assertAlmostEqual(weights[1], 0.4, places=6)
        self.assertAlmostEqual(eigenvalue, 2.0, places=6)
        self.assertEqual(consistency_ratio(config["criteria"]["pairwise_matrix"]), 0.0)

    def test_paper_scores(self) -> None:
        expected = {
            "sql_injection": ("HIGH", 8.9),
            "brute_force": ("MEDIUM", 7.8),
            "xss_attack": ("LOW", 5.2),
            "padding_oracle": ("MEDIUM", 6.7),
        }
        for attack_type, (level, score) in expected.items():
            with self.subTest(attack_type=attack_type):
                result = self.model.score(attack_type, True)
                self.assertEqual(result.level, level)
                self.assertEqual(result.score, score)
                self.assertEqual(result.dynamic_factor, 1)

    def test_blocked_or_failed_attack_is_info_zero(self) -> None:
        result = self.model.score("sql_injection", False)
        self.assertEqual(result.level, "INFO")
        self.assertEqual(result.score, 0.0)
        self.assertEqual(result.dynamic_factor, 0)

    def test_unknown_attack_type_fails_closed(self) -> None:
        with self.assertRaises(KeyError):
            self.model.score("not_configured", True)


if __name__ == "__main__":
    unittest.main()

