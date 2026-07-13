from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any


RANDOM_INDEX = {
    1: 0.0,
    2: 0.0,
    3: 0.58,
    4: 0.90,
    5: 1.12,
    6: 1.24,
    7: 1.32,
    8: 1.41,
    9: 1.45,
    10: 1.49,
}


@dataclass(frozen=True)
class RiskResult:
    level: str
    score: float
    impact: float
    attack_complexity: float
    dynamic_factor: int


def principal_eigenvector(matrix: list[list[float]], iterations: int = 100) -> tuple[list[float], float]:
    """Return the normalized principal eigenvector and eigenvalue.

    Power iteration keeps the AHP derivation executable without adding NumPy to
    the runtime containers.
    """
    size = len(matrix)
    if size == 0 or any(len(row) != size for row in matrix):
        raise ValueError("AHP matrix must be non-empty and square")
    if any(value <= 0 for row in matrix for value in row):
        raise ValueError("AHP matrix values must be positive")

    vector = [1.0 / size] * size
    for _ in range(iterations):
        next_vector = [sum(matrix[i][j] * vector[j] for j in range(size)) for i in range(size)]
        total = sum(next_vector)
        if total <= 0:
            raise ValueError("AHP matrix produced an invalid weight vector")
        next_vector = [value / total for value in next_vector]
        if max(abs(next_vector[i] - vector[i]) for i in range(size)) < 1e-12:
            vector = next_vector
            break
        vector = next_vector

    multiplied = [sum(matrix[i][j] * vector[j] for j in range(size)) for i in range(size)]
    eigenvalue = sum(multiplied[i] / vector[i] for i in range(size)) / size
    return vector, eigenvalue


def consistency_ratio(matrix: list[list[float]]) -> float:
    size = len(matrix)
    _, eigenvalue = principal_eigenvector(matrix)
    if size <= 2:
        return 0.0
    consistency_index = (eigenvalue - size) / (size - 1)
    random_index = RANDOM_INDEX.get(size)
    if random_index is None or random_index == 0:
        raise ValueError(f"No random-index value configured for a {size}x{size} matrix")
    return consistency_index / random_index


class RiskModel:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        criteria = config["criteria"]
        self.impact_weight = float(criteria["weights"]["impact"])
        self.exploitability_weight = float(criteria["weights"]["exploitability"])
        if not math.isclose(self.impact_weight + self.exploitability_weight, 1.0, abs_tol=1e-9):
            raise ValueError("Risk weights must sum to 1.0")

        calculated, _ = principal_eigenvector(criteria["pairwise_matrix"])
        configured = [self.impact_weight, self.exploitability_weight]
        if any(abs(calculated[i] - configured[i]) > 0.01 for i in range(2)):
            raise ValueError(
                f"Configured weights {configured} do not match AHP-derived weights {calculated}"
            )
        if consistency_ratio(criteria["pairwise_matrix"]) >= 0.1:
            raise ValueError("AHP consistency ratio must be below 0.1")

        self.high_threshold = float(config["thresholds"]["high"])
        self.medium_threshold = float(config["thresholds"]["medium"])
        self.vulnerabilities = config["vulnerabilities"]

    @classmethod
    def from_file(cls, path: str | Path) -> "RiskModel":
        with Path(path).open("r", encoding="utf-8") as handle:
            return cls(json.load(handle))

    def score(self, attack_type: str, success: bool) -> RiskResult:
        metrics = self.vulnerabilities.get(attack_type)
        if metrics is None:
            raise KeyError(f"Unknown attack type: {attack_type}")
        impact = float(metrics["impact"])
        complexity = float(metrics["attack_complexity"])
        dynamic_factor = 1 if success else 0
        raw_score = dynamic_factor * (
            self.impact_weight * impact
            + self.exploitability_weight * (10.0 - complexity)
        )
        score = round(raw_score, 1)
        if score == 0:
            level = "INFO"
        elif score >= self.high_threshold:
            level = "HIGH"
        elif score >= self.medium_threshold:
            level = "MEDIUM"
        else:
            level = "LOW"
        return RiskResult(level, score, impact, complexity, dynamic_factor)

    def static_baseline_score(self, attack_type: str) -> float:
        metrics = self.vulnerabilities.get(attack_type)
        if metrics is None:
            raise KeyError(f"Unknown attack type: {attack_type}")
        return float(metrics["static_baseline_score"])

