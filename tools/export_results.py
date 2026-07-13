from __future__ import annotations

import argparse
import csv
import json
import math
import sqlite3
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from common.risk_model import RiskModel


def percentile(values: list[float], probability: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def safe_mean(values: list[float]) -> float:
    return statistics.fmean(values) if values else 0.0


def query_run(db_path: Path, run_id: str) -> list[dict[str, Any]]:
    connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    rows = connection.execute(
        "SELECT * FROM attack_logs WHERE run_id=? ORDER BY sequence_no, persisted_at", (run_id,)
    ).fetchall()
    connection.close()
    return [dict(row) for row in rows]


def add_derived_fields(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    result["probe_latency_ms"] = (row["response_received_at"] - row["request_started_at"]) * 1000.0
    result["pipeline_latency_ms"] = (row["persisted_at"] - row["emitted_at"]) * 1000.0
    result["end_to_end_latency_ms"] = (row["persisted_at"] - row["request_started_at"]) * 1000.0
    return result


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {
            "total": 0,
            "success": 0,
            "failure": 0,
            "success_rate_percent": 0.0,
            "average_risk_score": 0.0,
            "risk_distribution": {},
            "latency": {},
            "by_attack_type": {},
        }
    derived = [add_derived_fields(row) for row in rows]
    end_to_end = [row["end_to_end_latency_ms"] for row in derived]
    by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in derived:
        by_type[row["attack_type"]].append(row)

    type_summary: dict[str, Any] = {}
    for attack_type, items in sorted(by_type.items()):
        latencies = [item["end_to_end_latency_ms"] for item in items]
        successful = sum(int(item["ground_truth_success"]) for item in items)
        type_summary[attack_type] = {
            "count": len(items),
            "success": successful,
            "success_rate_percent": round(successful / len(items) * 100.0, 3),
            "average_risk_score": round(safe_mean([float(item["risk_score"]) for item in items]), 3),
            "latency_average_ms": round(safe_mean(latencies), 3),
            "latency_p50_ms": round(percentile(latencies, 0.50), 3),
            "latency_p95_ms": round(percentile(latencies, 0.95), 3),
            "latency_p99_ms": round(percentile(latencies, 0.99), 3),
        }

    successful = sum(int(row["ground_truth_success"]) for row in rows)
    return {
        "run_id": rows[0]["run_id"],
        "scenario": rows[0]["scenario"],
        "total": len(rows),
        "success": successful,
        "failure": len(rows) - successful,
        "success_rate_percent": round(successful / len(rows) * 100.0, 3),
        "average_risk_score": round(safe_mean([float(row["risk_score"]) for row in rows]), 3),
        "risk_distribution": dict(Counter(row["risk_level"] for row in rows)),
        "latency": {
            "average_ms": round(safe_mean(end_to_end), 3),
            "p50_ms": round(percentile(end_to_end, 0.50), 3),
            "p95_ms": round(percentile(end_to_end, 0.95), 3),
            "p99_ms": round(percentile(end_to_end, 0.99), 3),
            "min_ms": round(min(end_to_end), 3),
            "max_ms": round(max(end_to_end), 3),
        },
        "by_attack_type": type_summary,
    }


def ablation_metrics(rows: list[dict[str, Any]], model: RiskModel) -> dict[str, Any]:
    sql_rows = [row for row in rows if row["attack_type"] == "sql_injection"]
    negatives = [row for row in sql_rows if not row["ground_truth_success"]]
    static_false_positives = sum(
        1 for row in negatives if model.static_baseline_score(row["attack_type"]) >= 8.0
    )
    drs_false_positives = sum(1 for row in negatives if float(row["risk_score"]) >= 8.0)
    denominator = len(negatives)
    return {
        "run_id": rows[0]["run_id"] if rows else None,
        "scenario": rows[0]["scenario"] if rows else None,
        "sql_events": len(sql_rows),
        "ground_truth_positive": len(sql_rows) - denominator,
        "ground_truth_negative": denominator,
        "static_false_positives": static_false_positives,
        "static_false_positive_rate_percent": round(static_false_positives / denominator * 100.0, 3)
        if denominator
        else None,
        "drs_false_positives": drs_false_positives,
        "drs_false_positive_rate_percent": round(drs_false_positives / denominator * 100.0, 3)
        if denominator
        else None,
        "average_drs": round(safe_mean([float(row["risk_score"]) for row in sql_rows]), 3),
        "static_baseline_score": model.static_baseline_score("sql_injection"),
    }


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    derived = [add_derived_fields(row) for row in rows]
    if not derived:
        return
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(derived[0]))
        writer.writeheader()
        writer.writerows(derived)


def write_figures(output_dir: Path, run_id: str, summary: dict[str, Any]) -> list[Path]:
    import matplotlib.pyplot as plt

    created: list[Path] = []
    by_type = summary.get("by_attack_type", {})
    if by_type:
        names = list(by_type)
        averages = [by_type[name]["latency_average_ms"] for name in names]
        p95_values = [by_type[name]["latency_p95_ms"] for name in names]
        figure, axis = plt.subplots(figsize=(9, 5))
        positions = range(len(names))
        axis.bar([position - 0.18 for position in positions], averages, width=0.36, label="Average")
        axis.bar([position + 0.18 for position in positions], p95_values, width=0.36, label="P95")
        axis.set_xticks(list(positions), [name.replace("_", "\n") for name in names])
        axis.set_ylabel("End-to-end latency (ms)")
        axis.set_title(f"Latency by attack type - {run_id}")
        axis.legend()
        axis.grid(axis="y", alpha=0.25)
        figure.tight_layout()
        path = output_dir / f"{run_id}-latency.png"
        figure.savefig(path, dpi=180)
        plt.close(figure)
        created.append(path)

    risk_distribution = summary.get("risk_distribution", {})
    if risk_distribution:
        levels = ["HIGH", "MEDIUM", "LOW", "INFO"]
        values = [risk_distribution.get(level, 0) for level in levels]
        figure, axis = plt.subplots(figsize=(7, 4.5))
        axis.bar(levels, values, color=["#dc2626", "#d97706", "#0d9488", "#64748b"])
        axis.set_ylabel("Event count")
        axis.set_title(f"DRS distribution - {run_id}")
        axis.grid(axis="y", alpha=0.25)
        figure.tight_layout()
        path = output_dir / f"{run_id}-risk-distribution.png"
        figure.savefig(path, dpi=180)
        plt.close(figure)
        created.append(path)
    return created


def write_ablation_figure(
    output_dir: Path,
    primary: dict[str, Any],
    comparison: dict[str, Any],
) -> Path:
    import matplotlib.pyplot as plt

    runs = [primary, comparison]
    labels = [str(item.get("scenario") or item.get("run_id")) for item in runs]
    static_scores = [float(item["static_baseline_score"]) for item in runs]
    drs_scores = [float(item["average_drs"]) for item in runs]
    positions = list(range(len(labels)))
    figure, axis = plt.subplots(figsize=(8, 5))
    axis.bar([position - 0.18 for position in positions], static_scores, width=0.36, label="Static baseline")
    axis.bar([position + 0.18 for position in positions], drs_scores, width=0.36, label="DRS")
    axis.set_xticks(positions, labels)
    axis.set_ylim(0, 10)
    axis.set_ylabel("Risk score")
    axis.set_title("WAF ablation: static score versus DRS")
    axis.legend()
    axis.grid(axis="y", alpha=0.25)
    figure.tight_layout()
    path = output_dir / f"{primary['run_id']}-vs-{comparison['run_id']}-ablation.png"
    figure.savefig(path, dpi=180)
    plt.close(figure)
    return path


def markdown_report(
    summary: dict[str, Any],
    ablation: dict[str, Any] | None,
    comparison: dict[str, Any] | None,
) -> str:
    latency = summary.get("latency", {})
    lines = [
        f"# Reproducible experiment report: {summary.get('run_id')}",
        "",
        "> Every value in this report was calculated from the SQLite evidence table. No expected result is hard-coded.",
        "",
        "## Overall results",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Scenario | {summary.get('scenario')} |",
        f"| Durable unique events | {summary.get('total', 0)} |",
        f"| Successful vulnerability validations | {summary.get('success', 0)} |",
        f"| Success rate | {summary.get('success_rate_percent', 0):.3f}% |",
        f"| Average DRS | {summary.get('average_risk_score', 0):.3f} |",
        f"| End-to-end average latency | {latency.get('average_ms', 0):.3f} ms |",
        f"| End-to-end P95 latency | {latency.get('p95_ms', 0):.3f} ms |",
        f"| End-to-end P99 latency | {latency.get('p99_ms', 0):.3f} ms |",
        "",
        "## Results by attack type",
        "",
        "| Attack type | Count | Success | Avg DRS | Avg latency (ms) | P95 (ms) |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for attack_type, values in summary.get("by_attack_type", {}).items():
        lines.append(
            f"| {attack_type} | {values['count']} | {values['success']} | "
            f"{values['average_risk_score']:.3f} | {values['latency_average_ms']:.3f} | "
            f"{values['latency_p95_ms']:.3f} |"
        )

    if ablation:
        lines.extend(
            [
                "",
                "## SQL injection ablation metrics",
                "",
                "| Metric | Value |",
                "|---|---:|",
                f"| Ground-truth positives | {ablation['ground_truth_positive']} |",
                f"| Ground-truth negatives | {ablation['ground_truth_negative']} |",
                f"| Static-model false positives | {ablation['static_false_positives']} |",
                f"| Static-model FPR | {ablation['static_false_positive_rate_percent']}% |",
                f"| DRS false positives | {ablation['drs_false_positives']} |",
                f"| DRS FPR | {ablation['drs_false_positive_rate_percent']}% |",
            ]
        )

    if comparison:
        lines.extend(
            [
                "",
                "## Compared ablation run",
                "",
                f"Comparison run: `{comparison['run_id']}` / scenario `{comparison['scenario']}`.",
                f"Static-model FPR: {comparison['static_false_positive_rate_percent']}%; "
                f"DRS FPR: {comparison['drs_false_positive_rate_percent']}%.",
            ]
        )
    lines.extend(
        [
            "",
            "## Interpretation boundary",
            "",
            "- A Padding Error response demonstrates distinguishable oracle behavior; it does not by itself demonstrate plaintext recovery.",
            "- Zero loss may be stated only when the stress-test `persisted` count equals the planned count.",
            "- Latency values are environment-specific and must be reported with this run ID and VM configuration.",
            "",
        ]
    )
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export real experiment evidence and paper-ready figures")
    parser.add_argument("--db", type=Path, default=Path("/data/passwords.db"))
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--compare-run-id")
    parser.add_argument("--output-dir", type=Path, default=Path("/results"))
    parser.add_argument("--risk-config", type=Path, default=Path("/app/config/risk_model.json"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    rows = query_run(args.db, args.run_id)
    if not rows:
        print(f"No records found for run_id={args.run_id}")
        return 2
    model = RiskModel.from_file(args.risk_config)
    summary = summarize(rows)
    ablation = ablation_metrics(rows, model) if any(row["attack_type"] == "sql_injection" for row in rows) else None
    comparison = None
    comparison_rows: list[dict[str, Any]] = []
    if args.compare_run_id:
        comparison_rows = query_run(args.db, args.compare_run_id)
        if not comparison_rows:
            print(f"No records found for compare_run_id={args.compare_run_id}")
            return 2
        comparison = ablation_metrics(comparison_rows, model)

    prefix = args.output_dir / args.run_id
    write_csv(prefix.with_name(f"{args.run_id}-events.csv"), rows)
    payload = {
        "summary": summary,
        "ablation": ablation,
        "comparison_ablation": comparison,
    }
    prefix.with_name(f"{args.run_id}-summary.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    prefix.with_name(f"{args.run_id}-report.md").write_text(
        markdown_report(summary, ablation, comparison), encoding="utf-8"
    )
    write_figures(args.output_dir, args.run_id, summary)

    if comparison_rows:
        combined_path = args.output_dir / f"{args.run_id}-vs-{args.compare_run_id}-ablation.json"
        combined_path.write_text(
            json.dumps(
                {
                    "primary": ablation,
                    "comparison": comparison,
                    "total_records": len(rows) + len(comparison_rows),
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        if ablation and comparison:
            write_ablation_figure(args.output_dir, ablation, comparison)
    print(args.output_dir / f"{args.run_id}-report.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
