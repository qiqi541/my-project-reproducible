from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, redirect, render_template, request, session, url_for


app = Flask(__name__)
app.secret_key = os.getenv("DASHBOARD_SECRET", "development-only-change-me")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

DB_FILE = Path(os.getenv("DB_FILE", "/data/passwords.db"))
ADMIN_USER = os.getenv("DASHBOARD_USER", "admin")
ADMIN_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "change-me")


def read_only_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(f"file:{DB_FILE}?mode=ro", uri=True, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA busy_timeout=5000")
    return connection


def percentile(values: list[float], probability: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def get_stats(run_id: str | None = None) -> dict[str, Any]:
    if not DB_FILE.exists():
        return empty_stats(run_id)
    where = " WHERE run_id = ?" if run_id else ""
    params: tuple[Any, ...] = (run_id,) if run_id else ()
    try:
        with read_only_connection() as connection:
            total = connection.execute(f"SELECT COUNT(*) FROM attack_logs{where}", params).fetchone()[0]
            success = connection.execute(
                f"SELECT COUNT(*) FROM attack_logs{where + (' AND' if where else ' WHERE')} ground_truth_success=1",
                params,
            ).fetchone()[0]
            risk_rows = connection.execute(
                f"SELECT risk_level, COUNT(*) AS count FROM attack_logs{where} GROUP BY risk_level",
                params,
            ).fetchall()
            risks = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for row in risk_rows:
                if row["risk_level"] in risks:
                    risks[row["risk_level"]] = row["count"]

            avg_row = connection.execute(
                f"SELECT AVG(risk_score) FROM attack_logs{where}", params
            ).fetchone()
            average_risk = round(float(avg_row[0] or 0.0), 2)
            latency_rows = connection.execute(
                f"SELECT (persisted_at-request_started_at)*1000.0 AS latency FROM attack_logs{where}",
                params,
            ).fetchall()
            latency_values = [float(row["latency"]) for row in latency_rows if row["latency"] is not None]
            logs = connection.execute(
                "SELECT event_id, run_id, scenario, persisted_at, attack_type, payload, "
                "http_status, ground_truth_success, risk_level, risk_score, "
                "(persisted_at-request_started_at)*1000.0 AS latency_ms "
                f"FROM attack_logs{where} ORDER BY persisted_at DESC LIMIT 20",
                params,
            ).fetchall()
            run_rows = connection.execute(
                "SELECT run_id, scenario, COUNT(*) AS count, MIN(request_started_at) AS started_at, "
                "MAX(persisted_at) AS ended_at FROM attack_logs GROUP BY run_id, scenario "
                "ORDER BY ended_at DESC LIMIT 30"
            ).fetchall()
    except (sqlite3.Error, OSError):
        return empty_stats(run_id)

    return {
        "run_id": run_id,
        "total": total,
        "success": success,
        "fail": total - success,
        "risks": risks,
        "average_risk": average_risk,
        "latency": {
            "average_ms": round(sum(latency_values) / len(latency_values), 2) if latency_values else 0.0,
            "p50_ms": round(percentile(latency_values, 0.50), 2),
            "p95_ms": round(percentile(latency_values, 0.95), 2),
            "p99_ms": round(percentile(latency_values, 0.99), 2),
        },
        "logs": [dict(row) for row in logs],
        "runs": [dict(row) for row in run_rows],
        "server_time": time.time(),
    }


def empty_stats(run_id: str | None) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "total": 0,
        "success": 0,
        "fail": 0,
        "risks": {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "average_risk": 0.0,
        "latency": {"average_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0},
        "logs": [],
        "runs": [],
        "server_time": time.time(),
    }


def authenticated() -> bool:
    return bool(session.get("logged_in"))


@app.get("/health")
def health():
    return jsonify({"status": "ok", "database_ready": DB_FILE.is_file()})


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if request.form.get("username") == ADMIN_USER and request.form.get("password") == ADMIN_PASSWORD:
            session.clear()
            session["logged_in"] = True
            return redirect(url_for("index"))
        error = "账号或口令错误"
    return render_template("login.html", error=error)


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
def index():
    if not authenticated():
        return redirect(url_for("login"))
    return render_template("index.html")


@app.get("/api/data")
def api_data():
    if not authenticated():
        return jsonify({"error": "unauthorized"}), 401
    return jsonify(get_stats(request.args.get("run_id") or None))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)

