from __future__ import annotations

import os
import sqlite3

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, jsonify, request


app = Flask(__name__)
WAF_ENABLED = os.getenv("WAF_ENABLED", "true").lower() in {"1", "true", "yes", "on"}
SECRET_KEY = b"zhejiang_univ_16"
IV = b"init_vector_1234"


def init_vulnerable_db() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:", check_same_thread=False)
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE users (username TEXT, secret_data TEXT)")
    cursor.execute("INSERT INTO users VALUES ('admin', 'administrator secret data')")
    cursor.execute("INSERT INTO users VALUES ('guest', 'public guest data')")
    connection.commit()
    return connection


db_connection = init_vulnerable_db()


@app.get("/health")
def health():
    return jsonify({"status": "ok", "waf_enabled": WAF_ENABLED})


@app.get("/config")
def config():
    return jsonify(
        {
            "waf_enabled": WAF_ENABLED,
            "endpoints": ["/login", "/search", "/feedback", "/crypto_check"],
            "purpose": "isolated academic vulnerability simulation only",
        }
    )


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    if data.get("username") == "admin" and data.get("password") == "admin123":
        return jsonify({"status": "success", "msg": "login successful"}), 200
    return jsonify({"status": "fail", "msg": "invalid credentials"}), 401


def waf_blocks(query: str) -> bool:
    normalized = query.upper()
    signatures = ("'", " OR ", "UNION", "--", "/*")
    return any(signature in normalized for signature in signatures)


@app.get("/search")
def search():
    query = request.args.get("q", "")
    if WAF_ENABLED and waf_blocks(query):
        response = jsonify(
            {
                "status": "blocked",
                "msg": "simulated WAF blocked a SQL injection signature",
            }
        )
        response.headers["X-Simulated-WAF"] = "blocked"
        return response, 403

    # Intentionally vulnerable SQL construction. This service must never be
    # exposed to an untrusted network.
    sql = f"SELECT * FROM users WHERE username = '{query}'"
    try:
        cursor = db_connection.cursor()
        cursor.execute(sql)
        rows = cursor.fetchall()
        if not rows:
            return jsonify({"status": "fail", "data": []}), 404
        return jsonify({"status": "success", "data": rows}), 200
    except sqlite3.Error as exc:
        return jsonify({"status": "error", "msg": str(exc)}), 500


@app.post("/feedback")
def feedback():
    data = request.get_json(silent=True) or {}
    content = str(data.get("content", ""))
    # Intentionally reflected without escaping for the isolated experiment.
    return f"submitted feedback: {content}", 200, {"Content-Type": "text/html; charset=utf-8"}


@app.post("/crypto_check")
def crypto_check():
    data = request.get_json(silent=True) or {}
    try:
        encrypted_token = bytes.fromhex(str(data.get("token", "")))
    except ValueError:
        return jsonify({"status": "error", "msg": "token must be hexadecimal"}), 400
    if not encrypted_token or len(encrypted_token) % 16 != 0:
        return jsonify({"status": "error", "msg": "token must contain complete AES blocks"}), 400
    try:
        cipher = Cipher(algorithms.AES(SECRET_KEY), modes.CBC(IV))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_token) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        unpadder.update(padded_data)
        unpadder.finalize()
        return jsonify({"status": "success", "msg": "valid token"}), 200
    except ValueError:
        # Deliberate oracle: padding failures are distinguishable from other
        # failures. This demonstrates oracle existence, not plaintext recovery.
        return jsonify({"status": "fail", "msg": "Padding Error"}), 500
    except Exception:
        return jsonify({"status": "error", "msg": "decryption failed"}), 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
