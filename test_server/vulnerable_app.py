#!/usr/bin/python3
"""
Vulnerable Flask test server for ptpasstime.

Provides two login endpoints:
  - /login/vulnerable  - non-constant-time password comparison (timing attack possible)
  - /login/secure      - hmac.compare_digest constant-time comparison

Run:
  pip install flask
  python vulnerable_app.py
"""

from __future__ import annotations

import hmac
import time

from flask import Flask, request

app = Flask(__name__)

CORRECT_USERNAME = "admin"
CORRECT_PASSWORD = "correctPassword"
COMPARE_DELAY_MS = 5.0


def _simulate_char_compare(expected: str, provided: str) -> bool:
    """Intentionally vulnerable early-exit string comparison."""
    if len(expected) != len(provided):
        return False

    for expected_char, provided_char in zip(expected, provided, strict=True):
        if expected_char != provided_char:
            return False
        time.sleep(COMPARE_DELAY_MS / 1000)
    return True


def _secure_compare(expected: str, provided: str) -> bool:
    if len(expected) != len(provided):
        return False
    return hmac.compare_digest(expected.encode("utf-8"), provided.encode("utf-8"))


def _login_response(ok: bool) -> tuple[dict[str, str], int]:
    if ok:
        return {"status": "ok", "message": "Login successful"}, 200
    return {"status": "error", "message": "Invalid credentials"}, 401


@app.route("/login/vulnerable", methods=["POST"])
def login_vulnerable():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    ok = username == CORRECT_USERNAME and _simulate_char_compare(CORRECT_PASSWORD, password)
    return _login_response(ok)


@app.route("/login/secure", methods=["POST"])
def login_secure():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    ok = (
        username == CORRECT_USERNAME
        and len(password) == len(CORRECT_PASSWORD)
        and _secure_compare(CORRECT_PASSWORD, password)
    )
    return _login_response(ok)


@app.route("/")
def index():
    return (
        "<h1>ptpasstime test server</h1>"
        "<ul>"
        "<li>POST /login/vulnerable - timing-vulnerable comparison</li>"
        "<li>POST /login/secure - constant-time comparison</li>"
        "</ul>"
        f"<p>Credentials: {CORRECT_USERNAME} / {CORRECT_PASSWORD}</p>"
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
