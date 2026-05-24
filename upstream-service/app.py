import os
import sqlite3
import time
import uuid

import jwt
from flask import Flask, jsonify, request

DEMO_NAME = "username1234"
DEMO_PASSWORD = "password1234"
JWT_SECRET = "demo-localhost-only-not-for-production-use-32b"
JWT_ALG = "HS256"
USER_ID = 3
TOKEN_TTL_SECONDS = 12 * 60 * 60

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sessions.db")

app = Flask(__name__)


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS user_session (
                user_id INTEGER PRIMARY KEY,
                device_id TEXT,
                active_sid TEXT NOT NULL
            )
            """
        )



def _session_get(user_id: int) -> tuple[str | None, str] | None:
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "SELECT device_id, active_sid FROM user_session WHERE user_id = ?",
            (user_id,),
        )
        row = cur.fetchone()
    if not row:
        return None
    return row[0], row[1]


def _session_put(user_id: int, device_id: str | None, active_sid: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO user_session (user_id, device_id, active_sid)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                device_id = excluded.device_id,
                active_sid = excluded.active_sid
            """,
            (user_id, device_id, active_sid),
        )


@app.route("/")
def index():
    return "hello world"


def _issue_token(user_id: int) -> tuple[str, str]:
    sid = str(uuid.uuid4())
    now = int(time.time())
    payload = {
        "id": user_id,
        "sid": sid,
        "iat": now,
        "exp": now + TOKEN_TTL_SECONDS,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG), sid


def _decode_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])


@app.route("/api/auths/local", methods=["POST"])
def auth_local():
    data = request.get_json(silent=True) or {}
    name = data.get("name", "")
    password = data.get("password", "")
    if name != DEMO_NAME or password != DEMO_PASSWORD:
        return jsonify({"error": "Invalid credentials"}), 401
    login_device = (data.get("deviceId") or "").strip() or None
    token, sid = _issue_token(USER_ID)
    _session_put(USER_ID, login_device, sid)
    return jsonify(
        {
            "fullName": name,
            "name": name,
            "role": "app",
            "token": token,
        }
    )


@app.route("/api/users/valide", methods=["POST"])
def users_valide():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401
    token = auth.removeprefix("Bearer ").strip()
    try:
        claims = _decode_token(token)
    except jwt.PyJWTError:
        return jsonify({"error": "Invalid or expired token"}), 401

    user_id = int(claims.get("id", USER_ID))
    sid = claims.get("sid")
    if not sid:
        return jsonify({"error": "Invalid or expired token"}), 401

    body = request.get_json(silent=True) or {}
    body_device = (body.get("deviceId") or "").strip()

    row = _session_get(user_id)
    if row is None:
        return jsonify({"error": "Invalid or expired token"}), 401

    stored_device, active_sid = row
    if sid != active_sid:
        return jsonify({"error": "Invalid or expired token"}), 401

    if stored_device is not None and body_device != stored_device:
        return (
            jsonify(
                {
                    "code": 403,
                    "message": "El usuario está asignado a otro dispositivo",
                }
            ),
            403,
        )

    if stored_device is None:
        dev = body_device or None
    else:
        dev = stored_device

    _session_put(user_id, dev, sid)

    out = {k: v for k, v in body.items() if k not in ("password", "detachDevices")}
    out["id"] = user_id
    out["token"] = token
    return jsonify(out)


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5001")), debug=True)
