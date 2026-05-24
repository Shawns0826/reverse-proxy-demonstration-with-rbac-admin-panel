import os
from pathlib import Path

from flask import Flask, jsonify, redirect, request, url_for

PROXY_DIR = Path(__file__).resolve().parent

import config
from database_security import initialize_database_security
from extensions import db, login_manager, migrate
from integrations import register_integrations
from routes import register_routes
from security import log_security_event
from workers import initialize_app

app = Flask(
    __name__,
    template_folder=str(PROXY_DIR / "templates"),
    instance_path=str(PROXY_DIR / "instance"),
)
app.secret_key = config.SECRET_KEY

app.config["PERMANENT_SESSION_LIFETIME"] = config.current_config.PERMANENT_SESSION_LIFETIME
app.config["SESSION_COOKIE_SECURE"] = config.current_config.SESSION_COOKIE_SECURE
app.config["SESSION_COOKIE_HTTPONLY"] = config.current_config.SESSION_COOKIE_HTTPONLY
app.config["SESSION_COOKIE_SAMESITE"] = config.current_config.SESSION_COOKIE_SAMESITE

login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.unauthorized_handler
def unauthorized():
    """Handle unauthorized access for API endpoints"""
    log_security_event(
        event_type="UNAUTHORIZED_ACCESS",
        ip_address=request.remote_addr,
        details=f"Attempted access to {request.path}",
    )
    if request.path.startswith("/api/") or request.headers.get("Content-Type") == "application/json":
        return jsonify({"success": False, "message": "Authentication required"}), 401
    return redirect(url_for("login"))


import models  # noqa: F401 — register metadata on db
from models import User


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


print(f"Database: {config.database_url_log_summary(config.DATABASE_URL)}")

try:
    initialize_database_security(config.DATABASE_URL)
    app.config["SQLALCHEMY_DATABASE_URI"] = config.DATABASE_URL
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
        "pool_recycle": 3600,
    }
    print("Database engine initialized.")
except Exception as e:
    print(f"Failed to initialize database connection: {e}")
    app.config["SQLALCHEMY_DATABASE_URI"] = config.DATABASE_URL

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)
migrate.init_app(app, db)

register_integrations(app)
register_routes(app)

initialize_app(app)

if __name__ == "__main__":
    _dev = os.environ.get("FLASK_ENV", "development") != "production"
    app.run(
        debug=_dev,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5002")),
    )
