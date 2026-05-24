import os
import secrets
import sys
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlparse

# Security Configuration
class Config:
    # Generate a secure secret key if not provided
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    
    # Session security
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)  # Session expires in 24 hours
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'  # HTTPS only in production
    SESSION_COOKIE_HTTPONLY = True  # Prevent XSS attacks
    SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
    
    # Password security
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_DIGITS = True
    PASSWORD_REQUIRE_SPECIAL = True
    
    # Rate limiting
    RATELIMIT_DEFAULT = "200 per day;50 per hour;10 per minute"
    RATELIMIT_STORAGE_URL = "memory://"
    
    # API Security
    API_RATE_LIMIT = "100 per hour;20 per minute"

    # HS256 JWT for app clients (not the upstream provider token). Use a long random string
    # (e.g. secrets.token_hex(32)); if unset, SECRET_KEY is used.
    CLIENT_JWT_SECRET = os.environ.get('CLIENT_JWT_SECRET')
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    
    # Database configuration
    DATABASE_URL = os.environ.get('DATABASE_URL')

    # Root admin: never hardcode passwords. First production boot: set ROOTADMIN_BOOTSTRAP_PASSWORD once
    # (must meet PASSWORD_* rules), deploy, log in, change password, then remove that env var.
    # Optional POST /create-rootadmin in production: set ROOTADMIN_CREATE_TOKEN and send X-Bootstrap-Token.
    ROOTADMIN_BOOTSTRAP_USERNAME = (os.environ.get("ROOTADMIN_BOOTSTRAP_USERNAME") or "rootadmin").strip()
    ROOTADMIN_BOOTSTRAP_PASSWORD = os.environ.get("ROOTADMIN_BOOTSTRAP_PASSWORD")
    ROOTADMIN_CREATE_TOKEN = os.environ.get("ROOTADMIN_CREATE_TOKEN")

class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE = False  # Allow HTTP in development

class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True

# Environment-based configuration
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

# Get current environment
FLASK_ENV = os.environ.get('FLASK_ENV', 'development')
current_config = config[FLASK_ENV]

# Apply configuration
SECRET_KEY = current_config.SECRET_KEY
DATABASE_URL = current_config.DATABASE_URL
ROOTADMIN_BOOTSTRAP_USERNAME = current_config.ROOTADMIN_BOOTSTRAP_USERNAME
ROOTADMIN_BOOTSTRAP_PASSWORD = current_config.ROOTADMIN_BOOTSTRAP_PASSWORD
ROOTADMIN_CREATE_TOKEN = current_config.ROOTADMIN_CREATE_TOKEN

# Deprecated aliases (godadmin rename); remove once env/docs are updated.
GODADMIN_BOOTSTRAP_USERNAME = ROOTADMIN_BOOTSTRAP_USERNAME
GODADMIN_BOOTSTRAP_PASSWORD = ROOTADMIN_BOOTSTRAP_PASSWORD
GODADMIN_CREATE_TOKEN = ROOTADMIN_CREATE_TOKEN


def database_url_log_summary(url):
    """Host + database name only — never log user, password, or full URI."""
    if not url:
        return "not set"
    if url.startswith("sqlite:"):
        return "sqlite (local file)"
    try:
        p = urlparse(url)
        host = p.hostname or "?"
        db = (p.path or "").strip("/") or "?"
        return f"{p.scheme}://{host}/{db}"
    except Exception:
        return "(configured)"


if not DATABASE_URL:
    if FLASK_ENV == "production":
        sys.exit(
            "DATABASE_URL must be set in the environment for production "
            "(e.g. Render dashboard → Environment)."
        )
    _instance = Path(__file__).resolve().parent / "instance"
    _instance.mkdir(exist_ok=True)
    _dbfile = _instance / "app.db"
    DATABASE_URL = "sqlite:///" + _dbfile.as_posix()

# Render/Heroku sometimes use postgres:// — SQLAlchemy expects postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Security warnings
if FLASK_ENV == 'production':
    if not os.environ.get('SECRET_KEY'):
        print("WARNING: SECRET_KEY not set in production environment!")
    if not os.environ.get('CLIENT_JWT_SECRET'):
        print("WARNING: CLIENT_JWT_SECRET not set in production; client JWT falls back to SECRET_KEY!")


def allow_public_trial_signup():
    """POST /create-trial-account: disabled in production unless ALLOW_PUBLIC_TRIAL_SIGNUP is truthy."""
    v = os.environ.get("ALLOW_PUBLIC_TRIAL_SIGNUP")
    if v is None:
        return FLASK_ENV != "production"
    return v.strip().lower() in ("1", "true", "yes")


def trial_duration_hours():
    """Wall-clock trial length for role=trial (from account created_at). Override with TRIAL_DURATION_HOURS."""
    try:
        return max(0.25, float(os.environ.get("TRIAL_DURATION_HOURS", "2")))
    except (TypeError, ValueError):
        return 2.0