"""Flask extensions and small process-wide shared state (no models or routes)."""
import threading

from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()

upstream_token_cache = {"token": None, "expires_at": None, "raw_response": None}
upstream_token_lock = threading.Lock()
