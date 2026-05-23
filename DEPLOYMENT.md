# Deploying this Flask app (Linux / new environment)

Plain text sections; open with any editor (`less DEPLOYMENT.md`, `nano`, VS Code, etc.).

---

## 1. What you need installed

- **Python 3.11+** (3.12 is fine). Check: `python3 --version`
- **PostgreSQL** reachable from the app host (production **requires** `DATABASE_URL`; local SQLite is only for non-production when `DATABASE_URL` is unset).
- **pip** and a virtual environment (recommended):

```bash
cd /path/to/flask-login-app
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## 2. Production environment variables (required)

Set these in your host (systemd, Docker, Render, etc.). Names are exact.

| Variable | Required? | Purpose |
|----------|-----------|---------|
| `FLASK_ENV` | **Yes** for real deploys | Set to `production` for HTTPS cookies and stricter behavior. |
| `DATABASE_URL` | **Yes** in production | PostgreSQL URL, e.g. `postgresql://USER:PASSWORD@HOST:5432/DBNAME`. App exits at startup if missing in production. |
| `SECRET_KEY` | **Strongly yes** | Long random string for Flask sessions. Generate e.g. `python3 -c "import secrets; print(secrets.token_hex(32))"`. |
| **Upstream API** | **Configure in code** | Set `UPSTREAM_*` constants in `integrations.py` (base URL, shared pool login, proxy options). Not read from environment variables. |

Optional but recommended:

| Variable | Purpose |
|----------|---------|
| `CLIENT_JWT_SECRET` | Separate secret for HS256 client JWTs; if unset, `SECRET_KEY` is used (logs a warning in production). |
| `PORT` | Listen port (many PaaS set this automatically, e.g. Render). |

---

## 3. Upstream proxy (optional reading)

Transparent `/api/*` forwarding, shared-pool upstream login, and JSON hygiene are controlled by **`UPSTREAM_*`** module-level constants in **`integrations.py`** (including `UPSTREAM_API_BASE`, optional full auth/valide/detach URL overrides, `UPSTREAM_SHARED_*`, `UPSTREAM_USER_ID`, proxy timeouts, skip paths, and playback merge). Edit that file and redeploy to change upstream behavior.

**App / client:**

- `APP_LATEST_VERSION` — if set, `/check-version` compares client `version` query param to this.
- `APK_DOWNLOAD_URL` — optional download link when an update is required.

**Root admin bootstrap (first deploy):**

- `ROOTADMIN_BOOTSTRAP_PASSWORD` — one-time password to create first `rootadmin` if none exists (must meet password policy below). Remove after first login and password change.
- `ROOTADMIN_BOOTSTRAP_USERNAME` — optional; defaults to `rootadmin`.

**Emergency rootadmin API (production):**

- `ROOTADMIN_CREATE_TOKEN` — long random secret; `POST /create-rootadmin` requires header `X-Bootstrap-Token` matching this value in production.

**Trial / signup:**

- `ALLOW_PUBLIC_TRIAL_SIGNUP` — truthy to allow `POST /create-trial-account` in production (default off in production).
- `TRIAL_DURATION_HOURS` — trial window length (default `2`).

**Logging / DB tuning:**

- `LOG_LEVEL` — default `INFO`.
- `DB_POOL_SIZE`, `DB_MAX_OVERFLOW`, `DB_POOL_TIMEOUT`, `DB_POOL_RECYCLE`, `DB_SSL_MODE`, `DB_FORCE_SSL`, `DB_SSL_CERT`, `DB_SSL_KEY`, `DB_SSL_ROOT_CERT`, `DB_STATEMENT_TIMEOUT`, `DB_SLOW_QUERY_THRESHOLD`, `APP_NAME` — see `DATABASE_SECURITY_SETUP.md` and `database_security.py`.

**JWT lifetime:**

- `CLIENT_JWT_TTL_HOURS` — default `12`.

---

## 4. Password policy (rootadmin bootstrap and user passwords)

From `config.py`, passwords must satisfy:

- At least **8** characters  
- At least one **uppercase**, one **lowercase**, one **digit**, one **special** character  

If `ROOTADMIN_BOOTSTRAP_PASSWORD` fails this, rootadmin is not created and the server prints a policy error.

---

## 5. Database migrations

With `DATABASE_URL` set and `FLASK_ENV` as you intend:

```bash
export FLASK_ENV=production
export DATABASE_URL='postgresql://...'
export SECRET_KEY='...'
source .venv/bin/activate
flask db upgrade
```

If `flask` is not on PATH, use `python3 -m flask db upgrade`.  
On first boot the app also runs `db.create_all()` from `init_db`, but **Alembic migrations** are the source of truth for schema evolution—run `upgrade` on each deploy.

---

## 6. First rootadmin (pick one path)

### Path A — Bootstrap env (simplest for first boot)

1. Set `ROOTADMIN_BOOTSTRAP_PASSWORD` (and optionally `ROOTADMIN_BOOTSTRAP_USERNAME`) to values meeting the password policy.  
2. Deploy/start the app once with **no** existing `rootadmin` user in the DB.  
3. Log in via the web UI, **change the password**, then **remove** `ROOTADMIN_BOOTSTRAP_PASSWORD` from the environment and redeploy.

### Path B — `POST /create-rootadmin` (production)

1. Set `ROOTADMIN_CREATE_TOKEN` to a long random string.  
2. Redeploy.  
3. Call the endpoint with JSON `{"username":"...","password":"..."}` and header `X-Bootstrap-Token: <same token>`.  
4. Unset `ROOTADMIN_CREATE_TOKEN` when finished if you do not want the endpoint usable anymore.

In **non-production**, `POST /create-rootadmin` works without `X-Bootstrap-Token` if no rootadmin exists (use only on trusted networks).

---

## 7. Running the app (example)

**Gunicorn** (typical for Linux servers / Render):

```bash
export FLASK_ENV=production
export DATABASE_URL='postgresql://...'
export SECRET_KEY='...'
# ... all other required vars ...
source .venv/bin/activate
gunicorn --bind 0.0.0.0:${PORT:-8000} --workers 2 app:app
```

Render sets `PORT` automatically; bind to `0.0.0.0` and that port.

**Local dev only** (SQLite under `instance/app.db` when `DATABASE_URL` is unset and `FLASK_ENV` is not `production`):

```bash
export FLASK_ENV=development
python3 app.py
```

---

## 8. Quick health checks after deploy

- Open the login page or hit a simple route.  
- If clients use upstream auth: confirm `UPSTREAM_*` values in `integrations.py` match your deployed upstream (wrong base URL or pool credentials produce JSON errors in responses / logs).  
- `GET /check-version?version=...` — if `APP_LATEST_VERSION` is unset, response explains that version enforcement is not configured.

---

## 9. Security reminders

- Never commit `.env` or real `DATABASE_URL` / passwords into git.  
- Rotate any secret that was ever pasted into chat, tickets, or logs.  
- Remove `ROOTADMIN_BOOTSTRAP_PASSWORD` after the first rootadmin login.  
- Use HTTPS in production (`SESSION_COOKIE_SECURE` follows `FLASK_ENV`).

---

## 10. Dependency list

See `requirements.txt` (Flask, SQLAlchemy, Migrate, Gunicorn, psycopg2-binary, PyJWT, requests, etc.).
