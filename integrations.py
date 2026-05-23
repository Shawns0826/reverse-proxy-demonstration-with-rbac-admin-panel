"""Upstream provider integration: shared authentication, client JWTs, /api/* proxy, and valide playback merge."""
import os
import re
import base64
import json
import copy
import calendar
import uuid
from datetime import datetime, UTC, timedelta

import jwt
import requests
from flask import jsonify, request, Response, g

import config
from extensions import db, upstream_token_cache, upstream_token_lock
from models import User, Device
from security import SecurityUtils, log_security_event

# --- Catch-all proxy: forward unknown /api/* upstream (see UPSTREAM_API_BASE) ---
_HOP_BY_HOP_HEADERS = frozenset({
    'host', 'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'te', 'trailers', 'transfer-encoding', 'upgrade',
})
# Let requests set Content-Length (body may be rewritten, e.g. deviceId blanking for upstream).
_UPSTREAM_REQ_DROP_HEADERS = frozenset({'content-length'})
_RESP_HEADERS_DROP = frozenset({
    'content-encoding', 'transfer-encoding', 'content-length', 'connection',
})

# ---------------------------------------------------------------------------
# Upstream API — edit here (not read from environment; see DEPLOYMENT.md §3).
# Local mock: this app listens on PORT (default 5001); upstream API on another port (e.g. 5002)
# so proxied /api/* traffic is not forwarded back into this same process.
# ---------------------------------------------------------------------------
UPSTREAM_API_BASE = "http://127.0.0.1:5002"
# Optional full URL overrides; leave empty to derive from UPSTREAM_API_BASE.
UPSTREAM_AUTH_URL = ""
UPSTREAM_VALIDE_URL = ""
UPSTREAM_DETACH_URL_BASE = ""
# Must match a real account on UPSTREAM_API_BASE (shared “pool” user for proxying), not each customer’s login.
UPSTREAM_SHARED_NAME = "username1234"
UPSTREAM_SHARED_PASSWORD = "password1234"
UPSTREAM_SHARED_PROVIDER = "com.sticktv.tv"
# Optional shared-account user id (Mongo-style) for detach + JSON id masking when not in JWT/auth body.
UPSTREAM_USER_ID = ""
UPSTREAM_API_PROXY_ENABLED = True
UPSTREAM_API_PROXY_TIMEOUT_SECONDS = 60.0
UPSTREAM_API_PROXY_ACCEPT_ENCODING = "gzip, deflate"
# Comma-separated exact /api/... paths to handle locally instead of forwarding (in addition to built-ins).
UPSTREAM_API_PROXY_SKIP_PATHS = ""
# Comma-separated extra substrings to replace in proxied JSON (see _mask_upstream_strings_in_json).
UPSTREAM_MASK_EXTRA_SUBSTRINGS = ""
UPSTREAM_VALIDE_PLAYBACK_MERGE_ENABLED = True


def _upstream_shared_credentials():
    """Shared streaming account sent to upstream POST /api/auths/local."""
    return (
        (UPSTREAM_SHARED_NAME or "").strip(),
        (UPSTREAM_SHARED_PASSWORD or "").strip(),
        (UPSTREAM_SHARED_PROVIDER or "").strip(),
    )

def _client_jwt_secret():
    return getattr(config.current_config, "CLIENT_JWT_SECRET", None) or config.SECRET_KEY


def _client_jwt_ttl_hours():
    try:
        return float(os.environ.get("CLIENT_JWT_TTL_HOURS", "12"))
    except ValueError:
        return 12.0


def _upstream_api_origin():
    """Base URL for upstream API (no trailing slash)."""
    return (UPSTREAM_API_BASE or "").strip().rstrip("/")


def _upstream_auth_url():
    u = (UPSTREAM_AUTH_URL or "").strip()
    if u:
        return u
    o = _upstream_api_origin()
    return f"{o}/api/auths/local" if o else ""


def _upstream_detach_url_base():
    b = (UPSTREAM_DETACH_URL_BASE or "").strip().rstrip("/")
    if b:
        return b
    o = _upstream_api_origin()
    return f"{o}/api/users/detachDevice" if o else ""


def _upstream_valide_url():
    u = (UPSTREAM_VALIDE_URL or "").strip()
    if u:
        return u
    o = _upstream_api_origin()
    return f"{o}/api/users/valide" if o else ""


def issue_client_jwt(user):
    """
    HS256 JWT: id, sid, iat, exp. sid matches user.auth_session_id so a new login revokes older tokens.
    """
    now = datetime.now(UTC)
    iat = int(now.timestamp())
    exp = int((now + timedelta(hours=_client_jwt_ttl_hours())).timestamp())
    sid = str(uuid.uuid4())
    user.auth_session_id = sid
    db.session.add(user)
    db.session.commit()
    payload = {
        "id": user.id,
        "sid": sid,
        "iat": iat,
        "exp": exp,
    }
    token = jwt.encode(payload, _client_jwt_secret(), algorithm="HS256")
    return token if isinstance(token, str) else token.decode("utf-8")


def refresh_client_jwt(user):
    """
    New exp (and iat) but same auth_session_id as issue_client_jwt — use when re-embedding
    the client token in proxied JSON so we do not rotate the session on every API call.
    """
    now = datetime.now(UTC)
    iat = int(now.timestamp())
    exp = int((now + timedelta(hours=_client_jwt_ttl_hours())).timestamp())
    sid = getattr(user, "auth_session_id", None)
    if not sid:
        return issue_client_jwt(user)
    payload = {
        "id": user.id,
        "sid": sid,
        "iat": iat,
        "exp": exp,
    }
    token = jwt.encode(payload, _client_jwt_secret(), algorithm="HS256")
    return token if isinstance(token, str) else token.decode("utf-8")


def _decode_client_jwt_token(token_str):
    return jwt.decode(
        token_str,
        _client_jwt_secret(),
        algorithms=["HS256"],
        options={"require": ["exp", "iat"]},
    )


def _trial_deadline_utc(user):
    if getattr(user, "role", None) != "trial" or not user.created_at:
        return None
    return user.created_at + timedelta(hours=config.trial_duration_hours())


def trial_window_expired(user):
    d = _trial_deadline_utc(user)
    if d is None:
        return False
    return datetime.utcnow() > d


# Gson ApiError { code, message }; client uses message substring for DeviceDetachDialog on valide only.
# Spanish device string from upstream on proxied APIs; we neutralize on proxy. Local auth no longer returns it.
CLIENT_DEVICE_SESSION_MESSAGE = "El usuario está asignado a otro dispositivo"

# English only — proxied API (movies, etc.): session ended after detachdevices or new login (no detach-dialog substring).
PROXY_SESSION_ENDED_MESSAGE = "Session ended"

TRIAL_EXPIRED_MESSAGE = (
    "Your free trial has ended. Please subscribe to continue."
)

_JSON_UTF8 = "application/json; charset=utf-8"


def json_response_utf8(payload, status):
    """application/json; charset=utf-8, compact UTF-8 body (typical mobile client wire format)."""
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return Response(body, status=status, content_type=_JSON_UTF8)


def json_api_error_utf8(code, message):
    """Retrofit-style ApiError: {\"code\": int, \"message\": str}; HTTP status usually matches code."""
    return json_response_utf8({"code": code, "message": message}, code)


def invalidate_outstanding_client_sessions(user):
    """
    End every previously issued client JWT for this user (e.g. after PUT detachdevices).
    New sid via issue_client_jwt on login/detach/password; valide only refreshes JWT exp (same sid).
    """
    user.auth_session_id = str(uuid.uuid4())
    db.session.add(user)
    db.session.commit()


def _user_for_detachdevices_request():
    """
    Identify user for PUT detachdevices: valid Bearer client JWT (any sid), else JSON body
    name + password (same as valide). Clears stored Device row(s) and invalidates client JWT sessions.
    Returns (user, None) or (None, (response, status_code)).
    """
    auth = request.headers.get("Authorization")
    if auth and auth.lower().startswith("bearer "):
        raw = auth[7:].strip()
        if raw:
            try:
                claims = _decode_client_jwt_token(raw)
                uid = claims.get("id")
                user = User.query.get(uid) if uid is not None else None
                if user:
                    return user, None
            except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                pass
    data = request.get_json(silent=True) or {}
    username = SecurityUtils.sanitize_input(
        (data.get("name") or data.get("username") or data.get("userName") or "")
    )
    password = data.get("password", "")
    if not username or not password:
        return None, (jsonify({"message": "Authorization or name and password required"}), 401)
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        log_security_event(
            event_type="LOGIN_FAILED",
            ip_address=request.remote_addr,
            details="detachdevices: invalid credentials in body",
        )
        return None, (jsonify({"message": "Invalid credentials"}), 401)
    return user, None


def _client_jwt_user_from_request(headers, require_bearer=True):
    """
    Validate Authorization: Bearer <our client JWT>. Returns (user, None) or (None, (response, status)).
    No upstream HTTP call — use for local-only API handlers.
    If require_bearer is False and there is no Bearer header, returns (None, None) so callers can skip.
    """
    auth = headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        if require_bearer:
            return None, (jsonify({"message": "Authorization required"}), 401)
        return None, None
    raw = auth[7:].strip()
    if not raw:
        return None, (jsonify({"message": "Authorization required"}), 401)
    try:
        claims = _decode_client_jwt_token(raw)
    except jwt.ExpiredSignatureError:
        return None, (jsonify({"message": "Token expired"}), 401)
    except jwt.InvalidTokenError:
        return None, (jsonify({"message": "Invalid token"}), 401)

    uid = claims.get("id")
    user = User.query.get(uid) if uid is not None else None
    if not user:
        return None, (jsonify({"message": "Invalid token"}), 401)
    token_sid = claims.get("sid")
    if not token_sid:
        return None, (json_api_error_utf8(401, PROXY_SESSION_ENDED_MESSAGE), 401)
    expected_sid = getattr(user, "auth_session_id", None)
    if expected_sid is None or str(token_sid) != str(expected_sid):
        return None, (json_api_error_utf8(401, PROXY_SESSION_ENDED_MESSAGE), 401)
    if trial_window_expired(user):
        return None, (jsonify({"message": TRIAL_EXPIRED_MESSAGE}), 403)
    if user.role not in ("rootadmin", "admin", "reseller") and not user.has_active_credits():
        return None, (jsonify({
            "message": "No credits remaining. Contact your reseller to extend your subscription."
        }), 403)
    return user, None


def _swap_client_bearer_for_upstream(headers):
    """
    If headers['Authorization'] is our client JWT, replace with shared upstream bearer token.
    Rejects tokens issued before the current server session (detachdevices, password change, or new login
    bumps user.auth_session_id; JWT carries sid). Generic 401 on mismatch — not the Spanish valide message.
    """
    user, err = _client_jwt_user_from_request(headers, require_bearer=False)
    if err is not None:
        return err
    if user is None:
        return None

    shared_auth_payload, shared_auth_error = get_shared_upstream_auth_payload()
    if shared_auth_error:
        return jsonify({
            "message": "Upstream authentication unavailable",
            "upstream_error": shared_auth_error,
        }), 502
    upstream_token = shared_auth_payload.get("token")
    if not upstream_token:
        return jsonify({"message": "Upstream authentication token missing"}), 502

    headers["Authorization"] = f"Bearer {upstream_token}"
    g.proxy_client_user = user
    return None


def _neutralize_upstream_device_message_in_proxy_payload(payload, status_code):
    """
    Upstream often returns 403 + the same Spanish device string on shared-account APIs (e.g. /api/movies).
    We only want that substring on valide/auth paths so the client does not open DeviceDetachDialog here.
    """
    if status_code != 403 or not isinstance(payload, dict):
        return payload, False
    msg = payload.get("message")
    if not isinstance(msg, str) or CLIENT_DEVICE_SESSION_MESSAGE not in msg:
        return payload, False
    out = dict(payload)
    out["message"] = "Service temporarily unavailable"
    out.setdefault("code", 403)
    return out, True


def _upstream_proxy_json_is_shared_device_lock(payload):
    """True when upstream rejected the shared account for device binding (raw body, before neutralize)."""
    if not isinstance(payload, dict):
        return False
    msg = payload.get("message")
    return isinstance(msg, str) and CLIENT_DEVICE_SESSION_MESSAGE in msg


def _redact_json_tokens(obj, replacement=None):
    """
    Remove or replace every 'token' key in a JSON-like tree so upstream JWTs are not leaked.
    replacement=str -> set each token key to that string; None -> omit token keys.
    """
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k == "token":
                if replacement is not None:
                    out[k] = replacement
                continue
            out[k] = _redact_json_tokens(v, replacement)
        return out
    if isinstance(obj, list):
        return [_redact_json_tokens(i, replacement) for i in obj]
    return obj


def _api_path_is_handled_locally(path):
    """Paths served by our app with custom logic (not raw-forwarded upstream)."""
    if path == '/api/auths/local':
        return True
    if path == '/api/users/valide':
        return True
    if path.startswith('/api/users/detachDevice/'):
        return True
    if path == '/api/users/detachdevices':
        return True
    # Local-only: customer password lives in our DB only; never send this route upstream.
    if path == '/api/users/password':
        return True
    for extra in UPSTREAM_API_PROXY_SKIP_PATHS.split(','):
        p = extra.strip()
        if p and path == p:
            return True
    return False

def _forward_request_to_upstream():
    g.proxy_client_user = None
    origin = _upstream_api_origin()
    if not origin:
        return jsonify({"message": "UPSTREAM_API_BASE is empty in integrations.py"}), 503
    target_url = origin + request.full_path
    enc = UPSTREAM_API_PROXY_ACCEPT_ENCODING

    def _proxy_attempt():
        h = {
            k: v for k, v in request.headers.items()
            if k.lower() not in _HOP_BY_HOP_HEADERS
            and k.lower() not in _UPSTREAM_REQ_DROP_HEADERS
        }
        h['Accept-Encoding'] = enc
        swap_err = _swap_client_bearer_for_upstream(h)
        if swap_err is not None:
            return None, swap_err
        try:
            up = requests.request(
                method=request.method,
                url=target_url,
                headers=h,
                data=_upstream_proxy_outbound_body_bytes(),
                cookies=request.cookies,
                timeout=float(UPSTREAM_API_PROXY_TIMEOUT_SECONDS),
                allow_redirects=False,
            )
        except requests.Timeout:
            return None, (jsonify({"message": "Upstream request timed out"}), 504)
        except requests.RequestException as exc:
            return None, (jsonify({"message": "Upstream unavailable", "detail": str(exc)}), 502)
        return up, None

    upstream, err = _proxy_attempt()
    if err is not None:
        return err

    if upstream.status_code == 403:
        ct0 = (upstream.headers.get("Content-Type") or "").lower()
        if "application/json" in ct0 and upstream.content:
            try:
                probe = json.loads(upstream.content.decode("utf-8"))
            except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
                probe = None
            if _upstream_proxy_json_is_shared_device_lock(probe):
                ok_detach, det_err = _upstream_detach_shared_account()
                if not ok_detach:
                    log_security_event(
                        event_type="DEVICE_BIND_FAILED",
                        user_id=getattr(g.proxy_client_user, "id", None),
                        ip_address=request.remote_addr,
                        details=f"proxy: upstream 403 device lock; shared detach failed: {det_err}",
                    )
                _invalidate_shared_upstream_token_cache()
                upstream2, err2 = _proxy_attempt()
                if err2 is not None:
                    return err2
                upstream = upstream2

    excluded = _RESP_HEADERS_DROP
    content_type = (upstream.headers.get("Content-Type") or "").lower()
    body = upstream.content
    if body and "application/json" in content_type:
        try:
            payload = upstream.json()
            payload, _neutralized = _neutralize_upstream_device_message_in_proxy_payload(
                payload, upstream.status_code
            )
            repl = None
            pu = getattr(g, "proxy_client_user", None)
            if pu is not None:
                payload = _normalize_upstream_proxy_json_for_client(payload, pu)
                repl = refresh_client_jwt(pu)
            payload = _redact_json_tokens(payload, repl)
            body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        except (ValueError, TypeError):
            body = upstream.content

    proxy_resp = Response(body, status=upstream.status_code)
    for key, value in upstream.headers.items():
        if key.lower() not in excluded:
            if key.lower() == "etag" and body != upstream.content:
                continue
            proxy_resp.headers[key] = value
    if "application/json" in content_type and body:
        proxy_resp.headers["Content-Type"] = upstream.headers.get(
            "Content-Type", "application/json; charset=utf-8"
        )
    return proxy_resp

def register_integrations(app):
    @app.before_request
    def upstream_api_catchall_proxy():
        """Transparently proxy /api/* upstream except routes we implement locally."""
        if not UPSTREAM_API_PROXY_ENABLED:
            return None
        path = request.path
        if not path.startswith('/api/'):
            return None
        if _api_path_is_handled_locally(path):
            return None
        return _forward_request_to_upstream()


def get_expiration_info(user):
    """Get expiration information for different credit types"""
    c = user.credits_int
    if user.role == "trial":
        if trial_window_expired(user):
            return "Trial expired"
        if c <= 0:
            return "No credits remaining"
        deadline = _trial_deadline_utc(user)
        if not deadline:
            return f"{c} trial credits remaining"
        rem = deadline - datetime.utcnow()
        secs = int(rem.total_seconds())
        if secs <= 0:
            return "Trial expired"
        h, r = divmod(secs, 3600)
        m, _ = divmod(r, 60)
        if h > 0:
            return f"{c} trial credits; {h}h {m}m left"
        return f"{c} trial credits; {m} min left"

    if c <= 0:
        return "No credits remaining"

    if user.role == 'test':
        return f"{c} test credits remaining"
    else:  # regular credits
        return f"{c} months remaining"

def _decode_jwt_payload_unverified(token):
    """Decode JWT payload JSON without signature verification."""
    try:
        token_parts = token.split('.')
        if len(token_parts) < 2:
            return None
        payload_b64 = token_parts[1]
        padded = payload_b64 + '=' * (-len(payload_b64) % 4)
        payload_json = base64.urlsafe_b64decode(padded.encode('utf-8')).decode('utf-8')
        return json.loads(payload_json)
    except Exception:
        return None


def _decode_jwt_exp(token):
    """Decode JWT exp claim without signature verification."""
    payload = _decode_jwt_payload_unverified(token)
    if not payload:
        return None
    exp = payload.get('exp')
    return int(exp) if exp is not None else None


def _local_display_name(username):
    """Friendly display string from our DB username (never upstream identity)."""
    return username.replace('_', ' ')

def _mask_upstream_strings_in_json(obj, local_username, local_display_name):
    """
    Replace shared upstream account strings anywhere in JSON-like structures so
    clients never see the upstream username/display name in nested payloads.
    Configure optional extra substrings via UPSTREAM_MASK_EXTRA_SUBSTRINGS (comma-separated).

    Not covered here (by design or limitation):
    - Opaque crypto fields (cbn, cfv, chak, …) may still be bound to the upstream session; do not strip.
    - Content/document Mongo _id values (movies, backgrounds) are not user ids; we do not rewrite them.
    - URLs (trailers, CDNs) may point at provider hosts; add substrings to UPSTREAM_MASK_EXTRA_SUBSTRINGS if needed.
    - New JSON key names holding the shared user id: extend _PROXY_USER_ID_JSON_KEYS or valide scrubbers.
    """
    shared_name, _, _ = _upstream_shared_credentials()
    extra = UPSTREAM_MASK_EXTRA_SUBSTRINGS
    # (needle, replacement, case_insensitive)
    rules = []
    if shared_name:
        rules.append((shared_name, local_username, False))
    for part in extra.split(","):
        needle = part.strip()
        if needle:
            rules.append((needle, local_display_name, True))
    if not rules:
        return obj

    def replace_in_str(s):
        out = s
        for needle, repl, ci in rules:
            if not needle:
                continue
            if ci:
                out = re.sub(re.escape(needle), repl, out, flags=re.IGNORECASE)
            else:
                out = out.replace(needle, repl)
        return out

    def walk(x):
        if isinstance(x, dict):
            return {k: walk(v) for k, v in x.items()}
        if isinstance(x, list):
            return [walk(i) for i in x]
        if isinstance(x, str):
            return replace_in_str(x)
        return x

    return walk(obj)


# JSON keys where a scalar is expected to be the shared upstream pool user id (never movie/content _id).
_PROXY_USER_ID_JSON_KEYS = frozenset({
    "userid", "user_id", "ownerid", "owner_id", "createdby", "createdbyuser",
    "authorid", "author_id", "addedby", "addedbyuser", "uploaduserid", "upload_user_id",
    "lastmodifiedby", "last_modified_by",
})


def _collect_upstream_identity_scalar_needles():
    """
    String and int forms of the shared upstream pool account id for proxy response rewriting.
    Uses UPSTREAM_USER_ID + in-memory token cache only (no network).
    """
    strs = set()
    ints = set()
    v = (UPSTREAM_USER_ID or "").strip()
    if v:
        strs.add(v)
        if v.isdigit():
            ints.add(int(v))
    with upstream_token_lock:
        raw = upstream_token_cache.get("raw_response")
        tok = upstream_token_cache.get("token")
    rd = raw if isinstance(raw, dict) else {}
    jp = _decode_jwt_payload_unverified(tok) if tok else None
    uid = _upstream_user_id_from_auth_sources(rd, jp)
    if uid:
        strs.add(uid)
        if uid.isdigit():
            ints.add(int(uid))
    return strs, ints


def _rewrite_scalar_if_upstream_user_id(val, local_user, str_needles, int_needles):
    if local_user is None or (not str_needles and not int_needles):
        return val
    if isinstance(val, int) and not isinstance(val, bool) and val in int_needles:
        return int(local_user.id)
    if isinstance(val, str):
        if val in str_needles:
            return str(local_user.id)
        if val.isdigit() and int(val) in int_needles:
            return str(local_user.id)
    return val


def _mask_upstream_user_ref_fields_in_json(obj, local_user):
    """
    On whitelisted keys only, replace values matching the shared upstream pool user id with local_user.id.
    Avoids touching content _id / movie ids.
    """
    str_needles, int_needles = _collect_upstream_identity_scalar_needles()
    if local_user is None or (not str_needles and not int_needles):
        return obj

    def walk(x):
        if isinstance(x, dict):
            out = {}
            for k, v in x.items():
                v2 = walk(v)
                lk = k.lower() if isinstance(k, str) else ""
                if lk in _PROXY_USER_ID_JSON_KEYS:
                    v2 = _rewrite_scalar_if_upstream_user_id(
                        v2, local_user, str_needles, int_needles
                    )
                out[k] = v2
            return out
        if isinstance(x, list):
            return [walk(i) for i in x]
        return x

    return walk(obj)


def _normalize_upstream_proxy_json_for_client(payload, local_user):
    """Single place: strip shared username strings + rewrite known user-ref fields to local id."""
    if local_user is None:
        return payload
    out = _mask_upstream_strings_in_json(
        payload, local_user.username, _local_display_name(local_user.username)
    )
    return _mask_upstream_user_ref_fields_in_json(out, local_user)


def _add_calendar_months(dt, months):
    """Add whole calendar months to a datetime (preserves tzinfo if present)."""
    if months <= 0:
        return dt
    month_index = dt.month - 1 + months
    year = dt.year + month_index // 12
    month = month_index % 12 + 1
    last_day = calendar.monthrange(year, month)[1]
    day = min(dt.day, last_day)
    return dt.replace(year=year, month=month, day=day)

def _user_subscription_date_expire_str(user):
    """
    Expiry string for app payloads (DD/MM/YYYY). One DB credit = one calendar month from now.
    Trial: wall-clock end from created_at + TRIAL_DURATION_HOURS (default 2). Empty when expired or no credits.
    """
    if user.role == "trial":
        if trial_window_expired(user) or user.credits_int <= 0:
            return ""
        d = _trial_deadline_utc(user)
        return d.strftime("%d/%m/%Y") if d else ""
    c = user.credits_int
    if c <= 0:
        return ""
    end = _add_calendar_months(datetime.now(UTC), c)
    return end.strftime("%d/%m/%Y")

def get_shared_upstream_auth_payload():
    """
    Fetch (or reuse cached) shared upstream auth payload for /api/* proxying, valide playback merge,
    and POST /api/auths/local (after local password ok). Reuses the cached upstream JWT until its
    exp (minus 60s); only then POSTs upstream /api/auths/local again. In-memory cache is cleared on
    process restart; multi-worker setups have one cache per worker.
    Returns: (payload_dict_or_none, error_message_or_none)
    """
    now_ts = int(datetime.now(UTC).timestamp())
    with upstream_token_lock:
        cached_exp = upstream_token_cache.get("expires_at")
        cached_payload = upstream_token_cache.get("raw_response")
        if cached_payload and cached_exp and cached_exp > (now_ts + 60):
            return cached_payload, None

        upstream_url = _upstream_auth_url()
        shared_name, shared_password, shared_provider = _upstream_shared_credentials()

        if not upstream_url:
            return None, "Upstream auth URL empty (set UPSTREAM_API_BASE or UPSTREAM_AUTH_URL in integrations.py)"
        if not shared_name or not shared_password or not shared_provider:
            return None, "Shared upstream credentials empty (UPSTREAM_SHARED_* in integrations.py)"

        try:
            upstream_response = requests.post(
                upstream_url,
                json={
                    "name": shared_name,
                    "password": shared_password,
                    "provider": shared_provider,
                },
                timeout=15
            )
        except requests.RequestException as exc:
            return None, f"Could not reach upstream auth server: {str(exc)}"

        if upstream_response.status_code != 200:
            snippet = (upstream_response.text or "")[:400].replace("\r", " ").replace("\n", " ")
            return None, (
                f"Upstream auth HTTP {upstream_response.status_code} from {upstream_url!r} "
                f"(body snippet: {snippet!r})"
            )

        try:
            upstream_payload = upstream_response.json()
        except ValueError:
            return None, "Upstream auth returned invalid JSON"

        token = upstream_payload.get("token")
        if not token:
            return None, "Upstream auth response did not include token"

        token_exp = _decode_jwt_exp(token)
        if token_exp is None:
            token_exp = now_ts + 300  # Fallback cache TTL when exp is missing

        upstream_token_cache["token"] = token
        upstream_token_cache["expires_at"] = token_exp
        upstream_token_cache["raw_response"] = upstream_payload
        return upstream_payload, None


def _invalidate_shared_upstream_token_cache():
    """Clear cached upstream provider JWT so the next request fetches a fresh token."""
    with upstream_token_lock:
        upstream_token_cache["token"] = None
        upstream_token_cache["expires_at"] = None
        upstream_token_cache["raw_response"] = None


def _upstream_user_id_from_auth_sources(auth_body, jwt_payload):
    """
    Best-effort upstream user id for PUT detachDevice on the shared pool account (proxy self-heal only).
    """
    for d in (auth_body, jwt_payload):
        if not isinstance(d, dict):
            continue
        for key in ("id", "_id", "userId", "user_id"):
            v = d.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
            if isinstance(v, int) and not isinstance(v, bool):
                return str(v)
        sub = d.get("sub")
        if isinstance(sub, str) and len(sub) == 24 and all(
            c in "0123456789abcdef" for c in sub.lower()
        ):
            return sub
    return None


def _resolve_upstream_detach_user_id():
    env_id = (UPSTREAM_USER_ID or "").strip()
    if env_id:
        return env_id, None

    with upstream_token_lock:
        raw = upstream_token_cache.get("raw_response")
        tok = upstream_token_cache.get("token")

    jwt_payload = _decode_jwt_payload_unverified(tok) if tok else None
    uid = _upstream_user_id_from_auth_sources(raw or {}, jwt_payload)
    if uid:
        return uid, None

    payload, err = get_shared_upstream_auth_payload()
    if err:
        return None, err
    tok2 = payload.get("token") if isinstance(payload, dict) else None
    jwt_payload = _decode_jwt_payload_unverified(tok2) if tok2 else None
    uid = _upstream_user_id_from_auth_sources(payload if isinstance(payload, dict) else {}, jwt_payload)
    if uid:
        return uid, None
    return None, "Upstream auth response and JWT did not expose a user id; set UPSTREAM_USER_ID in integrations.py"


def _upstream_detach_shared_account():
    """
    Clear device binding on the upstream shared streaming pool user only.
    Used when the /api/* proxy gets 403 + device message — not called from customer detach/valide.
    """
    shared_auth_payload, shared_auth_error = get_shared_upstream_auth_payload()
    if shared_auth_error:
        return False, shared_auth_error
    token = shared_auth_payload.get("token")
    if not token:
        return False, "Upstream token missing"
    vid, verr = _resolve_upstream_detach_user_id()
    if not vid:
        return False, verr or "Could not resolve upstream pool user id"
    base = _upstream_detach_url_base()
    if not base:
        return False, "Set UPSTREAM_API_BASE or UPSTREAM_DETACH_URL_BASE in integrations.py"
    url = f"{base}/{vid}"
    try:
        r = requests.put(
            url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )
        if r.status_code in (200, 204):
            return True, None
        return False, f"detach status {r.status_code}: {r.text[:300]}"
    except requests.RequestException as exc:
        return False, str(exc)


def _is_staff_role(role):
    """Panel / reseller staff — no deviceId session rules on valide or auths/local."""
    return role in ("rootadmin", "admin", "reseller")


def _prior_tracked_device_id(user):
    row = Device.query.filter_by(user_id=user.id).first()
    return row.device_id if row else None


def _record_device_and_issue_session_token(user, device_id):
    """
    Persist current deviceId from valide. Issue a new client JWT sid unless the stored deviceId already
    matches (same device: refresh exp only). When there is no stored device yet (prior is None), we
    still issue a fresh sid so tokens from auths/local alone cannot share a session with this valide.
    Staff/other roles: new full JWT without device storage.
    Returns (token_str, None) or (None, error_message).
    """
    if _is_staff_role(user.role):
        return issue_client_jwt(user), None
    if not device_id:
        return None, "deviceId is required"
    prior = _prior_tracked_device_id(user)
    ok, err = record_current_device_for_user(user, device_id)
    if not ok:
        return None, err or "Could not record device"
    # Use != only (not "prior and ..."): prior None must rotate, else auths/local + valide on a second
    # device would refresh_client_jwt and leave both devices on the same sid.
    if prior != device_id:
        log_security_event(
            event_type="DEVICE_BIND",
            user_id=user.id,
            ip_address=request.remote_addr,
            details=(
                f"session: device changed {prior!r} -> {device_id!r}; new sid"
                if prior
                else f"session: first stored device {device_id!r}; new sid (orphan auths/local session ended)"
            ),
        )
        return issue_client_jwt(user), None
    return refresh_client_jwt(user), None


def _clear_devices_for_user(user):
    """Remove all Device rows for user (e.g. detachdevices / detachDevice)."""
    Device.query.filter_by(user_id=user.id).delete(synchronize_session=False)
    db.session.commit()
    db.session.expire(user, ["devices"])


def record_current_device_for_user(user, device_id):
    """
    Keep at most one Device row per user with the latest deviceId (from valide).
    Returns (ok, error_message_or_None).
    """
    if not device_id:
        return True, None
    try:
        Device.query.filter_by(user_id=user.id).delete(synchronize_session=False)
        db.session.add(Device(device_id=device_id, user_id=user.id))
        db.session.commit()
        db.session.expire(user, ["devices"])
        user.log_credit_transaction(
            action_type="DEVICE_BIND",
            credits_amount=0,
            performed_by="system",
            notes=f"Current device recorded: {device_id}",
            credits_before=user.credits,
        )
        return True, None
    except Exception as exc:
        db.session.rollback()
        return False, str(exc)


# JSON keys stripped before forwarding valide body upstream (our-only takeover flags).
_VALIDE_STRIP_FOR_UPSTREAM = frozenset({
    "confirmTakeover", "forceDeviceTakeover", "detachDevices", "detachDevicesFirst",
    "confirm_takeover", "force_device_takeover", "detach_devices", "takeoverDevice",
})


def _valide_client_confirms_device_takeover(data):
    """True when client retries valide after 403 device conflict (same flags upstream accepts)."""
    if not isinstance(data, dict):
        return False
    for k in _VALIDE_STRIP_FOR_UPSTREAM:
        v = data.get(k)
        if v is True or v == 1:
            return True
        if isinstance(v, str) and v.strip().lower() in ("true", "1", "yes"):
            return True
    return False


def _blank_device_id_fields_for_upstream_payload(obj):
    """
    Never send customer hardware ids to the upstream shared pool account: blank deviceId / device_id
    everywhere in a JSON tree (empty string).
    """
    if isinstance(obj, dict):
        for k, v in list(obj.items()):
            lk = k.lower().replace("-", "_") if isinstance(k, str) else ""
            if lk in ("deviceid", "device_id"):
                obj[k] = ""
            else:
                _blank_device_id_fields_for_upstream_payload(v)
    elif isinstance(obj, list):
        for item in obj:
            _blank_device_id_fields_for_upstream_payload(item)


def _upstream_proxy_outbound_body_bytes():
    """Body bytes for /api/* forward upstream; JSON is parsed, device ids blanked, re-encoded."""
    raw = request.get_data()
    if not raw:
        return raw
    ct = (request.content_type or "").lower()
    if "application/json" not in ct:
        return raw
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return raw
    _blank_device_id_fields_for_upstream_payload(payload)
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


# Copied from upstream valide JSON when we POST as the shared account (playback / DRM hints).
_VALIDE_PLAYBACK_KEYS_FROM_UPSTREAM = frozenset({
    "cbn", "cfv", "chak", "chsi", "csak", "ivit", "kidp",
})
_VALIDE_SETTING_MERGE_KEYS_FROM_UPSTREAM = frozenset({
    "appVersionCode", "appVersionName", "contentUrlBase", "tvUrlBase", "urlUpdate",
    "videoDefault", "videoDefaultProvider", "videoTutorialMobile", "videoTutorialTv",
    "videoTutorialMobileProvider", "videoTutorialTvProvider", "contentProvider",
    "episodeCovertDefault", "useChannelList", "linkReserved", "contentBackground",
    "alertMessages",
})


def _fetch_upstream_valide_playback_payload(original_client_data):
    """
    POST upstream /api/users/valide as the shared streaming user so the client receives real
    cbn/cfv/etc. Local valide still owns auth, credits, and last-seen deviceId — this is merge-only.
    """
    if not UPSTREAM_VALIDE_PLAYBACK_MERGE_ENABLED:
        return None
    shared_auth, err = get_shared_upstream_auth_payload()
    if err or not shared_auth:
        log_security_event(
            event_type="LOGIN_ERROR",
            ip_address=request.remote_addr,
            details=f"valide: skip upstream playback merge (no shared auth): {err}",
        )
        return None
    token = shared_auth.get("token")
    if not token:
        return None
    sn, sp, _ = _upstream_shared_credentials()
    if not sn or not sp:
        return None
    try:
        body = copy.deepcopy(original_client_data)
    except Exception:
        body = dict(original_client_data) if isinstance(original_client_data, dict) else {}
    if not isinstance(body, dict):
        return None
    body.pop("password", None)
    for k in _VALIDE_STRIP_FOR_UPSTREAM:
        body.pop(k, None)
    body["name"] = sn
    body["password"] = sp
    _blank_device_id_fields_for_upstream_payload(body)
    url = _upstream_valide_url()
    if not url:
        log_security_event(
            event_type="LOGIN_ERROR",
            ip_address=request.remote_addr,
            details="valide: skip upstream playback merge (UPSTREAM_API_BASE or UPSTREAM_VALIDE_URL empty)",
        )
        return None
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json; charset=UTF-8",
        "Accept-Encoding": "gzip, deflate",
    }
    ua = request.headers.get("User-Agent")
    if ua:
        headers["User-Agent"] = ua
    try:
        r = requests.post(url, json=body, headers=headers, timeout=30)
    except requests.RequestException as exc:
        log_security_event(
            event_type="LOGIN_ERROR",
            ip_address=request.remote_addr,
            details=f"valide: upstream playback POST failed: {exc}",
        )
        return None
    if r.status_code != 200:
        log_security_event(
            event_type="LOGIN_ERROR",
            ip_address=request.remote_addr,
            details=f"valide: upstream playback status {r.status_code}: {r.text[:280]}",
        )
        return None
    try:
        return r.json()
    except ValueError:
        return None


def _merge_upstream_valide_playback_into_response(response_payload, upstream_json):
    if not isinstance(upstream_json, dict):
        return
    for k in _VALIDE_PLAYBACK_KEYS_FROM_UPSTREAM:
        v = upstream_json.get(k)
        if v is not None and v != "":
            response_payload[k] = v
    us = upstream_json.get("setting")
    ls = response_payload.get("setting")
    if isinstance(us, dict) and isinstance(ls, dict):
        for k in _VALIDE_SETTING_MERGE_KEYS_FROM_UPSTREAM:
            if k not in us:
                continue
            v = us[k]
            if v in (None, ""):
                continue
            if k == "contentBackground" and isinstance(v, list) and len(v) == 0:
                continue
            if k == "alertMessages" and isinstance(v, list) and len(v) == 0:
                continue
            ls[k] = copy.deepcopy(v)
        response_payload["setting"] = ls
    elif isinstance(us, dict) and not isinstance(ls, dict):
        response_payload["setting"] = copy.deepcopy(us)


def _scrub_valide_setting_embedded_user_blobs(payload, local_user):
    """
    Upstream contentBackground items may embed user:{id,_id,userId} with the shared pool account.
    Only touches dicts under keys user/owner/author inside list items (not top-level content _id).
    """
    str_needles, int_needles = _collect_upstream_identity_scalar_needles()
    if local_user is None or (not str_needles and not int_needles):
        return
    setting = payload.get("setting")
    if not isinstance(setting, dict):
        return
    for arr_key in ("contentBackground", "alertMessages"):
        arr = setting.get(arr_key)
        if not isinstance(arr, list):
            continue
        for item in arr:
            if not isinstance(item, dict):
                continue
            for blob_key in ("user", "owner", "author"):
                b = item.get(blob_key)
                if not isinstance(b, dict):
                    continue
                for id_key in ("id", "_id", "userId", "user_id"):
                    if id_key not in b:
                        continue
                    b[id_key] = _rewrite_scalar_if_upstream_user_id(
                        b[id_key], local_user, str_needles, int_needles
                    )


def _enforce_valide_local_identity_fields(payload, user, username, local_display):
    """After upstream merge: root identity must never reflect the shared pool account."""
    payload["id"] = int(user.id)
    payload["name"] = username
    payload["fullName"] = local_display
    payload["creditAmount"] = user.credits_int
    payload["role"] = user.role
    payload["dateExpire"] = _user_subscription_date_expire_str(user)
