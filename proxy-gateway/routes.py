"""Flask URL handlers (register with register_routes(app))."""
import copy
import hmac
import os
import uuid
from collections import defaultdict
from datetime import datetime, UTC, timedelta

from markupsafe import Markup, escape
from flask import (
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy import text
from sqlalchemy.orm import joinedload

import config
from extensions import db
from models import User, Device, CreditLog, _sync_customer_billing_clock_after_credit_change
from security import SecurityUtils, rate_limit, require_role, log_security_event
from integrations import (
    issue_client_jwt,
    refresh_client_jwt,
    invalidate_outstanding_client_sessions,
    get_expiration_info,
    trial_window_expired,
    _user_for_detachdevices_request,
    _client_jwt_user_from_request,
    json_api_error_utf8,
    CLIENT_DEVICE_SESSION_MESSAGE,
    PROXY_SESSION_ENDED_MESSAGE,
    TRIAL_EXPIRED_MESSAGE,
    get_shared_upstream_auth_payload,
    record_current_device_for_user,
    _fetch_upstream_valide_playback_payload,
    _merge_upstream_valide_playback_into_response,
    _scrub_valide_setting_embedded_user_blobs,
    _enforce_valide_local_identity_fields,
    _local_display_name,
    _redact_json_tokens,
    _valide_client_confirms_device_takeover,
    _clear_devices_for_user,
    _VALIDE_STRIP_FOR_UPSTREAM,
    _is_staff_role,
    _prior_tracked_device_id,
    _record_device_and_issue_session_token,
    _user_subscription_date_expire_str,
    _mask_upstream_user_ref_fields_in_json,
    _mask_upstream_strings_in_json,
)

# Default first-boot rootadmin password when ROOTADMIN_BOOTSTRAP_PASSWORD is unset (override in production via env).
_DEFAULT_ROOTADMIN_PASSWORD = "rootadmin123"


def create_root_admin():
    """
    Create the initial rootadmin when none exists, using ROOTADMIN_BOOTSTRAP_PASSWORD
    or the default above. Prefer setting ROOTADMIN_BOOTSTRAP_PASSWORD in production.

    In development, the bootstrap password (env or default) is re-applied to the rootadmin
    user on each startup so local login matches the current default. Set
    ROOTADMIN_BOOTSTRAP_PASSWORD in dev to keep a different password.
    """
    try:
        raw_pw = (config.ROOTADMIN_BOOTSTRAP_PASSWORD or _DEFAULT_ROOTADMIN_PASSWORD).strip()
        if not raw_pw:
            return None
        username = (config.ROOTADMIN_BOOTSTRAP_USERNAME or "rootadmin").strip() or "rootadmin"

        existing = User.query.filter_by(role="rootadmin").first()
        if existing:
            if config.FLASK_ENV == "development":
                try:
                    existing.set_password(raw_pw)
                    db.session.commit()
                except ValueError as ve:
                    print(f"Root admin dev password sync failed: {ve}")
            return existing

        by_name = User.query.filter_by(username=username).first()
        if by_name:
            if config.FLASK_ENV == "development" and by_name.role != "rootadmin":
                by_name.role = "rootadmin"
                by_name.credits = 999999
                try:
                    by_name.set_password(raw_pw)
                    db.session.commit()
                    print("Development: existing user promoted to rootadmin; password set from bootstrap default/env.")
                except ValueError as ve:
                    db.session.rollback()
                    print(f"Root admin bootstrap failed (password policy): {ve}")
                    return None
                return by_name
            print(f"Root admin bootstrap skipped: username {username!r} already taken")
            return None

        rootadmin = User(username=username, role="rootadmin", credits=999999)
        try:
            rootadmin.set_password(raw_pw)
        except ValueError as ve:
            print(f"Root admin bootstrap failed (password policy): {ve}")
            return None
        db.session.add(rootadmin)
        db.session.commit()
        print(
            "Root admin user created. Log in, then set ROOTADMIN_BOOTSTRAP_PASSWORD in production "
            "and consider changing the default password if you used the built-in default."
        )
        return rootadmin
    except Exception as e:
        db.session.rollback()
        print(f"Error creating rootadmin: {str(e)}")
        return None

# Web Panel Routes


def _descendant_user_ids(root_id: int) -> list:
    """All user IDs in the subtree under root_id (by parent_id links), not including root_id."""
    rows = db.session.query(User.id, User.parent_id).all()
    by_parent = defaultdict(list)
    for uid, pid in rows:
        if pid is not None:
            by_parent[pid].append(uid)
    out = []
    stack = list(by_parent.get(root_id, []))
    while stack:
        cid = stack.pop()
        out.append(cid)
        stack.extend(by_parent.get(cid, []))
    return out


def users_visible_in_panel(viewer: User) -> list:
    """
    Users the viewer may manage in the panel: full DB for rootadmin; for admin/reseller,
    all descendants in the parent_id tree that pass can_manage_user (fixes direct-children-only bug).
    """
    if viewer.role == "rootadmin":
        return (
            User.query.options(joinedload(User.parent))
            .order_by(User.username)
            .all()
        )
    desc_ids = _descendant_user_ids(viewer.id)
    if not desc_ids:
        return []
    candidates = (
        User.query.options(joinedload(User.parent))
        .filter(User.id.in_(desc_ids))
        .order_by(User.username)
        .all()
    )
    return [u for u in candidates if viewer.can_manage_user(u)]


def build_panel_tree_html(viewer: User) -> Markup:
    """
    Tree rooted at the viewer. For rootadmin, every account appears under you: valid parent links
    are preserved; users with no parent, missing parent, or parent not in the panel set are
    attached as your direct children so there is a single full tree with you at the top.
    """
    managed = users_visible_in_panel(viewer)
    by_id = {viewer.id: viewer}
    for u in managed:
        by_id[u.id] = u
    by_parent = defaultdict(list)
    is_rootadmin = viewer.role == "rootadmin"
    for u in managed:
        if u.id == viewer.id:
            continue
        pid = u.parent_id
        if pid is not None and pid in by_id and pid != u.id:
            by_parent[pid].append(u)
        elif is_rootadmin:
            by_parent[viewer.id].append(u)

    def walk(uid: int) -> str:
        u = by_id.get(uid)
        if u is None:
            return ""
        nm = escape(u.username)
        role = escape(str(u.role))
        inner = (
            f'<div class="tree-node"><span class="user">{nm} '
            f'<span class="role">({role})</span></span>'
        )
        kids = sorted(by_parent.get(uid, []), key=lambda c: c.username.lower())
        if kids:
            inner += '<div class="tree-children">'
            for c in kids:
                inner += walk(c.id)
            inner += "</div>"
        inner += "</div>"
        return inner

    return Markup(walk(viewer.id))


def register_routes(app):
    @app.route("/")
    def home():
        return "Welcome to the Home Page!"
    
    # Login endpoint
    @app.route('/login', methods=['GET', 'POST'])
    @rate_limit(max_requests=5, window_seconds=300)  # 5 attempts per 5 minutes
    def login():
        try:
            if request.method == 'POST':
                # Sanitize and validate input
                username = SecurityUtils.sanitize_input(request.form.get('username', ''))
                password = request.form.get('password', '')
    
                # Check if this is an API request (JSON)
                is_api_request = request.is_json or request.headers.get('Content-Type') == 'application/json'
                if is_api_request:
                    data = request.get_json(silent=True) or {}
                    username = SecurityUtils.sanitize_input(data.get('username', ''))
                    password = data.get('password', '')
    
                # Validate required fields
                if not username or not password:
                    log_security_event(
                        event_type="LOGIN_FAILED",
                        ip_address=request.remote_addr,
                        details="Missing username or password"
                    )
                    if is_api_request:
                        return jsonify({"success": False, "message": "Username and password are required"}), 400
                    else:
                        flash("Username and password are required", "error")
                        return redirect(url_for('login'))
    
                # Validate input length
                if len(username) > 80 or len(password) > 255:
                    log_security_event(
                        event_type="LOGIN_FAILED",
                        ip_address=request.remote_addr,
                        details="Input too long"
                    )
                    if is_api_request:
                        return jsonify({"success": False, "message": "Invalid input length"}), 400
                    else:
                        flash("Invalid input length", "error")
                        return redirect(url_for('login'))
    
                user = User.query.filter_by(username=username).first()
    
                if user and user.check_password(password):
                    if trial_window_expired(user):
                        log_security_event(
                            event_type="LOGIN_FAILED",
                            user_id=user.id,
                            ip_address=request.remote_addr,
                            details=f"Login denied: trial expired for {username}",
                        )
                        if is_api_request:
                            return jsonify({
                                "success": False,
                                "message": TRIAL_EXPIRED_MESSAGE,
                                "role": user.role,
                                "expires_at": get_expiration_info(user),
                            }), 403
                        flash(TRIAL_EXPIRED_MESSAGE, "error")
                        return redirect(url_for("login"))
    
                    # Customers (and other end-user roles) need credits to sign in; staff/reseller always can
                    if user.role not in ['rootadmin', 'admin', 'reseller'] and not user.has_active_credits():
                        log_security_event(
                            event_type="LOGIN_FAILED",
                            user_id=user.id,
                            ip_address=request.remote_addr,
                            details=f"Login denied: no credits for user {username}"
                        )
                        if is_api_request:
                            return jsonify({
                                "success": False,
                                "message": "No credits remaining. Contact your reseller to extend your subscription.",
                                "credits_remaining": user.credits,
                                "role": user.role,
                                "expires_at": get_expiration_info(user),
                            }), 403
                        else:
                            flash("No credits remaining. Contact your reseller to extend your subscription.", "error")
                            return redirect(url_for('login'))
    
                    try:
                        # Log successful login attempt
                        log_security_event(
                            event_type="LOGIN_SUCCESS",
                            user_id=user.id,
                            ip_address=request.remote_addr,
                            details=f"Login successful for user {username}"
                        )
    
                        # Update last_login for all users (credits are consumed by background worker)
                        user.last_login = datetime.utcnow()
                        db.session.commit()
    
                        # Login user with Flask-Login
                        login_user(user, remember=True)
    
                        # Return appropriate response based on request type
                        if is_api_request:
                            token_out = issue_client_jwt(user)
                            return jsonify({
                                "success": True,
                                "message": "Login successful",
                                "token": token_out,
                                "credits_remaining": user.credits,
                                "role": user.role,
                                "last_login": user.last_login.isoformat() if user.last_login else None,
                                "expires_at": get_expiration_info(user),
                            })
                        else:
                            # Redirect to panel for web form submissions
                            return redirect(url_for('panel_dashboard'))
    
                    except Exception as e:
                        print(f"Error during user login processing: {str(e)}")
                        log_security_event(
                            event_type="LOGIN_ERROR",
                            user_id=user.id if user else None,
                            ip_address=request.remote_addr,
                            details=f"Login processing error: {str(e)}"
                        )
                        db.session.rollback()
                        if is_api_request:
                            return jsonify({"success": False, "message": f"Error processing login: {str(e)}"}), 500
                        else:
                            flash(f"Error processing login: {str(e)}", "error")
                            return redirect(url_for('login'))
                else:
                    # Log failed login attempt
                    log_security_event(
                        event_type="LOGIN_FAILED",
                        ip_address=request.remote_addr,
                        details=f"Invalid credentials for username: {username}"
                    )
                    if is_api_request:
                        return jsonify({"success": False, "message": "Invalid username or password"}), 401
                    else:
                        flash("Invalid username or password", "error")
                        return redirect(url_for('login'))
    
            # For GET requests, return the login page
            return render_template('login.html')
    
        except Exception as e:
            print(f"Unexpected error in login endpoint: {str(e)}")
            log_security_event(
                event_type="LOGIN_ERROR",
                ip_address=request.remote_addr,
                details=f"Unexpected login error: {str(e)}"
            )
            if request.is_json:
                return jsonify({"success": False, "message": f"Internal server error: {str(e)}"}), 500
            else:
                flash(f"Internal server error: {str(e)}", "error")
                return redirect(url_for('login'))
    
    @app.route('/api/auths/local', methods=['POST'])
    @rate_limit(max_requests=10, window_seconds=60)
    def local_auth_proxy():
        """
        Validate local credentials and return a client JWT. Shared upstream auth uses the same cache as
        the API proxy (get_shared_upstream_auth_payload). DeviceId and per-device session rules apply only
        on POST /api/users/valide; each successful local auth issues a fresh client JWT (new sid).
        """
        try:
            data = request.get_json(silent=True) or {}
            username = SecurityUtils.sanitize_input(data.get('name', ''))
            password = data.get('password', '')
    
            if not username or not password:
                return jsonify({"message": "name and password are required"}), 400
    
            user = User.query.filter_by(username=username).first()
            if not user or not user.check_password(password):
                log_security_event(
                    event_type="LOGIN_FAILED",
                    ip_address=request.remote_addr,
                    details=f"Proxy auth invalid credentials for username: {username}"
                )
                return jsonify({"message": "Invalid credentials"}), 401
    
            if trial_window_expired(user):
                return jsonify({"message": TRIAL_EXPIRED_MESSAGE}), 403
    
            if user.role not in ['rootadmin', 'admin', 'reseller'] and not user.has_active_credits():
                return jsonify({
                    "message": "No credits remaining. Contact your reseller to extend your subscription."
                }), 403
    
            upstream_payload, upstream_error = get_shared_upstream_auth_payload()
            if upstream_error or not upstream_payload:
                log_security_event(
                    event_type="LOGIN_ERROR",
                    user_id=user.id,
                    ip_address=request.remote_addr,
                    details=f"Proxy auth shared upstream: {upstream_error}",
                )
                return jsonify({
                    "message": "Upstream authentication unavailable",
                    "upstream_error": upstream_error or "unknown",
                }), 502
    
            return jsonify({
                "fullName": username.replace('_', ' '),
                "name": username,
                "role": upstream_payload.get("role", "app"),
                "token": issue_client_jwt(user),
            }), 200
        except Exception as e:
            log_security_event(
                event_type="LOGIN_ERROR",
                ip_address=request.remote_addr,
                details=f"Unexpected proxy auth error: {str(e)}"
            )
            return jsonify({"message": "Internal server error"}), 500
    
    @app.route('/api/users/valide', methods=['POST'])
    @rate_limit(max_requests=20, window_seconds=60)
    def users_valide_proxy():
        """
        Local validate: password + credits. All non-staff roles must send deviceId. If another deviceId is
        already stored, return HTTP 403 + Gson ApiError {code,message} with CLIENT_DEVICE_SESSION_MESSAGE
        (same substring the client uses for DeviceDetachDialog on upstream valide). Retries with confirmTakeover /
        forceDeviceTakeover / detachDevices / etc. proceed and rotate session like upstream. Staff: no
        deviceId; refresh_client_jwt. Optionally merges upstream valide playback (cbn/cfv/setting).
        """
        try:
            data = request.get_json(silent=True) or {}
            username = SecurityUtils.sanitize_input(data.get('name', ''))
            password = data.get('password', '')
    
            if not username or not password:
                return jsonify({"message": "name and password are required"}), 400
    
            user = User.query.filter_by(username=username).first()
            if not user or not user.check_password(password):
                log_security_event(
                    event_type="LOGIN_FAILED",
                    ip_address=request.remote_addr,
                    details=f"Valide proxy invalid credentials for username: {username}"
                )
                return jsonify({"message": "Invalid credentials"}), 401
    
            if trial_window_expired(user):
                return jsonify({"message": TRIAL_EXPIRED_MESSAGE}), 403
    
            if user.role not in ['rootadmin', 'admin', 'reseller'] and not user.has_active_credits():
                return jsonify({
                    "message": "No credits remaining. Contact your reseller to extend your subscription."
                }), 403
    
            device_id = SecurityUtils.sanitize_input(data.get("deviceId", "") or "")
            if not _is_staff_role(user.role) and not device_id:
                return jsonify({"message": "deviceId is required"}), 400
    
            if not _is_staff_role(user.role):
                prior = _prior_tracked_device_id(user)
                if prior and prior != device_id and not _valide_client_confirms_device_takeover(data):
                    log_security_event(
                        event_type="DEVICE_BIND",
                        user_id=user.id,
                        ip_address=request.remote_addr,
                        details=f"valide: 403 device conflict (stored {prior!r} != request {device_id!r})",
                    )
                    return json_api_error_utf8(403, CLIENT_DEVICE_SESSION_MESSAGE)
    
            try:
                response_payload = copy.deepcopy(data)
            except Exception:
                response_payload = dict(data)
            if not isinstance(response_payload, dict):
                return jsonify({"message": "Invalid request body"}), 400
            response_payload.pop("password", None)
            for k in _VALIDE_STRIP_FOR_UPSTREAM:
                response_payload.pop(k, None)
    
            local_display = _local_display_name(username)
            response_payload["name"] = username
            response_payload["fullName"] = local_display
            response_payload["creditAmount"] = user.credits_int
            response_payload["role"] = user.role
            response_payload["dateExpire"] = _user_subscription_date_expire_str(user)
            response_payload["id"] = user.id
            if device_id:
                response_payload["deviceId"] = device_id
    
            upstream_playback = _fetch_upstream_valide_playback_payload(data)
            if isinstance(upstream_playback, dict):
                _merge_upstream_valide_playback_into_response(response_payload, upstream_playback)
    
            for k in ("cbn", "cfv", "chak", "chsi", "csak", "ivit", "kidp"):
                response_payload.setdefault(k, "")
    
            _enforce_valide_local_identity_fields(response_payload, user, username, local_display)
            _scrub_valide_setting_embedded_user_blobs(response_payload, user)
            response_payload = _mask_upstream_user_ref_fields_in_json(response_payload, user)
            response_payload = _mask_upstream_strings_in_json(
                response_payload, username, local_display
            )
            if not _is_staff_role(user.role):
                tok, terr = _record_device_and_issue_session_token(user, device_id)
                if terr:
                    log_security_event(
                        event_type="DEVICE_BIND_FAILED",
                        user_id=user.id,
                        ip_address=request.remote_addr,
                        details=f"valide: {terr}",
                    )
                    status = 400 if terr == "deviceId is required" else 500
                    return jsonify({"message": terr}), status
                response_payload["token"] = tok
            else:
                response_payload["token"] = refresh_client_jwt(user)
    
            return jsonify(response_payload), 200
        except Exception as e:
            log_security_event(
                event_type="LOGIN_ERROR",
                ip_address=request.remote_addr,
                details=f"Unexpected users/valide proxy error: {str(e)}"
            )
            return jsonify({"message": "Internal server error"}), 500
    
    @app.route('/api/users/password', methods=['PUT'])
    @rate_limit(max_requests=10, window_seconds=300)
    def api_users_change_password():
        """
        Local-only: update the hashed password in our User table. Not proxied upstream;
        the Authorization header is irrelevant to this handler.
    
        Identify the account via JSON: name / username / userName, or deviceId (last valide device
        row), or (if exactly one user matches oldPassword) that single match; otherwise require
        name or deviceId when multiple accounts share the same current password.
        """
        try:
            data = request.get_json(silent=True) or {}
            old_pw = data.get('oldPassword')
            new_pw = data.get('newPassword')
    
            if data.get('permissionToAlter') is False:
                return jsonify({"code": 403, "message": "Operación no permitida"}), 403
    
            if old_pw is None or new_pw is None:
                return jsonify({"code": 400, "message": "Contraseña anterior y nueva requeridas"}), 400
    
            username = SecurityUtils.sanitize_input(
                data.get('name') or data.get('username') or data.get('userName') or ''
            )
            user = User.query.filter_by(username=username).first() if username else None
            if not user:
                did = SecurityUtils.sanitize_input(data.get('deviceId', '') or '')
                if did:
                    dev = Device.query.filter_by(device_id=did).first()
                    if dev:
                        user = db.session.get(User, dev.user_id)
    
            if user:
                if not user.check_password(old_pw):
                    log_security_event(
                        event_type="LOGIN_FAILED",
                        user_id=user.id,
                        ip_address=request.remote_addr,
                        details="Password change rejected: wrong current password",
                    )
                    return jsonify({"code": 422, "message": "La contraseña actual es incorrecta"}), 422
            else:
                matches = [u for u in User.query.all() if u.check_password(old_pw)]
                if len(matches) == 1:
                    user = matches[0]
                elif len(matches) == 0:
                    return jsonify({"code": 422, "message": "La contraseña actual es incorrecta"}), 422
                else:
                    return jsonify({
                        "code": 400,
                        "message": "Varias cuentas usan esa contraseña; incluya name o deviceId en el cuerpo",
                    }), 400
    
            ok, msg = user.update_password(new_pw)
            if not ok:
                return jsonify({"code": 400, "message": msg}), 400
    
            user.auth_session_id = str(uuid.uuid4())
            db.session.commit()
            log_security_event(
                event_type="PASSWORD_CHANGE",
                user_id=user.id,
                ip_address=request.remote_addr,
                details="Password changed via /api/users/password",
            )
            return jsonify({"message": "Contraseña actualizada"}), 200
        except Exception as e:
            db.session.rollback()
            log_security_event(
                event_type="LOGIN_ERROR",
                ip_address=request.remote_addr,
                details=f"/api/users/password error: {str(e)}",
            )
            return jsonify({"code": 500, "message": "Error interno del servidor"}), 500
    
    
    @app.route("/api/users/detachdevices", methods=["PUT"])
    @rate_limit(max_requests=20, window_seconds=60)
    def detach_devices_local():
        """
        Clear stored valide deviceId row(s) and end all outstanding client JWT sessions for this customer.
        No HTTP to upstream here (shared streaming token is obtained/refreshed only when proxying media).
    
        Auth: Bearer client JWT, or JSON body {"name","password"} (like valide) when
        the app has no valid token yet after a device-conflict 403.
        """
        try:
            user, err = _user_for_detachdevices_request()
            if err is not None:
                resp, code = err
                return resp, code
    
            if trial_window_expired(user):
                return jsonify({"message": TRIAL_EXPIRED_MESSAGE}), 403
    
            _clear_devices_for_user(user)
            invalidate_outstanding_client_sessions(user)
            log_security_event(
                event_type="DEVICE_BIND",
                user_id=user.id,
                ip_address=request.remote_addr,
                details="detachdevices: device row cleared + client sessions invalidated",
            )
            return jsonify({}), 200
        except Exception as e:
            log_security_event(
                event_type="LOGIN_ERROR",
                ip_address=request.remote_addr,
                details=f"Unexpected detachdevices error: {str(e)}",
            )
            return jsonify({"message": "Internal server error"}), 500
    
    
    @app.route('/api/users/detachDevice/<user_id>', methods=['PUT'])
    @rate_limit(max_requests=20, window_seconds=60)
    def detach_device_proxy(user_id):
        """
        Local-only: clear target user's stored device row(s); if target != caller, invalidate target sessions.
        Rotate caller JWT. The client uses this path after device conflict — no HTTP to upstream here.
        """
        try:
            g.proxy_client_user = None
            try:
                local_id = int(user_id)
            except ValueError:
                return jsonify({"message": "Invalid user id"}), 400
    
            pu, auth_err = _client_jwt_user_from_request(request.headers)
            if auth_err is not None:
                return auth_err
            g.proxy_client_user = pu
    
            staff = pu.role in ("rootadmin", "admin", "reseller")
            if not staff and local_id != pu.id:
                return jsonify({"message": "Forbidden"}), 403
            if staff and User.query.get(local_id) is None:
                return jsonify({"message": "User not found"}), 404
    
            target_user = User.query.get(local_id)
            if target_user is not None:
                _clear_devices_for_user(target_user)
                if target_user.id != pu.id:
                    invalidate_outstanding_client_sessions(target_user)
                log_security_event(
                    event_type="DEVICE_BIND",
                    user_id=local_id,
                    ip_address=request.remote_addr,
                    details="detachDevice: device row cleared; target sessions invalidated where applicable",
                )
    
            repl = issue_client_jwt(pu)
            return jsonify({"token": repl}), 200
        except Exception as e:
            log_security_event(
                event_type="LOGIN_ERROR",
                ip_address=request.remote_addr,
                details=f"Unexpected detachDevice proxy error: {str(e)}"
            )
            return jsonify({"message": "Internal server error"}), 500
    
    @app.route('/logout', methods=['GET', 'POST'])
    @login_required
    def logout():
        """Logout user and clear session"""
        try:
            # Log the logout event
            log_security_event(
                event_type="LOGOUT",
                user_id=current_user.id,
                ip_address=request.remote_addr,
                details=f"User {current_user.username} logged out"
            )
    
            logout_user()
    
            # Check if this is an API request
            if request.is_json or request.headers.get('Content-Type') == 'application/json':
                return jsonify({"success": True, "message": "Logged out successfully"})
            else:
                # Redirect to login page for web requests
                flash("You have been logged out successfully", "success")
                return redirect(url_for('login'))
    
        except Exception as e:
            log_security_event(
                event_type="LOGOUT_ERROR",
                user_id=current_user.id if current_user.is_authenticated else None,
                ip_address=request.remote_addr,
                details=f"Logout error: {str(e)}"
            )
            if request.is_json:
                return jsonify({"success": False, "message": "Error during logout"}), 500
            else:
                flash("Error during logout", "error")
                return redirect(url_for('login'))
    
    @app.route('/me', methods=['GET'])
    @login_required
    def get_current_user():
        """Get current logged in user info"""
        return jsonify({
            "success": True,
            "user": {
                "id": current_user.id,
                "username": current_user.username,
                "role": current_user.role,
                "credits": current_user.credits,
                "created_at": current_user.created_at.isoformat(),
                "last_login": current_user.last_login.isoformat() if current_user.last_login else None
            }
        })
    
    
    
    @app.route('/add-user', methods=['POST'])
    @login_required
    def add_user():
        try:
            # Handle malformed JSON gracefully
            try:
                data = request.get_json()
                if data is None:
                    return jsonify({"success": False, "message": "Invalid JSON format"}), 400
            except Exception as e:
                return jsonify({"success": False, "message": "Invalid JSON format"}), 400
    
            username = data.get('username')
            password = data.get('password')
            role = data.get('role', 'customer')  # Default to customer
            credits = data.get('credits', 0)  # Default to 0 credit if not specified
            if not username or not password:
                return jsonify({"success": False, "message": "Username and password are required"}), 400
    
            if User.query.filter_by(username=username).first():
                return jsonify({"success": False, "message": "Username already exists"}), 400
    
            # Check if current user can create the specified role
            if not current_user.can_create_role(role):
                return jsonify({"success": False, "message": f"You cannot create users with role '{role}'"}), 403
    
            # Check if current user has enough credits (except rootadmin and admin who have infinite credits)
            if current_user.role not in ['rootadmin', 'admin']:
                if current_user.credits_int < credits:
                    return jsonify({"success": False, "message": f"Insufficient credits. You have {current_user.credits_int} credits, need {credits}"}), 400
    
            # Store the current credits before modification for both users
            reseller_credits_before = current_user.credits_int if current_user.role not in ['rootadmin', 'admin'] else None
    
            # Create new user with credits
            new_user = User(
                username=username,
                password=password,
                role=role,
                credits=credits,
                parent_id=current_user.id if current_user.role != 'rootadmin' else None
            )
            new_user.set_password(password)
    
            # Initialize credits if provided
            if credits > 0:
                new_user.initial_credits = credits
    
            _sync_customer_billing_clock_after_credit_change(new_user, 0)
    
            # Deduct credits from the reseller (except rootadmin and admin)
            if current_user.role not in ['rootadmin', 'admin']:
                # Fetch the current user directly from database to ensure we have the latest data
                current_user_from_db = User.query.get(current_user.id)
                if not current_user_from_db:
                    return jsonify({"success": False, "message": "Current user not found in database"}), 500
    
                print(f"DEBUG: Before deduction - {current_user_from_db.username} has {current_user_from_db.credits_int} credits (role: {current_user_from_db.role})")
    
                current_user_from_db.credits = current_user_from_db.credits_int - credits
                print(f"DEBUG: After deduction - {current_user_from_db.username} now has {current_user_from_db.credits} credits")
    
            db.session.add(new_user)
            db.session.commit()
    
            # Log credit transaction AFTER user is committed (so user has an ID)
            if credits > 0:
                new_user.log_credit_transaction(
                    action_type="INITIAL_CREDITS",
                    credits_amount=credits,
                    performed_by=current_user.username,
                    notes="Initial credits assigned during account creation"
                )
    
                # Log the credit deduction for the reseller (except rootadmin)
                if current_user.role not in ['rootadmin', 'admin']:
                    current_user_from_db.log_credit_transaction(
                        action_type="TRANSFER",
                        credits_amount=-credits,
                        performed_by=current_user.username,
                        notes=f"Transferred {credits} credits to {new_user.username} during account creation",
                        credits_before=reseller_credits_before
                    )
                    print(f"DEBUG: Logged credit deduction for {current_user_from_db.username}")
                else:
                    print(f"DEBUG: Skipped credit deduction for {current_user.username} (role: {current_user.role})")
    
            # Log the user creation
            log_security_event(
                event_type="USER_CREATED",
                user_id=current_user.id,
                details=f"Created user {username} (role: {role}) with {credits} credits"
            )
    
            flash(f'User {username} created successfully', 'success')
            return redirect(url_for('panel_users'))
    
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating user: {str(e)}', 'error')
            return redirect(url_for('panel_add_user'))
    
    @app.route("/delete-user", methods=['POST'])
    @login_required
    def delete_user():
        try:
            # Handle malformed JSON gracefully
            try:
                data = request.get_json()
                if data is None:
                    return jsonify({"success": False, "message": "Invalid JSON format"}), 400
            except Exception as e:
                return jsonify({"success": False, "message": "Invalid JSON format"}), 400
    
            username = data.get('username')
    
            if not username:
                return jsonify({"success": False, "message": "Username is required"}), 400
    
            target_user = User.query.filter_by(username=username).first()
            if not target_user:
                return jsonify({"success": False, "message": "User not found"}), 404
    
            # Check if current user can manage the target user
            if not current_user.can_manage_user(target_user):
                return jsonify({"success": False, "message": f"You don't have permission to delete user '{username}'"}), 403
    
            # Prevent self-deletion
            if target_user.id == current_user.id:
                return jsonify({"success": False, "message": "You cannot delete your own account"}), 400
    
            # If deleting a reseller, move their customers up in the hierarchy
            if target_user.role == 'reseller':
                # Get all customers under the reseller being deleted
                customers_to_move = User.query.filter_by(parent_id=target_user.id).all()
                for customer in customers_to_move:
                    customer.parent_id = current_user.id  # Move to the deleting user
                    print(f"Moved customer {customer.username} from {target_user.username} to {current_user.username}")
    
            # Delete associated credit logs first
            CreditLog.query.filter_by(user_id=target_user.id).delete()
    
            # Delete the user
            db.session.delete(target_user)
            db.session.commit()
    
            return jsonify({
                "success": True, 
                "message": f"User {username} and all associated data deleted successfully",
                "deleted_by": current_user.username
            })
    
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": f"Error deleting user: {str(e)}"}), 500
    
    @app.route("/reset-password", methods=['POST'])
    @login_required
    def reset_password():
        try:
            data = request.get_json()
            username = data.get('username')
            new_password = data.get('new_password')
    
            if not username or not new_password:
                return jsonify({"success": False, "message": "Username and new password are required"}), 400
    
            user = User.query.filter_by(username=username).first()
            if not user:
                return jsonify({"success": False, "message": "User not found"}), 404
    
            if user.id == current_user.id:
                return jsonify({
                    "success": False,
                    "message": "Use the authenticated account password change flow for your own account",
                }), 400
            if not current_user.can_manage_user(user):
                return jsonify({"success": False, "message": "You don't have permission to reset this user's password"}), 403
    
            success, message = user.update_password(new_password)
    
            if success:
                db.session.commit()
                return jsonify({"success": True, "message": message}), 200
            else:
                return jsonify({"success": False, "message": message}), 400
        except Exception as e:
            return jsonify({"success": False, "message": f"Error resetting password: {str(e)}"}), 500
    
    @app.route("/list-users", methods=['GET'])
    @login_required
    @require_role(['rootadmin', 'admin'])
    def list_users():
        try:
            users = User.query.all()
            user_list = [{"username": user.username} for user in users]
            return jsonify({"success": True, "users": user_list}), 200
        except Exception as e:
            return jsonify({"success": False, "message": f"Error listing users: {str(e)}"}), 500
    
    @app.route("/renew-subscription", methods=['POST'])
    @login_required
    def renew_subscription():
        try:
            data = request.get_json()
            username = data.get('username')
            subscription_type = data.get('subscription_type', 'monthly')  # Default to monthly if not specified
    
            if not username:
                return jsonify({"success": False, "message": "Username is required"}), 400
    
            # Validate subscription type
            valid_subscriptions = ['weekly', 'monthly', 'yearly', 'test']
            if subscription_type not in valid_subscriptions:
                return jsonify({"success": False, "message": "Invalid subscription type"}), 400
    
            user = User.query.filter_by(username=username).first()
            if not user:
                return jsonify({"success": False, "message": "User not found"}), 404
    
            if not current_user.can_manage_user(user):
                return jsonify({"success": False, "message": "You don't have permission to renew this subscription"}), 403
    
            before = user.credits_int
            user.credits = 0
            user.initial_credits = 0
            _sync_customer_billing_clock_after_credit_change(user, before)
            user.role = subscription_type
            db.session.commit()
    
            return jsonify({
                "success": True, 
                "message": "Subscription renewed successfully",
                "role": user.role
            }), 200
        except Exception as e:
            return jsonify({"success": False, "message": f"Error renewing subscription: {str(e)}"}), 500
    
    @app.route('/extend-credits', methods=['POST'])
    @login_required
    def extend_credits():
        try:
            # Handle malformed JSON gracefully
            try:
                data = request.get_json()
                if data is None:
                    return jsonify({"success": False, "message": "Invalid JSON format"}), 400
            except Exception as e:
                return jsonify({"success": False, "message": "Invalid JSON format"}), 400
    
            username = data.get('username')
            credits_to_add = data.get('credits', 1)
    
            if not username or credits_to_add <= 0:
                return jsonify({"success": False, "message": "Username and positive credits amount are required"}), 400
    
            # Get the target user
            target_user = User.query.filter_by(username=username).first()
            if not target_user:
                return jsonify({"success": False, "message": "User not found"}), 404
    
            # Check if current user can manage the target user
            if not current_user.can_manage_user(target_user):
                return jsonify({"success": False, "message": "You don't have permission to extend credits for this user"}), 403
    
            # Check if current user has enough credits (except rootadmin and admin who have infinite credits)
            if current_user.role not in ['rootadmin', 'admin']:
                if current_user.credits_int < credits_to_add:
                    return jsonify({"success": False, "message": f"Insufficient credits. You have {current_user.credits_int} credits, need {credits_to_add}"}), 400
    
            # Store the current credits before modification for both users
            target_credits_before = target_user.credits_int
            reseller_credits_before = current_user.credits_int if current_user.role not in ['rootadmin', 'admin'] else None
    
            # Add credits to the target user
            target_user.credits = target_user.credits_int + credits_to_add
    
            # Also add to initial_credits for tracking total ever given
            target_user.initial_credits = (target_user.initial_credits or 0) + credits_to_add
    
            _sync_customer_billing_clock_after_credit_change(target_user, target_credits_before)
    
            # Deduct credits from the reseller (except rootadmin and admin)
            if current_user.role not in ['rootadmin', 'admin']:
                # Fetch the current user directly from database to ensure we have the latest data
                current_user_from_db = User.query.get(current_user.id)
                if not current_user_from_db:
                    return jsonify({"success": False, "message": "Current user not found in database"}), 500
    
                print(f"DEBUG: Before deduction - {current_user_from_db.username} has {current_user_from_db.credits_int} credits (role: {current_user_from_db.role})")
    
                if current_user_from_db.credits_int < credits_to_add:
                    return jsonify({"success": False, "message": f"Insufficient credits. You have {current_user_from_db.credits_int} credits, need {credits_to_add}"}), 400
    
                current_user_from_db.credits = current_user_from_db.credits_int - credits_to_add
                print(f"DEBUG: After deduction - {current_user_from_db.username} now has {current_user_from_db.credits} credits")
    
                # Store the final credits for the response
                final_reseller_credits = current_user_from_db.credits
            else:
                current_user_from_db = current_user
                final_reseller_credits = "infinite"
    
            # Commit the transaction
            db.session.commit()
            print(f"DEBUG: After commit - reseller credits: {final_reseller_credits}")
    
            # Verify the deduction actually happened by querying the database again
            if current_user.role not in ['rootadmin', 'admin']:
                verification_user = User.query.get(current_user.id)
                print(f"DEBUG: Verification - {verification_user.username} has {verification_user.credits} credits in database")
                if verification_user.credits != final_reseller_credits:
                    print(f"DEBUG: WARNING - Credits mismatch! Expected: {final_reseller_credits}, Actual: {verification_user.credits}")
    
            # Log the credit extension for the target user
            target_user.log_credit_transaction(
                action_type="EXTEND",
                credits_amount=credits_to_add,
                performed_by=current_user.username,
                notes=f"Extended by {credits_to_add} credits by {current_user.username} (total allocated: {target_user.initial_credits})",
                credits_before=target_credits_before
            )
    
            # Log the credit deduction for the reseller (except rootadmin)
            if current_user.role not in ['rootadmin', 'admin']:
                # Use the database object for logging to ensure consistency
                current_user_from_db.log_credit_transaction(
                    action_type="TRANSFER",
                    credits_amount=-credits_to_add,
                    performed_by=current_user.username,
                    notes=f"Transferred {credits_to_add} credits to {target_user.username}",
                    credits_before=reseller_credits_before
                )
                print(f"DEBUG: Logged credit deduction for {current_user_from_db.username}")
            else:
                print(f"DEBUG: Skipped credit deduction for {current_user.username} (role: {current_user.role})")
    
            return jsonify({
                "success": True, 
                "message": f"Added {credits_to_add} credits to {target_user.username} successfully",
                "target_user_credits": target_user.credits,
                "target_user_total_allocated": target_user.initial_credits,
                "reseller_credits_remaining": final_reseller_credits
            }), 200
    
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": f"Error extending credits: {str(e)}"}), 500
    
    @app.route('/create-trial-account', methods=['POST'])
    @rate_limit(max_requests=10, window_seconds=3600)
    def create_trial_account():
        """Create a trial account; access ends TRIAL_DURATION_HOURS (default 2) after creation."""
        if not config.allow_public_trial_signup():
            abort(404)
        try:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
    
            if not username or not password:
                return jsonify({"success": False, "message": "Username and password are required"})
    
            if User.query.filter_by(username=username).first():
                return jsonify({"success": False, "message": "Username already exists"})
    
            new_user = User(
                username=username,
                credits=1,
                initial_credits=1,
                role='trial',
            )
            try:
                new_user.set_password(password)
            except ValueError as ve:
                return jsonify({"success": False, "message": str(ve)}), 400
            db.session.add(new_user)
            db.session.commit()
    
            return jsonify({
                "success": True,
                "message": (
                    f"Trial account created successfully — active for "
                    f"{config.trial_duration_hours()} hour(s) from signup."
                ),
                "username": username,
                "role": "trial",
                "trial_hours": config.trial_duration_hours(),
            }), 201
        except Exception as e:
            return jsonify({"success": False, "message": f"Error creating trial account: {str(e)}"}), 500
    
    @app.route('/get-credit-logs/<username>', methods=['GET'])
    @login_required
    def get_credit_logs(username):
        """Get credit transaction history for a user"""
        try:
            user = User.query.filter_by(username=username).first()
            if not user:
                return jsonify({"success": False, "message": "User not found"})
    
            if user.id != current_user.id and not current_user.can_manage_user(user):
                return jsonify({"success": False, "message": "You don't have permission to view these logs"}), 403
    
            logs = []
            for log in user.credit_logs:
                logs.append({
                    "id": log.id,
                    "action_type": log.action_type,
                    "credits_amount": log.credits_amount,
                    "credits_before": log.credits_before,
                    "credits_after": log.credits_after,
                    "performed_by": log.performed_by,
                    "notes": log.notes,
                    "created_at": log.created_at.isoformat()
                })
    
            # Sort by most recent first
            logs.sort(key=lambda x: x['created_at'], reverse=True)
    
            return jsonify({
                "success": True,
                "username": username,
                "current_credits": user.credits,
                "total_logs": len(logs),
                "logs": logs
            })
    
        except Exception as e:
            return jsonify({"success": False, "message": f"Error getting credit logs: {str(e)}"})
    
    @app.route('/create-rootadmin', methods=['POST'])
    @rate_limit(max_requests=5, window_seconds=3600)
    def create_root_admin_endpoint():
        """
        Create the first rootadmin via JSON {username, password}. Production requires X-Bootstrap-Token
        matching ROOTADMIN_CREATE_TOKEN (long random secret). No default passwords.
        """
        try:
            if os.environ.get("FLASK_ENV") == "production":
                token = (config.ROOTADMIN_CREATE_TOKEN or "").strip()
                if not token:
                    return jsonify({
                        "success": False,
                        "message": "Disabled in production (set ROOTADMIN_CREATE_TOKEN for emergency use)",
                    }), 403
                supplied = (request.headers.get("X-Bootstrap-Token") or "").strip()
                if len(supplied) != len(token) or not hmac.compare_digest(
                    supplied.encode("utf-8"), token.encode("utf-8")
                ):
                    log_security_event(
                        event_type="LOGIN_FAILED",
                        ip_address=request.remote_addr,
                        details="create-rootadmin: invalid or missing X-Bootstrap-Token",
                    )
                    return jsonify({"success": False, "message": "Forbidden"}), 403
    
            data = request.get_json(silent=True) or {}
            username = SecurityUtils.sanitize_input((data.get("username") or "").strip())
            password = data.get("password")
            if not username or not password:
                return jsonify({
                    "success": False,
                    "message": "username and password are required",
                }), 400
    
            existing_rootadmin = User.query.filter_by(role="rootadmin").first()
            if existing_rootadmin:
                return jsonify({
                    "success": False,
                    "message": f"Root admin already exists: {existing_rootadmin.username}",
                }), 400
    
            if User.query.filter_by(username=username).first():
                return jsonify({"success": False, "message": "Username already taken"}), 400
    
            rootadmin = User(username=username, role="rootadmin", credits=999999)
            try:
                rootadmin.set_password(password)
            except ValueError as ve:
                return jsonify({"success": False, "message": str(ve)}), 400
    
            db.session.add(rootadmin)
            db.session.commit()
    
            return jsonify({
                "success": True,
                "message": f"Root admin '{username}' created successfully",
                "username": username,
                "role": "rootadmin",
                "credits": 999999,
            }), 201
    
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": f"Error creating root admin: {str(e)}"}), 500
    
    @app.route('/panel')
    @login_required
    @require_role(['rootadmin', 'admin', 'reseller'])
    def panel_dashboard():
        """Main dashboard for the web panel"""
        try:
            # Refresh current user data from database to ensure accurate credits display
            db.session.refresh(current_user)
    
            # Users in this panel user's subtree that they may manage (full hierarchy, not direct-only)
            managed_users = users_visible_in_panel(current_user)
            user_ids = [user.id for user in managed_users]
    
            # Get filtered statistics
            total_users = len(managed_users)
            active_users = User.query.filter(
                User.id.in_(user_ids),
                User.last_login >= datetime.utcnow() - timedelta(days=30)
            ).count() if user_ids else 0
    
            # Total credits should show the current user's own credits, not their customers'
            total_credits = current_user.credits
    
            # Get recent activity (last 10 credit transactions) for managed users only
            if user_ids:
                recent_activity_raw = db.session.query(
                    CreditLog, User.username
                ).join(User, CreditLog.user_id == User.id).filter(
                    CreditLog.user_id.in_(user_ids)
                ).order_by(
                    CreditLog.created_at.desc()
                ).limit(10).all()
            else:
                recent_activity_raw = []
    
            # Format the data for the template
            recent_activity = []
            for credit_log, username in recent_activity_raw:
                activity_item = {
                    'username': username,
                    'action_type': credit_log.action_type,
                    'notes': credit_log.notes or '',
                    'created_at': credit_log.created_at,
                    'credits_amount': credit_log.credits_amount
                }
                recent_activity.append(activity_item)
    
            stats = {
                'total_users': total_users,
                'active_users': active_users,
                'total_credits': total_credits
            }
    
            return render_template('panel/dashboard.html', stats=stats, recent_activity=recent_activity)
    
        except Exception as e:
            flash(f'Error loading dashboard: {str(e)}', 'error')
            return render_template('panel/dashboard.html', stats={}, recent_activity=[])
    
    @app.route('/panel/users')
    @login_required
    @require_role(['rootadmin', 'admin', 'reseller'])
    def panel_users():
        view_mode = request.args.get('view', 'list')
        users = users_visible_in_panel(current_user)
        tree_html = None
        if view_mode == 'tree':
            tree_html = build_panel_tree_html(current_user)
        return render_template(
            'panel/users.html',
            users=users,
            view_mode=view_mode,
            tree_html=tree_html,
        )
    
    @app.route('/panel/credits')
    @login_required
    @require_role(['rootadmin', 'admin', 'reseller'])
    def panel_credits():
        """Credit management page"""
        try:
            # Refresh current user data from database to ensure accurate credits display
            db.session.refresh(current_user)
    
            users = users_visible_in_panel(current_user)
            return render_template('panel/credits.html', users=users)
    
        except Exception as e:
            flash(f'Error loading credits page: {str(e)}', 'error')
            return render_template('panel/credits.html', users=[])
    
    @app.route('/panel/reports')
    @login_required
    @require_role(['rootadmin', 'admin', 'reseller'])
    def panel_reports():
        """Reports page with comprehensive analytics"""
        try:
            managed_users = users_visible_in_panel(current_user)
            user_ids = [user.id for user in managed_users]
    
            # Basic statistics
            total_users = len(managed_users)
            active_users = User.query.filter(
                User.id.in_(user_ids),
                User.last_login >= datetime.utcnow() - timedelta(days=30)
            ).count() if user_ids else 0
    
            if user_ids:
                total_credits = db.session.query(db.func.sum(User.credits)).filter(
                    User.id.in_(user_ids)
                ).scalar() or 0
            else:
                total_credits = 0
    
            # User growth data (last 30 days)
            user_growth_labels = []
            user_growth_data = []
            for i in range(30, -1, -1):
                date = datetime.utcnow() - timedelta(days=i)
                start_of_day = date.replace(hour=0, minute=0, second=0, microsecond=0)
                end_of_day = start_of_day + timedelta(days=1)
    
                if user_ids:
                    new_users = User.query.filter(
                        User.id.in_(user_ids),
                        User.created_at >= start_of_day,
                        User.created_at < end_of_day
                    ).count()
                else:
                    new_users = 0
    
                user_growth_labels.append(date.strftime('%m-%d'))
                user_growth_data.append(new_users)
    
            # Role distribution
            role_counts = {}
            for user in managed_users:
                role = user.role
                role_counts[role] = role_counts.get(role, 0) + 1
    
            role_labels = list(role_counts.keys())
            role_data = list(role_counts.values())
    
            # Credit activity (last 7 days)
            if user_ids:
                credit_activity_raw = db.session.query(
                    CreditLog.action_type,
                    db.func.count(CreditLog.id).label('count'),
                    db.func.sum(CreditLog.credits_amount).label('total_credits')
                ).filter(
                    CreditLog.user_id.in_(user_ids),
                    CreditLog.created_at >= datetime.utcnow() - timedelta(days=7)
                ).group_by(CreditLog.action_type).all()
            else:
                credit_activity_raw = []
    
            credit_activity = []
            for action_type, count, total_credits in credit_activity_raw:
                credit_activity.append({
                    'action_type': action_type,
                    'count': count,
                    'total_credits': total_credits or 0
                })
    
            # Recent activity (last 20 credit transactions)
            if user_ids:
                recent_activity_raw = db.session.query(
                    CreditLog, User.username
                ).join(User, CreditLog.user_id == User.id).filter(
                    CreditLog.user_id.in_(user_ids)
                ).order_by(
                    CreditLog.created_at.desc()
                ).limit(20).all()
            else:
                recent_activity_raw = []
    
            recent_activity = []
            for credit_log, username in recent_activity_raw:
                activity_item = {
                    'username': username,
                    'action_type': credit_log.action_type,
                    'notes': credit_log.notes or '',
                    'created_at': credit_log.created_at,
                    'credits_amount': credit_log.credits_amount
                }
                recent_activity.append(activity_item)
    
            stats = {
                'total_users': total_users,
                'active_users': active_users,
                'total_credits': total_credits
            }
    
            return render_template('panel/reports.html', 
                                 stats=stats, 
                                 recent_activity=recent_activity,
                                 user_growth_labels=user_growth_labels,
                                 user_growth_data=user_growth_data,
                                 role_labels=role_labels,
                                 role_data=role_data,
                                 credit_activity=credit_activity)
    
        except Exception as e:
            flash(f'Error loading reports: {str(e)}', 'error')
            return render_template('panel/reports.html', 
                                 stats={}, 
                                 recent_activity=[],
                                 user_growth_labels=[],
                                 user_growth_data=[],
                                 role_labels=[],
                                 role_data=[],
                                 credit_activity=[])
    
    @app.route('/panel/api/users/<username>', methods=['GET'])
    @login_required
    @require_role(['rootadmin', 'admin', 'reseller'])
    def panel_get_user(username):
        """Get user details for panel"""
        try:
            user = User.query.options(joinedload(User.parent)).filter_by(username=username).first()
            if not user:
                return jsonify({"success": False, "message": "User not found"}), 404
    
            # Check if current user can manage this user
            if not current_user.can_manage_user(user):
                return jsonify({"success": False, "message": "Insufficient permissions"}), 403
    
            # Get recent credit logs
            credit_logs = []
            for log in user.credit_logs.order_by(CreditLog.created_at.desc()).limit(10).all():
                credit_logs.append({
                    'action_type': log.action_type,
                    'credits_amount': log.credits_amount,
                    'credits_before': log.credits_before,
                    'credits_after': log.credits_after,
                    'performed_by': log.performed_by,
                    'notes': log.notes,
                    'created_at': log.created_at.isoformat() if log.created_at else None
                })
    
            user_data = {
                'id': user.id,
                'username': user.username,
                'role': user.role,
                'credits': user.credits,
                'initial_credits': user.initial_credits,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'last_credit_consumption': user.last_credit_consumption.isoformat() if user.last_credit_consumption else None,
                'parent_username': user.parent.username if user.parent else None,
                'credit_logs': credit_logs
            }
    
            return jsonify({"success": True, "user": user_data})
    
        except Exception as e:
            return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500
    
    @app.route('/panel/api/users/<username>', methods=['PUT'])
    @login_required
    @require_role(['rootadmin', 'admin', 'reseller'])
    def panel_update_user(username):
        """Update user details from panel"""
        try:
            user = User.query.options(joinedload(User.parent)).filter_by(username=username).first()
            if not user:
                return jsonify({"success": False, "message": "User not found"}), 404
    
            # Check if current user can manage this user
            if not current_user.can_manage_user(user):
                return jsonify({"success": False, "message": "Insufficient permissions"}), 403
    
            data = request.get_json()
            if not data:
                return jsonify({"success": False, "message": "No data provided"}), 400
    
            # Track changes for logging
            changes = []
    
            # Update credits if provided (only rootadmin and admin can edit credits)
            if 'credits' in data and current_user.role in ['rootadmin', 'admin']:
                old_credits_int = user.credits_int
                new_credits = int(data['credits'])
                if new_credits != old_credits_int:
                    user.credits = new_credits
                    changes.append(f"Credits: {old_credits_int} → {new_credits}")
                    _sync_customer_billing_clock_after_credit_change(user, old_credits_int)
    
                    # Log credit change
                    user.log_credit_transaction(
                        action_type="MANUAL_ADJUSTMENT",
                        credits_amount=new_credits - old_credits_int,
                        performed_by=current_user.username,
                        notes=f"Manual adjustment by {current_user.username}",
                        credits_before=old_credits_int
                    )
            elif 'credits' in data and current_user.role not in ['rootadmin', 'admin']:
                return jsonify({"success": False, "message": "Only administrators can edit user credits"}), 403
    
            # Update role if provided (only rootadmin can change roles)
            if 'role' in data and current_user.role == 'rootadmin':
                old_role = user.role
                new_role = data['role']
                if new_role != old_role and new_role in ['admin', 'reseller', 'customer']:
                    user.role = new_role
                    changes.append(f"Role: {old_role} → {new_role}")
    
            # Save changes
            if changes:
                db.session.commit()
    
                # Log the changes
                log_security_event(
                    event_type="USER_UPDATED",
                    user_id=current_user.id,
                    details=f"Updated user {username}: {', '.join(changes)}"
                )
    
                return jsonify({
                    "success": True, 
                    "message": f"User updated successfully: {', '.join(changes)}"
                })
            else:
                return jsonify({"success": True, "message": "No changes made"})
    
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500
    
    @app.route('/panel/api/users/<username>', methods=['DELETE'])
    @login_required
    @require_role(['rootadmin', 'admin', 'reseller'])
    def panel_delete_user_api(username):
        """Delete user from panel API"""
        try:
            user = User.query.options(joinedload(User.parent)).filter_by(username=username).first()
            if not user:
                return jsonify({"success": False, "message": "User not found"}), 404
    
            # Check if current user can manage this user
            if not current_user.can_manage_user(user):
                return jsonify({"success": False, "message": "Insufficient permissions"}), 403
    
            # Prevent deleting rootadmin unless current user is rootadmin
            if user.role == 'rootadmin' and current_user.role != 'rootadmin':
                return jsonify({"success": False, "message": "Cannot delete root admin user"}), 403
    
            # Prevent deleting yourself
            if user.id == current_user.id:
                return jsonify({"success": False, "message": "Cannot delete your own account"}), 403
    
            # Store user info for logging
            deleted_username = user.username
            deleted_role = user.role
    
            # Delete the user (cascade will handle related records)
            db.session.delete(user)
            db.session.commit()
    
            # Log the deletion
            log_security_event(
                event_type="USER_DELETED",
                user_id=current_user.id,
                details=f"Deleted user {deleted_username} (role: {deleted_role})"
            )
    
            flash(f'User {deleted_username} deleted successfully.', 'success')
            return redirect(url_for('panel_users'))
    
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500
    
    @app.route('/panel/add-user', methods=['GET', 'POST'])
    @login_required
    @require_role(['rootadmin', 'admin', 'reseller'])
    def panel_add_user():
        """Add user page (server-side)"""
        if request.method == 'POST':
            try:
                username = request.form.get('username', '').strip()
                password = request.form.get('password', '')
                role = request.form.get('role', 'customer')
                credits = int(request.form.get('credits', 0))
    
                # Validate input
                if not username or not password:
                    flash('Username and password are required', 'error')
                    return redirect(url_for('panel_add_user'))
    
                if len(username) > 80:
                    flash('Username too long', 'error')
                    return redirect(url_for('panel_add_user'))
    
                # Check if user can create this role
                if not current_user.can_create_role(role):
                    flash('Insufficient permissions to create this role', 'error')
                    return redirect(url_for('panel_add_user'))
    
                # Check if username already exists
                if User.query.filter_by(username=username).first():
                    flash('Username already exists', 'error')
                    return redirect(url_for('panel_add_user'))
    
                # Check if current user has enough credits (except rootadmin and admin who have infinite credits)
                if current_user.role not in ['rootadmin', 'admin']:
                    if current_user.credits_int < credits:
                        flash(f'Insufficient credits. You have {current_user.credits_int} credits, need {credits}', 'error')
                        return redirect(url_for('panel_add_user'))
    
                # Store the current credits before modification for both users
                reseller_credits_before = current_user.credits_int if current_user.role not in ['rootadmin', 'admin'] else None
    
                # Create new user
                new_user = User(
                    username=username,
                    role=role,
                    credits=credits,
                    parent_id=current_user.id if current_user.role != 'rootadmin' else None
                )
                new_user.set_password(password)
    
                # Initialize credits if provided
                if credits > 0:
                    new_user.initial_credits = credits
    
                _sync_customer_billing_clock_after_credit_change(new_user, 0)
    
                # Deduct credits from the reseller (except rootadmin and admin)
                if current_user.role not in ['rootadmin', 'admin']:
                    # Fetch the current user directly from database to ensure we have the latest data
                    current_user_from_db = User.query.get(current_user.id)
                    if not current_user_from_db:
                        flash('Current user not found in database', 'error')
                        return redirect(url_for('panel_add_user'))
    
                    print(f"DEBUG: Before deduction - {current_user_from_db.username} has {current_user_from_db.credits_int} credits (role: {current_user_from_db.role})")
    
                    current_user_from_db.credits = current_user_from_db.credits_int - credits
                    print(f"DEBUG: After deduction - {current_user_from_db.username} now has {current_user_from_db.credits} credits")
    
                db.session.add(new_user)
                db.session.commit()
    
                # Log credit transaction AFTER user is committed (so user has an ID)
                if credits > 0:
                    new_user.log_credit_transaction(
                        action_type="INITIAL_CREDITS",
                        credits_amount=credits,
                        performed_by=current_user.username,
                        notes="Initial credits assigned during account creation"
                    )
    
                    # Log the credit deduction for the reseller (except rootadmin)
                    if current_user.role not in ['rootadmin', 'admin']:
                        current_user_from_db.log_credit_transaction(
                            action_type="TRANSFER",
                            credits_amount=-credits,
                            performed_by=current_user.username,
                            notes=f"Transferred {credits} credits to {new_user.username} during account creation",
                            credits_before=reseller_credits_before
                        )
                        print(f"DEBUG: Logged credit deduction for {current_user_from_db.username}")
                    else:
                        print(f"DEBUG: Skipped credit deduction for {current_user.username} (role: {current_user.role})")
    
                # Log the user creation
                log_security_event(
                    event_type="USER_CREATED",
                    user_id=current_user.id,
                    details=f"Created user {username} (role: {role}) with {credits} credits"
                )
    
                flash(f'User {username} created successfully with {credits} credits', 'success')
                return redirect(url_for('panel_users'))
    
            except Exception as e:
                db.session.rollback()
                flash(f'Error creating user: {str(e)}', 'error')
                return redirect(url_for('panel_add_user'))
    
        return render_template('panel/add_user.html')
    
    @app.route('/panel/users/<username>/view')
    @login_required
    @require_role(['rootadmin', 'admin', 'reseller'])
    def panel_view_user(username):
        """View user details page (server-side)"""
        try:
            user = User.query.options(joinedload(User.parent)).filter_by(username=username).first()
            if not user:
                flash('User not found', 'error')
                return redirect(url_for('panel_users'))
    
            # Check if current user can view this user
            if not current_user.can_manage_user(user):
                flash('Insufficient permissions', 'error')
                return redirect(url_for('panel_users'))
    
            return render_template('panel/view_user.html', user=user)
    
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
            return redirect(url_for('panel_users'))
    
    @app.route('/panel/users/<username>/edit', methods=['GET', 'POST'])
    @login_required
    @require_role(['rootadmin', 'admin', 'reseller'])
    def panel_edit_user(username):
        """Edit user page (server-side)"""
        try:
            user = User.query.options(joinedload(User.parent)).filter_by(username=username).first()
            if not user:
                flash('User not found', 'error')
                return redirect(url_for('panel_users'))
    
            # Check if current user can manage this user
            if not current_user.can_manage_user(user):
                flash('Insufficient permissions', 'error')
                return redirect(url_for('panel_users'))
    
            if request.method == 'POST':
                changes = []
    
                # Update credits if provided (only rootadmin and admin can edit credits)
                if 'credits' in request.form and current_user.role in ['rootadmin', 'admin']:
                    old_credits_int = user.credits_int
                    new_credits = int(request.form['credits'])
                    if new_credits != old_credits_int:
                        user.credits = new_credits
                        changes.append(f"Credits: {old_credits_int} → {new_credits}")
                        _sync_customer_billing_clock_after_credit_change(user, old_credits_int)
    
                        # Log credit change
                        user.log_credit_transaction(
                            action_type="MANUAL_ADJUSTMENT",
                            credits_amount=new_credits - old_credits_int,
                            performed_by=current_user.username,
                            notes=f"Manual adjustment by {current_user.username}"
                        )
                elif 'credits' in request.form and current_user.role not in ['rootadmin', 'admin']:
                    flash('Only administrators can edit user credits', 'error')
                    return redirect(url_for('panel_users'))
    
                # Update role if provided (only rootadmin can change roles)
                if 'role' in request.form and current_user.role == 'rootadmin':
                    old_role = user.role
                    new_role = request.form['role']
                    if new_role != old_role and new_role in ['admin', 'reseller', 'customer']:
                        user.role = new_role
                        changes.append(f"Role: {old_role} → {new_role}")
    
                # Save changes
                if changes:
                    db.session.commit()
    
                    # Log the changes
                    log_security_event(
                        event_type="USER_UPDATED",
                        user_id=current_user.id,
                        details=f"Updated user {username}: {', '.join(changes)}"
                    )
    
                    flash(f'User updated successfully: {", ".join(changes)}', 'success')
                else:
                    flash('No changes made', 'info')
    
                return redirect(url_for('panel_users'))
    
            return render_template('panel/edit_user.html', user=user)
    
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
            return redirect(url_for('panel_users'))
    
    @app.route('/panel/users/<username>/delete', methods=['POST'])
    @login_required
    @require_role(['rootadmin', 'admin', 'reseller'])
    def panel_delete_user(username):
        """Delete user (server-side)"""
        try:
            user = User.query.options(joinedload(User.parent)).filter_by(username=username).first()
            if not user:
                flash('User not found', 'error')
                return redirect(url_for('panel_users'))
    
            # Check if current user can manage this user
            if not current_user.can_manage_user(user):
                flash('Insufficient permissions', 'error')
                return redirect(url_for('panel_users'))
    
            # Prevent deleting rootadmin unless current user is rootadmin
            if user.role == 'rootadmin' and current_user.role != 'rootadmin':
                flash('Cannot delete root admin user', 'error')
                return redirect(url_for('panel_users'))
    
            # Prevent deleting yourself
            if user.id == current_user.id:
                flash('Cannot delete your own account', 'error')
                return redirect(url_for('panel_users'))
    
            # Store user info for logging
            deleted_username = user.username
            deleted_role = user.role
    
            # Delete the user (cascade will handle related records)
            db.session.delete(user)
            db.session.commit()
    
            # Log the deletion
            log_security_event(
                event_type="USER_DELETED",
                user_id=current_user.id,
                details=f"Deleted user {deleted_username} (role: {deleted_role})"
            )
    
            flash(f'User {deleted_username} deleted successfully.', 'success')
            return redirect(url_for('panel_users'))
    
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'error')
            return redirect(url_for('panel_users'))
    
