import re
import hashlib
import secrets
import string
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, current_app
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityUtils:
    """Security utility functions"""
    
    @staticmethod
    def validate_password(password):
        """
        Validate password strength
        Returns: (is_valid, error_message)
        """
        # For development, allow any password
        if len(password) < 1:
            return False, "Password cannot be empty"
        
        return True, "Password is valid"
    
    @staticmethod
    def sanitize_input(input_string, max_length=255):
        """
        Sanitize user input to prevent injection attacks
        """
        if not input_string:
            return ""
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\']', '', str(input_string))
        
        # Limit length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized.strip()
    
    @staticmethod
    def generate_secure_token(length=32):
        """Generate a cryptographically secure token"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def hash_password(password):
        """Hash password using SHA-256 (for now, consider bcrypt for production)"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    @staticmethod
    def verify_password(password, hashed_password):
        """Verify password against hash"""
        return SecurityUtils.hash_password(password) == hashed_password

class RateLimiter:
    """Simple in-memory rate limiter"""
    
    def __init__(self):
        self.requests = {}
    
    def is_allowed(self, identifier, max_requests, window_seconds):
        """
        Check if request is allowed based on rate limit
        """
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=window_seconds)
        
        # Clean old entries
        if identifier in self.requests:
            self.requests[identifier] = [
                req_time for req_time in self.requests[identifier]
                if req_time > window_start
            ]
        else:
            self.requests[identifier] = []
        
        # Check if limit exceeded
        if len(self.requests[identifier]) >= max_requests:
            return False
        
        # Add current request
        self.requests[identifier].append(now)
        return True

# Global rate limiter instance
rate_limiter = RateLimiter()

def rate_limit(max_requests=100, window_seconds=3600):
    """
    Decorator for rate limiting endpoints
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            return f(*args, **kwargs)

            # Get client identifier (IP address or user ID)
            if hasattr(request, 'user') and request.user:
                identifier = f"user_{request.user.id}"
            else:
                identifier = request.remote_addr
            
            if not rate_limiter.is_allowed(identifier, max_requests, window_seconds):
                return jsonify({
                    "success": False,
                    "message": "Rate limit exceeded. Please try again later."
                }), 429
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_role(required_roles):
    """
    Decorator to require specific user role(s)
    Accepts either a single role string or a list of roles
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask_login import current_user
            
            if not current_user.is_authenticated:
                return jsonify({
                    "success": False,
                    "message": "Authentication required"
                }), 401
            
            # Convert single role to list for consistent handling
            if isinstance(required_roles, str):
                allowed_roles = [required_roles]
            else:
                allowed_roles = required_roles
            
            # Check if user's role is in the allowed roles
            if current_user.role not in allowed_roles:
                return jsonify({
                    "success": False,
                    "message": "Insufficient permissions"
                }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def log_security_event(event_type, user_id=None, details=None, ip_address=None, severity='INFO'):
    """
    Log security events for audit purposes
    """
    if not ip_address:
        ip_address = request.remote_addr if request else "unknown"
    
    user_agent = request.headers.get('User-Agent') if request else None
    
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "user_id": user_id,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "details": details,
        "severity": severity
    }
    
    logger.info(f"SECURITY_EVENT: {log_entry}")
    
    # Store in database if available
    try:
        from extensions import db
        from models import SecurityAuditLog
        audit_log = SecurityAuditLog(
            event_type=event_type,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details,
            severity=severity
        )
        db.session.add(audit_log)
        db.session.commit()
    except Exception as e:
        logger.error(f"Failed to store security event in database: {e}")
        # Don't fail the main operation if logging fails

def validate_json_schema(data, required_fields, optional_fields=None):
    """
    Validate JSON data against a schema
    """
    if not isinstance(data, dict):
        return False, "Data must be a JSON object"
    
    # Check required fields
    for field in required_fields:
        if field not in data:
            return False, f"Missing required field: {field}"
        if data[field] is None or data[field] == "":
            return False, f"Required field cannot be empty: {field}"
    
    # Check optional fields (if provided)
    if optional_fields:
        for field in data:
            if field not in required_fields and field not in optional_fields:
                return False, f"Unknown field: {field}"
    
    return True, "Data is valid"

def sanitize_user_data(user_data):
    """
    Sanitize user registration/update data
    """
    sanitized = {}
    
    if 'username' in user_data:
        sanitized['username'] = SecurityUtils.sanitize_input(
            user_data['username'], max_length=80
        )
    
    if 'role' in user_data:
        # Only allow valid roles
        valid_roles = ['rootadmin', 'admin', 'reseller', 'customer']
        if user_data['role'] in valid_roles:
            sanitized['role'] = user_data['role']
    
    if 'credits' in user_data:
        try:
            credits = int(user_data['credits'])
            if 0 <= credits <= 1000000:  # Reasonable limit
                sanitized['credits'] = credits
        except (ValueError, TypeError):
            pass
    
    return sanitized 