"""SQLAlchemy models and database bootstrap."""
from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

import config
from extensions import db
from security import SecurityUtils, log_security_event


class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(150), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# Define the User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Increased length for hashed passwords
    role = db.Column(db.String(20), nullable=False, default='customer')  # rootadmin, admin, reseller, customer
    parent_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Hierarchical relationship
    credits = db.Column(db.Integer, default=0)
    initial_credits = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    last_credit_consumption = db.Column(db.DateTime, nullable=True)  # Track when credits were last consumed
    # Rotated on detach/new login so old client JWTs stop.
    auth_session_id = db.Column(db.String(36), nullable=True)

    # Relationships
    devices = db.relationship('Device', backref='user', lazy=True, cascade='all, delete-orphan')
    credit_logs = db.relationship('CreditLog', backref='user', lazy=True, cascade='all, delete-orphan')
    
    # Self-referential relationship for hierarchy
    children = db.relationship('User', backref=db.backref('parent', remote_side=[id]))
    
    def set_password(self, password):
        """Set password with proper hashing"""
        # Validate password strength
        is_valid, error_message = SecurityUtils.validate_password(password)
        if not is_valid:
            raise ValueError(error_message)
        
        # Hash the password using Werkzeug's secure hashing
        self.password = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password against hash"""
        return check_password_hash(self.password, password)
    
    def update_password(self, new_password):
        """Update password with validation and logging"""
        try:
            old_password_hash = self.password
            self.set_password(new_password)
            
            # Log password change
            log_security_event(
                event_type="PASSWORD_CHANGE",
                user_id=self.id,
                details="Password updated successfully"
            )
            
            return True, "Password updated successfully"
        except ValueError as e:
            return False, str(e)
        except Exception as e:
            # Revert on error
            self.password = old_password_hash
            return False, f"Error updating password: {str(e)}"
    
    def can_manage_user(self, target_user):
        """Check if this user can manage the target user based on role hierarchy"""
        if self.role == 'rootadmin':
            return True  # Root admin can manage everyone
        elif self.role == 'admin':
            # Admin can manage resellers and customers under them (entire hierarchy)
            return self.is_in_hierarchy(target_user) and target_user.role in ['reseller', 'customer']
        elif self.role == 'reseller':
            # Reseller can manage resellers and customers under them (entire hierarchy)
            return self.is_in_hierarchy(target_user) and target_user.role in ['reseller', 'customer']
        return False
    
    def is_in_hierarchy(self, target_user):
        """Check if target_user is anywhere in the hierarchy under this user"""
        if target_user.id == self.id:
            return False  # Can't manage yourself
        
        # Check if target_user is a direct child
        if target_user.parent_id == self.id:
            return True
        
        # Check if target_user is anywhere in the hierarchy under this user
        # (recursively check all children)
        for child in self.children:
            if child.id == target_user.id:
                return True
            # Recursively check children of children
            if child.is_in_hierarchy(target_user):
                return True
        
        return False
    
    def can_create_role(self, role):
        """Check if this user can create users with the specified role"""
        if self.role == 'rootadmin':
            return role in ['admin', 'reseller', 'customer']
        elif self.role == 'admin':
            return role in ['reseller', 'customer']
        elif self.role == 'reseller':
            return role in ['reseller', 'customer']
        return False

    @property
    def credits_int(self):
        """Credits as int; NULL/None in DB is treated as 0 (avoids TypeError on comparisons)."""
        c = self.credits
        return 0 if c is None else c
    
    def has_active_credits(self):
        """Check if user has active credits"""
        return self.credits_int > 0
    
    def log_credit_transaction(self, action_type, credits_amount, performed_by="system", notes=None, credits_before=None):
        """Log credit transactions for audit trail"""
        try:
            if credits_before is None:
                credits_before = self.credits_int
            credits_after = self.credits_int
            
            credit_log = CreditLog(
                user_id=self.id,
                action_type=action_type,
                credits_amount=credits_amount,
                credits_before=credits_before,
                credits_after=credits_after,
                performed_by=performed_by,
                notes=notes
            )
            db.session.add(credit_log)
            db.session.commit()
            
            return True
        except Exception as e:
            print(f"Error logging credit transaction: {str(e)}")
            return False


def _sync_customer_billing_clock_after_credit_change(user: User, credits_before_int: int) -> None:
    """
    Customers only: if balance crosses from non-positive to positive, reset last_credit_consumption
    so time spent at 0 is not charged when credits are added. If balance is 0 or below, clear the
    clock so stale timestamps do not linger.
    """
    if user.role != "customer":
        return
    before = credits_before_int if credits_before_int is not None else 0
    after = user.credits_int
    if before <= 0 < after:
        user.last_credit_consumption = datetime.utcnow()
    elif after <= 0:
        user.last_credit_consumption = None


# Define the CreditLog model
class CreditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    action_type = db.Column(db.String(50), nullable=False)  # ADD, CONSUME, TRANSFER, etc.
    credits_amount = db.Column(db.Integer, nullable=False)  # Positive for add, negative for consume
    credits_before = db.Column(db.Integer, nullable=False)
    credits_after = db.Column(db.Integer, nullable=False)
    performed_by = db.Column(db.String(50), nullable=False)  # Username or "system"
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Define the SecurityAuditLog model
class SecurityAuditLog(db.Model):
    """Model for storing security audit events"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    event_type = db.Column(db.String(50), nullable=False)  # LOGIN_SUCCESS, LOGIN_FAILED, etc.
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=True)  # Can be null for failed logins
    ip_address = db.Column(db.String(45), nullable=False)  # IPv6 compatible
    user_agent = db.Column(db.String(500), nullable=True)
    details = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), default='INFO')  # INFO, WARNING, ERROR, CRITICAL
    
    # Relationship
    user = db.relationship('User', backref='security_logs')
    
    def __repr__(self):
        return f'<SecurityAuditLog {self.event_type} by {self.user_id} at {self.timestamp}>'



def init_db(app):
    try:
        with app.app_context():
            print("\nCreating database tables...")
            print(f"Using database: {config.database_url_log_summary(app.config['SQLALCHEMY_DATABASE_URI'])}")
            db.create_all()
            print("Database tables created successfully!")
    except Exception as e:
        print(f"Error creating database tables: {str(e)}")
        print(f"Error type: {type(e)}")
        print(f"Error details: {str(e)}")
        raise

