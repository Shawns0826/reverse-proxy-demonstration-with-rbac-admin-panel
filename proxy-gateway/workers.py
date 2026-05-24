"""Background credit worker and startup hooks."""
import threading
import time
from datetime import datetime

from sqlalchemy import text, inspect

import config
from extensions import db
from models import User, init_db
from security import log_security_event
from routes import create_root_admin

credit_worker_running = False
credit_worker_thread = None

# Remove the worker management functions and make it completely automatic
def start_credit_worker(app):
    """Start the background credit consumption worker automatically"""
    global credit_worker_running, credit_worker_thread

    if credit_worker_running:
        return
    
    credit_worker_running = True
    credit_worker_thread = threading.Thread(target=lambda: credit_worker_loop(app), daemon=True)
    credit_worker_thread.start()
    print("Credit consumption worker started automatically")

def credit_worker_loop(app):
    """Background worker that consumes credits based on time elapsed"""
    global credit_worker_running
    
    while credit_worker_running:
        try:
            with app.app_context():
                # Process customers in batches of 100
                customers = User.query.filter(User.role == 'customer').limit(100).all()
                
                updated_count = 0
                for customer in customers:
                    if customer.credits_int <= 0:
                        continue
                    
                    # Initialize last_credit_consumption if not set
                    if not hasattr(customer, 'last_credit_consumption') or not customer.last_credit_consumption:
                        customer.last_credit_consumption = datetime.utcnow()
                        db.session.commit()
                        continue
                    
                    # Calculate time elapsed since last consumption
                    now = datetime.utcnow()
                    time_elapsed = now - customer.last_credit_consumption
                    days_elapsed = time_elapsed.days
                    
                    # If less than 30 days have passed, skip
                    if days_elapsed < 30:
                        continue
                    
                    # Consume 1 credit per 30 days
                    credits_to_consume = days_elapsed // 30  # Integer division
                    if credits_to_consume > 0:
                        before = customer.credits_int
                        customer.credits = max(0, before - credits_to_consume)
                        if customer.credits_int <= 0:
                            customer.last_credit_consumption = None
                        else:
                            customer.last_credit_consumption = now
                        
                        # Log the consumption
                        customer.log_credit_transaction(
                            action_type="CONSUME",
                            credits_amount=-credits_to_consume,
                            performed_by="system",
                            notes=f"Automatic consumption: {credits_to_consume} credit(s) for {days_elapsed} days",
                            credits_before=before
                        )
                        
                        updated_count += 1
                
                if updated_count > 0:
                    db.session.commit()
                    print(f"Credit worker: Updated {updated_count} customers")
                
        except Exception as e:
            print(f"Error in credit worker: {e}")
            # Use app context for logging
            with app.app_context():
                log_security_event(
                    event_type="WORKER_ERROR",
                    user_id=None,
                    ip_address="127.0.0.1",
                    details=f"Credit worker error: {str(e)}"
                )
        
        # Sleep for 1 hour (3600 seconds)
        time.sleep(3600)

def add_last_credit_consumption_column(app):
    """Manually add the last_credit_consumption column if it doesn't exist"""
    try:
        with app.app_context():
            column_names = {
                c["name"] for c in inspect(db.engine).get_columns("user")
            }
            if "last_credit_consumption" not in column_names:
                db.session.execute(
                    text(
                        'ALTER TABLE "user" ADD COLUMN last_credit_consumption TIMESTAMP'
                    )
                )
                db.session.commit()
                print("Added last_credit_consumption column to database")
            else:
                print("last_credit_consumption column already exists")
    except Exception as e:
        print(f"Error adding last_credit_consumption column: {e}")


def initialize_app(app):
    """Initialize the application and start background workers"""
    with app.app_context():
        init_db(app)
        create_root_admin()
        if config.FLASK_ENV == "production" and User.query.filter_by(role="rootadmin").first() is None:
            print(
                "WARNING: No root admin user. For first deploy set ROOTADMIN_BOOTSTRAP_PASSWORD "
                "(and optionally ROOTADMIN_BOOTSTRAP_USERNAME), redeploy once, log in and change password, "
                "then remove ROOTADMIN_BOOTSTRAP_PASSWORD. Or use POST /create-rootadmin with "
                "ROOTADMIN_CREATE_TOKEN and X-Bootstrap-Token."
            )
        add_last_credit_consumption_column(app)
        start_credit_worker(app)
