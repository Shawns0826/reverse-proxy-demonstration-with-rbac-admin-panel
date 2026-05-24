"""
Database Security Module
Implements secure database connection practices including SSL/TLS encryption,
connection pooling, and security monitoring.
"""

import os
import ssl
import logging
from urllib.parse import urlparse
from sqlalchemy import create_engine, event
from sqlalchemy.pool import QueuePool
from sqlalchemy.engine import Engine
from contextlib import contextmanager
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DatabaseSecurityManager:
    """Manages secure database connections and monitoring"""
    
    def __init__(self, database_url):
        self.database_url = database_url
        self.engine = None
        self.connection_stats = {
            'total_connections': 0,
            'active_connections': 0,
            'failed_connections': 0,
            'slow_queries': 0
        }
    
    def create_secure_engine(self):
        """Create a SQLAlchemy engine with security configurations"""
        try:
            # Parse the database URL
            parsed_url = urlparse(self.database_url)
            
            # Security configurations
            security_config = {
                # Connection pooling
                'poolclass': QueuePool,
                'pool_size': int(os.environ.get('DB_POOL_SIZE', 10)),
                'max_overflow': int(os.environ.get('DB_MAX_OVERFLOW', 20)),
                'pool_timeout': int(os.environ.get('DB_POOL_TIMEOUT', 30)),
                'pool_recycle': int(os.environ.get('DB_POOL_RECYCLE', 3600)),  # Recycle connections every hour
                'pool_pre_ping': True,  # Verify connections before use
                
                # SSL/TLS Configuration
                'connect_args': self._get_ssl_config(parsed_url),
                
                # Performance and security
                'echo': os.environ.get('FLASK_ENV') == 'development',  # Log SQL in development
                'echo_pool': os.environ.get('FLASK_ENV') == 'development',
            }
            
            # Create the engine
            self.engine = create_engine(self.database_url, **security_config)
            
            # Set up event listeners for monitoring
            self._setup_event_listeners()
            
            logger.info("✅ Secure database engine created successfully")
            logger.info(f"   Pool size: {security_config['pool_size']}")
            logger.info(f"   Max overflow: {security_config['max_overflow']}")
            logger.info(f"   SSL enabled: {bool(security_config['connect_args'].get('sslmode'))}")
            
            return self.engine
            
        except Exception as e:
            logger.error(f"❌ Failed to create secure database engine: {e}")
            raise
    
    def _get_ssl_config(self, parsed_url):
        """Configure SSL/TLS for database connection"""
        ssl_config = {}
        if parsed_url.scheme and parsed_url.scheme.startswith("sqlite"):
            return ssl_config

        # Check if we're connecting to a cloud database (Render, Heroku, etc.)
        is_cloud_db = any(domain in parsed_url.hostname for domain in [
            'render.com', 'heroku.com', 'aws.amazon.com', 'cloud.google.com'
        ]) if parsed_url.hostname else False
        
        # Check if we're in development mode
        is_development = os.environ.get('FLASK_ENV') == 'development'
        
        if is_cloud_db and not is_development:
            # Force SSL for cloud databases in production
            ssl_config['sslmode'] = 'require'
            logger.info("🔒 SSL/TLS encryption enabled (cloud database in production)")
        elif os.environ.get('DB_FORCE_SSL') == 'true':
            # Custom SSL mode from environment
            ssl_config['sslmode'] = os.environ.get('DB_SSL_MODE', 'require')
            logger.info(f"🔒 SSL/TLS mode: {ssl_config['sslmode']}")
        elif os.environ.get('DB_SSL_MODE'):
            # Custom SSL mode from environment
            ssl_config['sslmode'] = os.environ.get('DB_SSL_MODE')
            logger.info(f"🔒 SSL/TLS mode: {ssl_config['sslmode']}")
        else:
            # Default SSL configuration - prefer but don't require
            ssl_config['sslmode'] = 'prefer'  # Use SSL if available
            logger.info("🔒 SSL/TLS encryption preferred (not required)")
        
        # Additional SSL parameters for enhanced security
        if ssl_config.get('sslmode') in ['require', 'verify-ca', 'verify-full']:
            ssl_config.update({
                'sslcert': os.environ.get('DB_SSL_CERT'),
                'sslkey': os.environ.get('DB_SSL_KEY'),
                'sslrootcert': os.environ.get('DB_SSL_ROOT_CERT'),
            })
        
        return ssl_config
    
    def _setup_event_listeners(self):
        """Set up database event listeners for monitoring and security"""
        
        @event.listens_for(Engine, "connect")
        def receive_connect(dbapi_connection, connection_record):
            """Log successful connections"""
            self.connection_stats['total_connections'] += 1
            self.connection_stats['active_connections'] += 1

            if self.database_url.startswith("sqlite:"):
                logger.debug(
                    f"🔗 Database connection established (total: {self.connection_stats['total_connections']})"
                )
                return

            # Set connection-level security parameters (PostgreSQL)
            cursor = dbapi_connection.cursor()

            # Set application name for monitoring (only for our app)
            app_name = os.environ.get('APP_NAME', 'proxy-gateway')
            cursor.execute(f"SET application_name = '{app_name}'")

            # Don't set aggressive timeouts that interfere with pgAdmin
            # Only set statement timeout if explicitly configured
            statement_timeout = os.environ.get('DB_STATEMENT_TIMEOUT')
            if statement_timeout:
                cursor.execute(f"SET statement_timeout = {statement_timeout}")

            # Don't set idle session timeout as it interferes with pgAdmin
            # idle_timeout = os.environ.get('DB_IDLE_TIMEOUT', '60000')  # 60 seconds
            # cursor.execute(f"SET idle_in_transaction_session_timeout = {idle_timeout}")

            cursor.close()
            
            logger.debug(f"🔗 Database connection established (total: {self.connection_stats['total_connections']})")
        
        @event.listens_for(Engine, "close")
        def receive_close(dbapi_connection, connection_record):
            """Log disconnections"""
            self.connection_stats['active_connections'] = max(0, self.connection_stats['active_connections'] - 1)
            logger.debug(f"🔌 Database connection closed (active: {self.connection_stats['active_connections']})")
        
        @event.listens_for(Engine, "before_cursor_execute")
        def receive_before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            """Monitor query execution time"""
            context._query_start_time = time.time()
        
        @event.listens_for(Engine, "after_cursor_execute")
        def receive_after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            """Log slow queries and security events"""
            total_time = time.time() - context._query_start_time
            
            # Log slow queries (configurable threshold)
            slow_query_threshold = float(os.environ.get('DB_SLOW_QUERY_THRESHOLD', '1.0'))  # 1 second
            if total_time > slow_query_threshold:
                self.connection_stats['slow_queries'] += 1
                logger.warning(f"🐌 Slow query detected ({total_time:.2f}s): {statement[:100]}...")
            
            # Log potentially dangerous operations
            dangerous_keywords = ['DROP', 'DELETE', 'TRUNCATE', 'ALTER', 'GRANT', 'REVOKE']
            if any(keyword in statement.upper() for keyword in dangerous_keywords):
                logger.warning(f"⚠️  Dangerous operation detected: {statement[:100]}...")
    
    @contextmanager
    def get_secure_connection(self):
        """Context manager for secure database connections"""
        connection = None
        try:
            connection = self.engine.connect()
            yield connection
        except Exception as e:
            self.connection_stats['failed_connections'] += 1
            logger.error(f"❌ Database connection error: {e}")
            raise
        finally:
            if connection:
                connection.close()
    
    def test_connection_security(self):
        """Test database connection security settings"""
        try:
            with self.get_secure_connection() as conn:
                # Test SSL connection
                result = conn.execute("SHOW ssl")
                ssl_status = result.fetchone()[0]
                
                # Test connection parameters
                result = conn.execute("SHOW application_name")
                app_name = result.fetchone()[0]
                
                result = conn.execute("SHOW statement_timeout")
                statement_timeout = result.fetchone()[0]
                
                logger.info("🔍 Database Security Test Results:")
                logger.info(f"   SSL Status: {ssl_status}")
                logger.info(f"   Application Name: {app_name}")
                logger.info(f"   Statement Timeout: {statement_timeout}")
                
                return {
                    'ssl_enabled': ssl_status == 'on',
                    'app_name': app_name,
                    'statement_timeout': statement_timeout,
                    'connection_stats': self.connection_stats
                }
                
        except Exception as e:
            logger.error(f"❌ Security test failed: {e}")
            return None
    
    def get_connection_stats(self):
        """Get current connection statistics"""
        return self.connection_stats.copy()

# Global database security manager instance
db_security_manager = None

def initialize_database_security(database_url):
    """Initialize the database security manager"""
    global db_security_manager
    db_security_manager = DatabaseSecurityManager(database_url)
    return db_security_manager.create_secure_engine()

def get_database_security_manager():
    """Get the global database security manager"""
    return db_security_manager 