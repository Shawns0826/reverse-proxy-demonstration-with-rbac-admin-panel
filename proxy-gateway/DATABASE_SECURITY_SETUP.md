# Database Security Setup Guide

This guide explains how to configure database security for your Flask application.

## 🔒 Security Features Implemented

### 1. **SSL/TLS Encryption**
- All database connections are encrypted in transit
- Automatic SSL detection for cloud databases (Render, Heroku, AWS, GCP)
- Configurable SSL modes for different security requirements

### 2. **Connection Pooling**
- Reuses database connections for better performance
- Prevents connection leaks and resource exhaustion
- Configurable pool size and overflow limits

### 3. **Query Monitoring**
- Tracks slow queries and dangerous operations
- Monitors connection statistics
- Logs security-relevant database activities

### 4. **Connection Security**
- Statement timeouts to prevent long-running queries
- Idle session timeouts to close inactive connections
- Application name tracking for monitoring

## 🌍 Environment Variables

### Required Variables (Already Set)
```bash
DATABASE_URL=postgresql://DB_USER:DB_PASSWORD@db.host.example:5432/dbname
SECRET_KEY=<output of e.g. python -c "import secrets; print(secrets.token_hex(32))">
```

### Optional Security Variables

#### Connection Pooling
```bash
# Number of connections to keep in the pool (default: 10)
DB_POOL_SIZE=10

# Maximum number of connections that can be created beyond pool_size (default: 20)
DB_MAX_OVERFLOW=20

# How long to wait for a connection from the pool (default: 30 seconds)
DB_POOL_TIMEOUT=30

# How often to recycle connections (default: 3600 seconds = 1 hour)
DB_POOL_RECYCLE=3600
```

#### SSL/TLS Configuration
```bash
# SSL mode: prefer, require, verify-ca, verify-full (default: prefer)
DB_SSL_MODE=require

# Force SSL even for local databases (default: false)
DB_FORCE_SSL=true

# SSL certificate files (for verify-ca/verify-full modes)
DB_SSL_CERT=/path/to/client-cert.pem
DB_SSL_KEY=/path/to/client-key.pem
DB_SSL_ROOT_CERT=/path/to/ca-cert.pem
```

#### Query Monitoring
```bash
# Statement timeout in milliseconds (default: 30000 = 30 seconds)
DB_STATEMENT_TIMEOUT=30000

# Idle session timeout in milliseconds (default: 60000 = 60 seconds)
DB_IDLE_TIMEOUT=60000

# Slow query threshold in seconds (default: 1.0)
DB_SLOW_QUERY_THRESHOLD=1.0
```

#### Application Configuration
```bash
# Application name for database monitoring (default: proxy-gateway)
APP_NAME=proxy-gateway
```

## 🚀 Setting Up Environment Variables

### For Local Development
Create a `.env` file in your project root:
```bash
# Database Security
DB_POOL_SIZE=5
DB_MAX_OVERFLOW=10
DB_SSL_MODE=prefer
DB_STATEMENT_TIMEOUT=30000
DB_SLOW_QUERY_THRESHOLD=0.5
APP_NAME=proxy-gateway-dev
```

### For Production (Render)
Add these environment variables in your Render dashboard:

1. Go to your service in Render
2. Click on "Environment"
3. Add the following variables:

```bash
# Connection Pooling
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=30
DB_POOL_TIMEOUT=30
DB_POOL_RECYCLE=3600

# SSL/TLS (Required for cloud databases)
DB_SSL_MODE=require
DB_FORCE_SSL=true

# Query Monitoring
DB_STATEMENT_TIMEOUT=30000
DB_IDLE_TIMEOUT=60000
DB_SLOW_QUERY_THRESHOLD=2.0

# Application
APP_NAME=proxy-gateway-prod
```

## 🧪 Verifying Database Security

There is no public HTTP test endpoint for DB security. Verify in production by:

- Connecting with `psql` or your host’s SQL console using the same SSL settings as the app.
- Watching application logs for connection errors, slow-query warnings, and pool exhaustion.
- Using your provider’s DB metrics (connections, CPU, slow queries).

## 🔍 Monitoring and Logs

### Connection Statistics
The system automatically tracks:
- Total connections made
- Currently active connections
- Failed connection attempts
- Slow queries detected

### Security Events Logged
- SSL connection status
- Dangerous database operations (DROP, DELETE, ALTER, etc.)
- Connection timeouts
- Query performance issues

### Viewing Logs
Check your application logs for security events:
```bash
# Look for security-related log entries
grep -i "ssl\|security\|slow\|dangerous" your-app.log
```

## 🛡️ Security Best Practices

### 1. **Always Use SSL in Production**
```bash
DB_SSL_MODE=require
DB_FORCE_SSL=true
```

### 2. **Set Appropriate Timeouts**
```bash
# Prevent long-running queries
DB_STATEMENT_TIMEOUT=30000

# Close idle connections
DB_IDLE_TIMEOUT=60000
```

### 3. **Monitor Connection Pool**
```bash
# Adjust based on your traffic
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=30
```

### 4. **Track Slow Queries**
```bash
# Alert on queries taking more than 2 seconds
DB_SLOW_QUERY_THRESHOLD=2.0
```

## 🔧 Troubleshooting

### SSL Connection Issues
If you see SSL-related errors:
1. Verify `DB_SSL_MODE=require` is set
2. Check if your database supports SSL
3. For local development, try `DB_SSL_MODE=prefer`

### Connection Pool Issues
If you see connection pool errors:
1. Increase `DB_POOL_SIZE` and `DB_MAX_OVERFLOW`
2. Check for connection leaks in your code
3. Monitor connection statistics in your database provider’s dashboard and app logs

### Performance Issues
If queries are slow:
1. Check slow query logs
2. Adjust `DB_SLOW_QUERY_THRESHOLD`
3. Monitor connection pool usage

## 📊 Recommended Production Settings

For a production IPTV application with moderate traffic:

```bash
# Connection Pooling
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=30
DB_POOL_TIMEOUT=30
DB_POOL_RECYCLE=3600

# SSL/TLS
DB_SSL_MODE=require
DB_FORCE_SSL=true

# Query Monitoring
DB_STATEMENT_TIMEOUT=30000
DB_IDLE_TIMEOUT=60000
DB_SLOW_QUERY_THRESHOLD=2.0

# Application
APP_NAME=proxy-gateway-prod
```

## 🔄 Next Steps

After setting up database security:

1. **Verify connectivity and SSL** using a SQL client and the same `DATABASE_URL` / SSL env as production
2. **Monitor logs** for security events
3. **Set up alerts** for slow queries and connection issues
4. **Consider implementing** database user permissions (separate read/write users)
5. **Add database backup** and recovery procedures

Your database is now secured with encryption, connection pooling, and comprehensive monitoring! 🔒 