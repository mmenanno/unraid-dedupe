"""
Gunicorn configuration file for production deployment
"""

import multiprocessing
import os

# Configure paths from environment variables
DATA_DIR = os.environ.get('DATA_DIR', '/data')
LOGS_DIR = os.path.join(DATA_DIR, 'logs')

# Server socket
bind = "0.0.0.0:5000"
backlog = 2048

# Worker processes
workers = int(os.environ.get('GUNICORN_WORKERS', multiprocessing.cpu_count()))
worker_class = 'gthread'
threads = int(os.environ.get('GUNICORN_THREADS', 2))
worker_connections = 1000
timeout = int(os.environ.get('GUNICORN_TIMEOUT', 3600))
keepalive = 2

# Logging
accesslog = os.path.join(LOGS_DIR, 'access.log')
errorlog = os.path.join(LOGS_DIR, 'error.log')
loglevel = os.environ.get('LOG_LEVEL', 'info')
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Process naming
proc_name = 'unraid-dedupe'

# Server mechanics
daemon = False
pidfile = None
umask = 0o022
user = None
group = None
tmp_upload_dir = None

# SSL (if needed)
# keyfile = None
# certfile = None

