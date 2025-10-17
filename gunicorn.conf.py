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
# Use one worker per CPU core for optimal performance
# Can be overridden with GUNICORN_WORKERS environment variable
workers = int(os.environ.get('GUNICORN_WORKERS', multiprocessing.cpu_count()))
worker_class = 'gthread'
threads = int(os.environ.get('GUNICORN_THREADS', 2))
worker_connections = 1000
timeout = int(os.environ.get('GUNICORN_TIMEOUT', 3600))
keepalive = 2

# Logging
# Log to both files AND stdout/stderr (for Docker logs)
# '-' means stdout for errorlog, but we want both file and stdout
# We'll configure this with custom handlers below
accesslog = '-'  # stdout for Docker logs
errorlog = '-'   # stderr for Docker logs
loglevel = os.environ.get('LOG_LEVEL', 'info')
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Custom logging setup to write to BOTH files and stdout/stderr
def on_starting(server):
    """Called just before the master process is initialized."""
    import logging
    from logging.handlers import RotatingFileHandler

    # Set up error log to go to both file and stderr
    error_log = logging.getLogger('gunicorn.error')
    error_log.setLevel(logging.INFO)

    # File handler for error.log
    error_file_handler = RotatingFileHandler(
        os.path.join(LOGS_DIR, 'error.log'),
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    error_file_handler.setFormatter(logging.Formatter(
        '[%(asctime)s] [%(process)d] [%(levelname)s] %(message)s',
        '%Y-%m-%d %H:%M:%S %z'
    ))
    error_log.addHandler(error_file_handler)

    # Set up access log to go to both file and stdout
    access_log = logging.getLogger('gunicorn.access')
    access_log.setLevel(logging.INFO)

    # File handler for access.log
    access_file_handler = RotatingFileHandler(
        os.path.join(LOGS_DIR, 'access.log'),
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    access_file_handler.setFormatter(logging.Formatter('%(message)s'))
    access_log.addHandler(access_file_handler)

    logger = logging.getLogger('gunicorn.error')
    logger.info("=" * 60)
    logger.info("Unraid Deduplication Manager Starting")
    logger.info(f"Workers: {server.cfg.workers}")
    logger.info(f"Threads per worker: {server.cfg.threads}")
    logger.info(f"Listening on: {server.cfg.bind}")
    mode = os.environ.get('FLASK_DEBUG', 'False').lower()
    logger.info(f"Mode: {'development' if mode == 'true' else 'production'}")
    logger.info(f"Logs: Files + Docker stdout/stderr")
    logger.info("=" * 60)

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


