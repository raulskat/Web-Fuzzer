import multiprocessing
import os

# Worker configuration
workers = multiprocessing.cpu_count() * 2 + 1
threads = 4
worker_class = 'gthread'
worker_connections = 1000
timeout = 30
keepalive = 2

# Logging configuration
accesslog = '-'  # stdout
errorlog = '-'   # stderr
loglevel = 'info'
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Bind configuration
bind = '0.0.0.0:5000'

# Server mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# SSL Configuration (if needed)
# keyfile = '/path/to/keyfile'
# certfile = '/path/to/certfile'

# Process naming
proc_name = 'web-fuzzer'

# Server hooks
def on_starting(server):
    """Called just before the master process is initialized."""
    pass

def on_reload(server):
    """Called before code is reloaded."""
    pass

def when_ready(server):
    """Called just after the server is started."""
    pass

def post_fork(server, worker):
    """Called just after a worker has been forked."""
    pass

