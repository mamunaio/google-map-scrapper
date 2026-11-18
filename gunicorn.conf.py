"""
LeadHunter Studio — Production Gunicorn Configuration.
Designed for Render / Docker web containers where long-running scraping executes
in isolated RQ worker processes rather than synchronous web workers.
"""

import os

from services.runtime_config import get_int_env, validate_startup_config

# Bind to platform-assigned PORT on all interfaces
_port = get_int_env("PORT", 5000, min_value=1, max_value=65535)
bind = f"0.0.0.0:{_port}"

# Conservative multi-worker + threaded configuration suitable for API/UI + export serving
workers = get_int_env("WEB_CONCURRENCY", 2, min_value=1, max_value=8)
threads = get_int_env("GUNICORN_THREADS", 4, min_value=1, max_value=16)
worker_class = "gthread"

# Web workers handle fast API/job-submission/polling/export requests (not multi-minute scrapes)
timeout = get_int_env("GUNICORN_TIMEOUT", 60, min_value=15, max_value=300)
graceful_timeout = get_int_env("GUNICORN_GRACEFUL_TIMEOUT", 30, min_value=10, max_value=120)
keepalive = get_int_env("GUNICORN_KEEPALIVE", 5, min_value=1, max_value=60)

# Recycle workers periodically to bound long-term memory growth
max_requests = get_int_env("GUNICORN_MAX_REQUESTS", 500, min_value=50, max_value=10000)
max_requests_jitter = get_int_env("GUNICORN_MAX_REQUESTS_JITTER", 50, min_value=0, max_value=500)

# Stream access & error logs to stdout/stderr for container log collectors
accesslog = "-"
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "info").strip().lower()
capture_output = False
preload_app = False


def on_starting(server):
    """Fail fast at Gunicorn master startup if required production configuration is invalid."""
    validate_startup_config(
        require_api_key_in_prod=True,
        require_redis_in_prod=True,
    )
