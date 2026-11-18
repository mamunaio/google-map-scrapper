"""
LeadHunter Studio — Dedicated RQ Background Worker Entrypoint.
Runs in a separate container/process using the same application Docker image as the web service.
"""

import logging
import os
import sys

from rq import SimpleWorker, Worker

from services.job_queue import get_job_queue, get_redis_connection
from services.runtime_config import configure_logging, validate_startup_config


def create_worker(conn=None):
    """Builds an RQ Worker bound to the configured LeadHunter queue."""
    connection = conn if conn is not None else get_redis_connection()
    queue = get_job_queue(conn=connection)
    # Use forking Worker on POSIX/Linux (Docker/Render) and SimpleWorker on Windows local dev
    worker_cls = SimpleWorker if sys.platform == "win32" else Worker
    return worker_cls([queue], connection=connection)


def main():
    # Conservative default concurrency for worker containers unless explicitly overridden
    os.environ.setdefault("BROWSER_MAX_CONCURRENCY", "1")
    configure_logging()
    logger = logging.getLogger("leadhunter.worker")

    config_summary = validate_startup_config(
        require_api_key_in_prod=False,
        require_redis_in_prod=True,
    )
    logger.info(
        "Starting RQ worker (production=%s, browser_max_concurrency=%d, job_timeout=%ds)",
        config_summary["production"],
        config_summary["browser_max_concurrency"],
        config_summary["job_timeout_seconds"],
    )

    worker = create_worker()
    worker.work(with_scheduler=True)


if __name__ == "__main__":
    main()
