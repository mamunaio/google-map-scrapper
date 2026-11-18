"""
LeadHunter Studio — Dedicated RQ Background Worker Entrypoint.
Runs in a separate container/process using the same application Docker image as the web service.
Supports `--healthcheck` to verify Redis connectivity and live RQ worker heartbeat/registration
without requiring an HTTP server inside the worker container.
"""

import argparse
import logging
import os
import sys

from rq import SimpleWorker, Worker

from services.job_queue import (
    check_worker_health,
    get_job_queue,
    get_redis_connection,
    get_worker_heartbeat_max_age_seconds,
    get_worker_ttl_seconds,
)
from services.runtime_config import configure_logging, load_local_dotenv, validate_startup_config


def create_worker(conn=None, worker_ttl: int | None = None):
    """
    Builds an RQ Worker bound to the configured LeadHunter queue with a bounded `worker_ttl`
    consistent with `WORKER_HEARTBEAT_MAX_AGE_SECONDS` (preserving SimpleWorker on Windows
    and forking Worker on POSIX/Linux).
    """
    connection = conn if conn is not None else get_redis_connection()
    queue = get_job_queue(conn=connection)
    resolved_ttl = get_worker_ttl_seconds() if worker_ttl is None else int(worker_ttl)
    # Use forking Worker on POSIX/Linux (Docker/Render) and SimpleWorker on Windows local dev
    worker_cls = SimpleWorker if sys.platform == "win32" else Worker
    return worker_cls([queue], connection=connection, worker_ttl=resolved_ttl)


def run_worker_healthcheck(conn=None, now_utc=None) -> tuple[bool, dict]:
    """
    Verifies worker container health via Redis connectivity and explicit RQ worker state
    + heartbeat freshness validation.
    Returns `(is_healthy, health_details)`.
    """
    details = check_worker_health(conn=conn, now_utc=now_utc)
    is_healthy = bool(details.get("redis_ok") and details.get("ok"))
    return is_healthy, details


def main(argv=None):
    load_local_dotenv()
    parser = argparse.ArgumentParser(description="LeadHunter RQ Background Worker")
    parser.add_argument(
        "--healthcheck",
        action="store_true",
        help="Check Redis connectivity and active RQ worker heartbeat health, then exit 0 (healthy) or 1 (unhealthy).",
    )
    args = parser.parse_args(argv)

    if args.healthcheck:
        healthy, _details = run_worker_healthcheck()
        sys.exit(0 if healthy else 1)

    # Conservative default concurrency for worker containers unless explicitly overridden
    os.environ.setdefault("BROWSER_MAX_CONCURRENCY", "1")
    configure_logging()
    logger = logging.getLogger("leadhunter.worker")

    config_summary = validate_startup_config(
        require_api_key_in_prod=False,
        require_redis_in_prod=True,
    )
    worker_ttl = get_worker_ttl_seconds()
    max_hb_age = get_worker_heartbeat_max_age_seconds()
    logger.info(
        "Starting RQ worker (production=%s, browser_max_concurrency=%d, job_timeout=%ds, worker_ttl=%ds, max_heartbeat_age=%ds)",
        config_summary["production"],
        config_summary["browser_max_concurrency"],
        config_summary["job_timeout_seconds"],
        worker_ttl,
        max_hb_age,
    )

    worker = create_worker(worker_ttl=worker_ttl)
    worker.work(with_scheduler=True)


if __name__ == "__main__":
    main()
