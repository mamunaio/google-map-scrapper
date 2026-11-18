"""
LeadHunter Redis + RQ Job Queue Manager.
Handles job enqueueing, duplicate-job protection, bounded retries, timeouts,
retention TTLs, status polling, result retrieval, and Redis/worker health checks.
"""

import hashlib
import logging
import os
import threading
from datetime import datetime, timezone

import redis
from rq import Queue, Retry, Worker
from rq.exceptions import NoSuchJobError
from rq.job import Job

from services.job_tasks import execute_scrape_job
from services.runtime_config import get_bool_env, get_int_env, get_redis_url

logger = logging.getLogger("leadhunter.queue")

ACTIVE_JOB_STATUSES = {"queued", "started", "deferred", "scheduled"}


class QueueUnavailableError(RuntimeError):
    """Raised when Redis is unconfigured or unreachable."""


class WorkerUnavailableError(RuntimeError):
    """Raised when no active RQ worker is available and `REQUIRE_ACTIVE_WORKER=true`."""


class JobNotFoundError(KeyError):
    """Raised when a requested job ID does not exist or has expired."""


_conn_lock = threading.Lock()
_injected_connection = None
_cached_connection = None
_cached_connection_url = ""


def set_redis_connection(conn):
    """Injects a Redis connection (e.g., FakeRedis in unit/integration tests)."""
    global _injected_connection
    with _conn_lock:
        _injected_connection = conn


def get_redis_connection():
    """Returns an active Redis connection or raises `QueueUnavailableError`."""
    global _cached_connection, _cached_connection_url
    with _conn_lock:
        if _injected_connection is not None:
            return _injected_connection
        url = get_redis_url()
        if not url:
            raise QueueUnavailableError("Background job queue is not configured (REDIS_URL is unset).")
        if _cached_connection is not None and _cached_connection_url == url:
            return _cached_connection
        try:
            conn = redis.Redis.from_url(
                url,
                socket_connect_timeout=3,
                socket_timeout=5,
                health_check_interval=30,
            )
            _cached_connection = conn
            _cached_connection_url = url
            return conn
        except Exception as exc:
            raise QueueUnavailableError(f"Failed to create Redis connection: {exc}") from exc


def get_queue_name() -> str:
    return (os.getenv("RQ_QUEUE_NAME", "leadhunter") or "leadhunter").strip()


def get_job_queue(conn=None) -> Queue:
    connection = conn if conn is not None else get_redis_connection()
    default_timeout = get_int_env("JOB_TIMEOUT_SECONDS", 900, min_value=30, max_value=3600)
    return Queue(name=get_queue_name(), connection=connection, default_timeout=default_timeout)


def check_redis_health(conn=None) -> tuple[bool, str]:
    """Checks Redis reachability via PING without exposing credentials or URL."""
    try:
        connection = conn if conn is not None else get_redis_connection()
        if connection.ping():
            return True, "Redis reachable"
        return False, "Redis ping returned false"
    except QueueUnavailableError as exc:
        return False, str(exc)
    except Exception as exc:
        return False, f"Redis unavailable: {exc.__class__.__name__}"


def count_active_workers(conn=None) -> int:
    """Returns the number of registered active RQ workers listening on the configured queue."""
    try:
        connection = conn if conn is not None else get_redis_connection()
        q = get_job_queue(conn=connection)
        workers = Worker.all(queue=q)
        return len(workers)
    except Exception:
        return 0


def compute_job_dedup_key(
    url: str,
    scrape_type: str,
    max_results: int,
    business_name: str = "",
    decision_maker: str = "",
) -> str:
    """Computes a deterministic Redis key for active-job deduplication."""
    raw = f"{scrape_type.strip().lower()}|{url.strip()}|{int(max_results)}|{business_name.strip().lower()}|{decision_maker.strip().lower()}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
    return f"leadhunter:dedup:{digest}"


def _get_job_return_value(job: Job):
    """Uses RQ 3.x `return_value()` when available, falling back to `.result`."""
    if hasattr(job, "return_value"):
        try:
            return job.return_value()
        except Exception:
            return None
    return getattr(job, "result", None)


def _get_job_exc_text(job: Job) -> str:
    """Uses RQ 3.x `latest_result().exc_string` when available, falling back cleanly."""
    if hasattr(job, "latest_result"):
        try:
            latest = job.latest_result()
            if latest is not None and getattr(latest, "exc_string", None):
                return str(latest.exc_string)
        except Exception:
            pass
    raw_exc = getattr(job, "_exc_info", None)
    return str(raw_exc or "")


def _normalize_job_status(job: Job) -> tuple[str, str | None]:
    """
    Normalizes RQ job status strings and extracts a sanitized error summary.
    Detects `JobTimeoutException` / `AbandonedJobError` explicitly and maps them to `timed_out`.
    """
    raw_status = job.get_status(refresh=True)
    status_str = raw_status.value if hasattr(raw_status, "value") else str(raw_status or "unknown")
    status_str = status_str.lower()
    error_msg: str | None = None

    if status_str == "failed":
        exc_info = _get_job_exc_text(job).strip()
        if "JobTimeoutException" in exc_info or "AbandonedJobError" in exc_info:
            status_str = "timed_out"
            error_msg = "Background job exceeded the maximum execution timeout."
        else:
            error_msg = "Background job failed while processing target."
    elif status_str == "finished":
        result = _get_job_return_value(job)
        if isinstance(result, dict) and result.get("success") is False:
            error_msg = str(result.get("error") or "Job finished with no extractable data.")

    return status_str, error_msg


def _iso_or_none(dt) -> str | None:
    if dt is None:
        return None
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    return str(dt)


def enqueue_scrape_job(
    *,
    url: str,
    scrape_type: str,
    max_results: int = 20,
    business_name: str = "",
    decision_maker: str = "",
    conn=None,
    require_worker: bool | None = None,
) -> dict:
    """
    Submits a scrape/audit job to RQ with:
    - Redis reachability verification (`QueueUnavailableError` on failure)
    - Optional active worker verification (`WorkerUnavailableError` when required)
    - Duplicate-job prevention for matching active jobs (`deduplicated=True`)
    - Bounded retries (`JOB_MAX_RETRIES`, default 2, intervals [10s, 30s])
    - Job timeout (`JOB_TIMEOUT_SECONDS`, default 900s)
    - Result & failure TTL expiration (`JOB_RESULT_TTL_SECONDS`, `JOB_FAILURE_TTL_SECONDS`)
    """
    connection = conn if conn is not None else get_redis_connection()
    try:
        connection.ping()
    except Exception as exc:
        raise QueueUnavailableError("Background job broker (Redis) is currently unavailable.") from exc

    enforce_worker = require_worker if require_worker is not None else get_bool_env("REQUIRE_ACTIVE_WORKER", False)
    workers_online = count_active_workers(conn=connection)
    if enforce_worker and workers_online < 1:
        raise WorkerUnavailableError("No active background workers are currently available to process jobs.")

    dedup_key = compute_job_dedup_key(
        url=url,
        scrape_type=scrape_type,
        max_results=max_results,
        business_name=business_name,
        decision_maker=decision_maker,
    )

    # Duplicate-job check: return existing active job if identical job is queued/running
    try:
        existing_id_bytes = connection.get(dedup_key)
        if existing_id_bytes:
            existing_id = existing_id_bytes.decode("utf-8") if isinstance(existing_id_bytes, bytes) else str(existing_id_bytes)
            try:
                existing_job = Job.fetch(existing_id, connection=connection)
                existing_status, _ = _normalize_job_status(existing_job)
                if existing_status in ACTIVE_JOB_STATUSES:
                    logger.info("Deduplicated job request; returning active job_id=%s status=%s", existing_id, existing_status)
                    return {
                        "job_id": existing_job.id,
                        "status": existing_status,
                        "deduplicated": True,
                        "workers_online": workers_online,
                    }
            except NoSuchJobError:
                pass
    except Exception as exc:
        logger.debug("Dedup lookup warning: %s", exc)

    job_timeout = get_int_env("JOB_TIMEOUT_SECONDS", 900, min_value=30, max_value=3600)
    result_ttl = get_int_env("JOB_RESULT_TTL_SECONDS", 3600, min_value=60, max_value=86400)
    failure_ttl = get_int_env("JOB_FAILURE_TTL_SECONDS", 3600, min_value=60, max_value=86400)
    max_retries = get_int_env("JOB_MAX_RETRIES", 2, min_value=0, max_value=5)
    dedup_ttl = get_int_env("JOB_DEDUP_TTL_SECONDS", job_timeout, min_value=60, max_value=3600)

    retry_policy = Retry(max=max_retries, interval=[10, 30][:max_retries] or 10) if max_retries > 0 else None

    queue = get_job_queue(conn=connection)
    job = queue.enqueue(
        execute_scrape_job,
        kwargs={
            "url": url,
            "scrape_type": scrape_type,
            "max_results": max_results,
            "business_name": business_name,
            "decision_maker": decision_maker,
        },
        job_timeout=job_timeout,
        result_ttl=result_ttl,
        failure_ttl=failure_ttl,
        retry=retry_policy,
        meta={
            "stage": "queued",
            "progress_pct": 0,
            "processed_leads": 0,
            "total_leads": max_results if scrape_type == "maps" else 1,
            "message": "Queued for background processing",
            "scrape_type": scrape_type,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
    )

    try:
        connection.set(dedup_key, job.id, ex=dedup_ttl)
    except Exception as exc:
        logger.debug("Could not write dedup key for job %s: %s", job.id, exc)

    logger.info("Enqueued background job_id=%s type=%s max_results=%d", job.id, scrape_type, max_results)
    return {
        "job_id": job.id,
        "status": "queued",
        "deduplicated": False,
        "workers_online": workers_online,
    }


def get_job_status_payload(job_id: str, conn=None) -> dict:
    """Fetches normalized status & progress metadata for a job."""
    connection = conn if conn is not None else get_redis_connection()
    try:
        connection.ping()
    except Exception as exc:
        raise QueueUnavailableError("Background job broker (Redis) is currently unavailable.") from exc

    try:
        job = Job.fetch(job_id, connection=connection)
    except NoSuchJobError as exc:
        raise JobNotFoundError(f"Job '{job_id}' was not found or has expired.") from exc

    status_str, error_msg = _normalize_job_status(job)
    meta = dict(job.meta or {})
    progress = {
        "stage": meta.get("stage", status_str),
        "progress_pct": meta.get("progress_pct", 100 if status_str == "finished" else 0),
        "processed_leads": meta.get("processed_leads", 0),
        "total_leads": meta.get("total_leads", 0),
        "message": meta.get("message", ""),
        "updated_at": meta.get("updated_at"),
    }

    return {
        "success": True,
        "job_id": job.id,
        "status": status_str,
        "progress": progress,
        "created_at": _iso_or_none(job.created_at),
        "started_at": _iso_or_none(job.started_at),
        "ended_at": _iso_or_none(job.ended_at),
        "retries_left": getattr(job, "retries_left", None),
        "error": error_msg,
    }


def get_job_result_payload(job_id: str, conn=None) -> tuple[dict, int]:
    """
    Returns `(payload, http_status)` for `GET /api/jobs/{job_id}/result`:
    - `202` if job is still queued/started/deferred/scheduled
    - `200` if job finished successfully
    - `400`/`422`/`500` if job finished with business/security error, failed, or timed out
    """
    connection = conn if conn is not None else get_redis_connection()
    try:
        connection.ping()
    except Exception as exc:
        raise QueueUnavailableError("Background job broker (Redis) is currently unavailable.") from exc

    try:
        job = Job.fetch(job_id, connection=connection)
    except NoSuchJobError as exc:
        raise JobNotFoundError(f"Job '{job_id}' was not found or has expired.") from exc

    status_str, error_msg = _normalize_job_status(job)

    if status_str in ACTIVE_JOB_STATUSES:
        return (
            {
                "success": False,
                "job_id": job.id,
                "status": status_str,
                "error": "Job is still processing.",
            },
            202,
        )

    if status_str == "timed_out":
        return (
            {
                "success": False,
                "job_id": job.id,
                "status": "timed_out",
                "error": error_msg or "Background job exceeded execution timeout.",
                "leads": [],
                "count": 0,
                "data": None,
            },
            504,
        )

    if status_str != "finished":
        return (
            {
                "success": False,
                "job_id": job.id,
                "status": status_str,
                "error": error_msg or "Background job failed.",
                "leads": [],
                "count": 0,
                "data": None,
            },
            500,
        )

    result = _get_job_return_value(job)
    if not isinstance(result, dict):
        return (
            {
                "success": False,
                "job_id": job.id,
                "status": "failed",
                "error": "Job result is unavailable or expired.",
                "leads": [],
                "count": 0,
                "data": None,
            },
            500,
        )

    http_code = int(result.get("http_status", 200 if result.get("success") else 422))
    payload = {k: v for k, v in result.items() if k != "http_status"}
    payload["job_id"] = job.id
    payload["status"] = "finished"
    return payload, http_code
