"""
LeadHunter Redis + RQ Job Queue Manager.
Handles job enqueueing, duplicate-job protection, bounded retries, timeouts,
retention TTLs, status polling, result retrieval, and Redis/worker health checks.
"""

import hashlib
import logging
import os
import threading
import time
import uuid
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


class JobReservationConflictError(RuntimeError):
    """
    Retryable error raised when another caller owns an in-flight reservation that has not
    yet committed a confirmed job within the bounded wait window.
    """


class JobReservationOwnershipError(RuntimeError):
    """
    Raised when reservation ownership is lost before job commit/promotion can be confirmed.
    Prevents silently reporting success or overwriting another caller's reservation.
    """


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


def get_worker_heartbeat_max_age_seconds() -> int:
    """Maximum permitted age (seconds) for an RQ worker's `last_heartbeat` to be considered healthy."""
    return get_int_env("WORKER_HEARTBEAT_MAX_AGE_SECONDS", 120, min_value=10, max_value=3600)


def get_worker_ttl_seconds() -> int:
    """Bounded RQ worker registration TTL (seconds), aligned with heartbeat freshness policy."""
    default_ttl = get_worker_heartbeat_max_age_seconds()
    return get_int_env("WORKER_TTL_SECONDS", default_ttl, min_value=30, max_value=3600)


def count_active_workers(conn=None, now_utc: datetime | None = None) -> int:
    """Returns the number of genuinely healthy, active RQ workers listening on the configured queue."""
    health = check_worker_health(conn=conn, now_utc=now_utc)
    return int(health["online"])


def _is_worker_healthy(worker_obj, current_time_utc: datetime, max_age_seconds: int) -> bool:
    """
    Validates that a registered RQ worker is genuinely alive:
    - Readable non-dead worker state (fail-closed on exception)
    - Present, parseable `last_heartbeat` (fail-closed on missing or exception)
    - Heartbeat age within `max_age_seconds`
    """
    try:
        state = worker_obj.get_state()
    except Exception:
        return False

    if not state or str(state).strip().lower() == "dead":
        return False

    try:
        last_hb = worker_obj.last_heartbeat
    except Exception:
        return False

    if last_hb is None:
        return False

    if isinstance(last_hb, str):
        try:
            last_hb = datetime.fromisoformat(last_hb.replace("Z", "+00:00"))
        except ValueError:
            return False

    if not isinstance(last_hb, datetime):
        return False

    if last_hb.tzinfo is None:
        last_hb = last_hb.replace(tzinfo=timezone.utc)

    age_seconds = (current_time_utc - last_hb).total_seconds()
    return age_seconds <= max_age_seconds


def check_worker_health(conn=None, now_utc: datetime | None = None) -> dict:
    """
    Verifies background worker availability using Redis connectivity and explicit RQ worker
    state + heartbeat freshness validation (no HTTP server required on workers).
    Stale, dead, missing-heartbeat, or unreadable worker registrations are excluded.
    """
    try:
        connection = conn if conn is not None else get_redis_connection()
        if not connection.ping():
            return {
                "ok": False,
                "redis_ok": False,
                "online": 0,
                "detail": "Redis ping returned false",
            }
        q = get_job_queue(conn=connection)
        workers = Worker.all(queue=q)
        current_time = now_utc if now_utc is not None else datetime.now(timezone.utc)
        if current_time.tzinfo is None:
            current_time = current_time.replace(tzinfo=timezone.utc)
        max_age = get_worker_heartbeat_max_age_seconds()

        active_workers = [
            w for w in workers if _is_worker_healthy(w, current_time, max_age)
        ]
        online = len(active_workers)
        ignored = len(workers) - online

        if online >= 1:
            detail = f"{online} active RQ worker(s) registered"
            if ignored > 0:
                detail += f" ({ignored} stale/unhealthy ignored)"
        elif ignored > 0:
            detail = f"No active RQ workers registered ({ignored} stale/unhealthy ignored)"
        else:
            detail = "No active RQ workers registered"

        return {
            "ok": online >= 1,
            "redis_ok": True,
            "online": online,
            "detail": detail,
        }
    except QueueUnavailableError as exc:
        return {
            "ok": False,
            "redis_ok": False,
            "online": 0,
            "detail": str(exc),
        }
    except Exception as exc:
        return {
            "ok": False,
            "redis_ok": False,
            "online": 0,
            "detail": f"Worker health check failed: {exc.__class__.__name__}",
        }


RESERVING_PREFIX = "reserving:"

_COMPARE_AND_DELETE_LUA = """
if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('del', KEYS[1])
else
    return 0
end
"""

_COMPARE_AND_SWAP_LUA = """
if redis.call('get', KEYS[1]) == ARGV[1] then
    redis.call('set', KEYS[1], ARGV[2], 'EX', tonumber(ARGV[3]))
    return 1
else
    return 0
end
"""

_COMPARE_AND_EXTEND_LUA = """
if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('expire', KEYS[1], tonumber(ARGV[2]))
else
    return 0
end
"""


def _decode_redis_str(raw) -> str | None:
    if raw is None:
        return None
    if isinstance(raw, bytes):
        return raw.decode("utf-8")
    return str(raw)


def _is_lua_unsupported_error(exc: redis.ResponseError) -> bool:
    """Returns True only when a Redis emulator reports that Lua EVAL is unsupported."""
    msg = str(exc).lower()
    return "unknown command" in msg and "eval" in msg


def _compare_and_delete_key_strict(connection, key: str, expected_value: str) -> bool:
    """
    Atomically deletes `key` ONLY if its current value matches `expected_value`.

    Distinguishes all three outcomes:
    - True:  Redis completed the atomic delete and ownership matched.
    - False: Redis completed the atomic check and confirmed ownership did NOT match (key untouched).
    - Raises QueueUnavailableError: Redis failed, was unavailable, or WATCH retries were exhausted
      so the ownership/delete outcome could not be confirmed.
    """
    try:
        deleted = connection.eval(_COMPARE_AND_DELETE_LUA, 1, key, expected_value)
        return bool(int(deleted))
    except redis.ResponseError as exc:
        if not _is_lua_unsupported_error(exc):
            raise QueueUnavailableError(
                "Background job broker returned an error while releasing job reservation; please retry."
            ) from exc
    except Exception as exc:
        raise QueueUnavailableError(
            "Background job broker became unavailable while releasing job reservation; please retry."
        ) from exc

    # Atomic WATCH/MULTI/EXEC fallback for test emulators without Lua EVAL
    last_watch_exc: redis.WatchError | None = None
    for _ in range(10):
        try:
            with connection.pipeline() as pipe:
                pipe.watch(key)
                current_str = _decode_redis_str(pipe.get(key))
                if current_str != expected_value:
                    pipe.unwatch()
                    return False
                pipe.multi()
                pipe.delete(key)
                pipe.execute()
                return True
        except redis.WatchError as exc:
            last_watch_exc = exc
            continue
        except Exception as exc:
            raise QueueUnavailableError(
                "Background job broker became unavailable while releasing job reservation; please retry."
            ) from exc
    raise QueueUnavailableError(
        "Background job broker experienced repeated transaction conflicts while releasing job reservation; please retry."
    ) from last_watch_exc


def _compare_and_delete_key(connection, key: str, expected_value: str) -> bool:
    """Atomically deletes `key` ONLY if its current value matches `expected_value`."""
    try:
        return _compare_and_delete_key_strict(connection, key, expected_value)
    except Exception as exc:
        logger.debug("Error releasing key %s: %s", key, exc)
        return False


def _compare_and_swap_key_strict(
    connection, key: str, expected_value: str, new_value: str, ex: int
) -> bool:
    """
    Atomically replaces `key` with `new_value` (with TTL `ex`) ONLY if it still equals `expected_value`.

    Distinguishes all three outcomes:
    - True:  Redis completed the atomic CAS and ownership matched (key updated).
    - False: Redis completed the atomic check and confirmed ownership did NOT match (key untouched).
    - Raises QueueUnavailableError: Redis failed, was unavailable, or WATCH retries were exhausted
      so the ownership/CAS outcome could not be confirmed.
    """
    try:
        swapped = connection.eval(_COMPARE_AND_SWAP_LUA, 1, key, expected_value, new_value, str(int(ex)))
        return bool(int(swapped))
    except redis.ResponseError as exc:
        if not _is_lua_unsupported_error(exc):
            raise QueueUnavailableError(
                "Background job broker returned an error while confirming job reservation; please retry."
            ) from exc
    except Exception as exc:
        raise QueueUnavailableError(
            "Background job broker became unavailable while confirming job reservation; please retry."
        ) from exc

    # Atomic WATCH/MULTI/EXEC fallback for test emulators without Lua EVAL
    last_watch_exc: redis.WatchError | None = None
    for _ in range(10):
        try:
            with connection.pipeline() as pipe:
                pipe.watch(key)
                current_str = _decode_redis_str(pipe.get(key))
                if current_str != expected_value:
                    pipe.unwatch()
                    return False
                pipe.multi()
                pipe.set(key, new_value, ex=int(ex))
                pipe.execute()
                return True
        except redis.WatchError as exc:
            last_watch_exc = exc
            continue
        except Exception as exc:
            raise QueueUnavailableError(
                "Background job broker became unavailable while confirming job reservation; please retry."
            ) from exc
    raise QueueUnavailableError(
        "Background job broker experienced repeated transaction conflicts while confirming job reservation; please retry."
    ) from last_watch_exc


def _compare_and_swap_key(connection, key: str, expected_value: str, new_value: str, ex: int) -> bool:
    """Atomically replaces `key` with `new_value` (with TTL `ex`) ONLY if it still equals `expected_value`."""
    try:
        return _compare_and_swap_key_strict(connection, key, expected_value, new_value, ex)
    except Exception as exc:
        logger.debug("Error updating key %s: %s", key, exc)
        return False


def _compare_and_extend_key(connection, key: str, expected_value: str, ex: int) -> bool:
    """Atomically extends TTL on `key` ONLY if its current value still equals `expected_value`."""
    try:
        extended = connection.eval(_COMPARE_AND_EXTEND_LUA, 1, key, expected_value, str(int(ex)))
        return bool(int(extended))
    except redis.ResponseError as exc:
        if "unknown command" not in str(exc).lower() or "eval" not in str(exc).lower():
            logger.debug("Error extending key %s: %s", key, exc)
            return False
    except Exception as exc:
        logger.debug("Error extending key %s: %s", key, exc)
        return False

    # Atomic WATCH/MULTI/EXEC fallback for test emulators without Lua EVAL
    for _ in range(10):
        try:
            with connection.pipeline() as pipe:
                pipe.watch(key)
                current_str = _decode_redis_str(pipe.get(key))
                if current_str != expected_value:
                    pipe.unwatch()
                    return False
                pipe.multi()
                pipe.expire(key, int(ex))
                pipe.execute()
                return True
        except redis.WatchError:
            continue
        except Exception as exc:
            logger.debug("Fallback extend warning for key %s: %s", key, exc)
            return False
    return False


class _ReservationLeaseRenewer:
    """
    Background ownership-safe lease renewer that periodically extends `dedup_key` TTL
    while `queue.enqueue()` is executing. Never extends another owner's reservation;
    records `ownership_lost=True` if renewal detects lost ownership.
    """

    def __init__(self, connection, key: str, expected_value: str, ttl_seconds: int, renew_interval: float | None = None):
        self._connection = connection
        self._key = key
        self._expected_value = expected_value
        self._ttl_seconds = max(1, int(ttl_seconds))
        self._interval = (
            float(renew_interval)
            if renew_interval is not None
            else max(0.05, self._ttl_seconds / 3.0)
        )
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self.ownership_lost = False
        self.renew_count = 0

    def _run(self):
        while not self._stop_event.wait(self._interval):
            ok = _compare_and_extend_key(
                self._connection,
                self._key,
                self._expected_value,
                self._ttl_seconds,
            )
            if ok:
                self.renew_count += 1
            else:
                self.ownership_lost = True
                return

    def __enter__(self):
        self._thread = threading.Thread(target=self._run, daemon=True, name="dedup-lease-renewer")
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._stop_event.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=1.0)


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
    reservation_wait_seconds: float | None = None,
    reservation_ttl_seconds: int | None = None,
    lease_renew_interval_seconds: float | None = None,
) -> dict:
    """
    Submits a scrape/audit job to RQ with:
    - Redis reachability verification (`QueueUnavailableError` on failure)
    - Optional active worker verification (`WorkerUnavailableError` when required)
    - Atomic pre-generated job ID reservation (`SET NX EX`) + ownership-safe lease renewal
    - Strict confirmation guarantee: NEVER returns an unconfirmed in-flight Job ID; raises
      retryable `JobReservationConflictError` if bounded wait expires while another caller
      is still enqueueing, or `JobReservationOwnershipError` if ownership is lost before commit
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

    job_timeout = get_int_env("JOB_TIMEOUT_SECONDS", 900, min_value=30, max_value=3600)
    result_ttl = get_int_env("JOB_RESULT_TTL_SECONDS", 3600, min_value=60, max_value=86400)
    failure_ttl = get_int_env("JOB_FAILURE_TTL_SECONDS", 3600, min_value=60, max_value=86400)
    max_retries = get_int_env("JOB_MAX_RETRIES", 2, min_value=0, max_value=5)
    dedup_ttl = get_int_env("JOB_DEDUP_TTL_SECONDS", job_timeout, min_value=60, max_value=3600)
    reservation_ttl = (
        max(1, int(reservation_ttl_seconds))
        if reservation_ttl_seconds is not None
        else get_int_env("JOB_RESERVATION_TTL_SECONDS", 60, min_value=10, max_value=3600)
    )
    wait_timeout = (
        max(0.01, float(reservation_wait_seconds))
        if reservation_wait_seconds is not None
        else get_int_env("JOB_RESERVATION_WAIT_MS", 1500, min_value=10, max_value=10000) / 1000.0
    )

    retry_policy = Retry(max=max_retries, interval=[10, 30][:max_retries] or 10) if max_retries > 0 else None

    # Pre-generate the RQ job ID before enqueueing so `SET dedup_key <reservation> NX EX`
    # atomically claims ownership. Lease renewal maintains ownership during prolonged enqueues.
    reserved_job_id = str(uuid.uuid4())
    reservation_val = f"{RESERVING_PREFIX}{reserved_job_id}"

    acquired_reservation = False
    wait_deadline = time.monotonic() + wait_timeout
    for _attempt in range(30):
        if connection.set(dedup_key, reservation_val, nx=True, ex=reservation_ttl):
            acquired_reservation = True
            break

        existing_raw = _decode_redis_str(connection.get(dedup_key))
        if not existing_raw:
            # Key vanished between SET NX and GET; retry atomic reservation
            continue

        # Case 1: Another caller currently holds an in-flight reservation for this exact payload.
        # NEVER return an unconfirmed Job ID — wait boundedly for either:
        #   (a) owner commits -> transition to Case 2 (confirmed active job),
        #   (b) owner fails & releases -> retry atomic reservation and enqueue, or
        #   (c) wait deadline expires -> raise explicit retryable `JobReservationConflictError`.
        if existing_raw.startswith(RESERVING_PREFIX):
            promoted_value = None
            released = False
            while time.monotonic() < wait_deadline:
                latest_raw = _decode_redis_str(connection.get(dedup_key))
                if not latest_raw:
                    released = True
                    break
                if not latest_raw.startswith(RESERVING_PREFIX):
                    promoted_value = latest_raw
                    break
                time.sleep(0.015)

            if released:
                # Owner failed and released its reservation; loop to atomically claim it
                continue

            if promoted_value is None:
                # One final check at deadline boundary before returning retryable conflict
                final_raw = _decode_redis_str(connection.get(dedup_key))
                if not final_raw:
                    continue
                if not final_raw.startswith(RESERVING_PREFIX):
                    promoted_value = final_raw
                else:
                    logger.info(
                        "Bounded wait (%.2fs) expired while another job reservation is still in flight for key=%s",
                        wait_timeout,
                        dedup_key,
                    )
                    raise JobReservationConflictError(
                        "An identical job submission is currently in progress; please retry shortly."
                    )

            existing_raw = promoted_value

        # Case 2: Committed job ID stored in `dedup_key`
        existing_id = existing_raw
        try:
            existing_job = Job.fetch(existing_id, connection=connection)
            existing_status, _ = _normalize_job_status(existing_job)
            if existing_status in ACTIVE_JOB_STATUSES:
                logger.info(
                    "Deduplicated job request; returning confirmed active job_id=%s status=%s",
                    existing_id,
                    existing_status,
                )
                return {
                    "job_id": existing_job.id,
                    "status": existing_status,
                    "deduplicated": True,
                    "workers_online": workers_online,
                }
        except NoSuchJobError:
            pass

        # Previous committed job reached a terminal state or expired:
        # atomically replace ONLY if `dedup_key` still equals `existing_id` (never overwrite another caller)
        if _compare_and_swap_key(connection, dedup_key, existing_id, reservation_val, ex=reservation_ttl):
            acquired_reservation = True
            break

    if not acquired_reservation:
        raise JobReservationConflictError(
            "An identical job submission is currently in progress; please retry shortly."
        )

    queue = get_job_queue(conn=connection)
    job = None
    reconciled_status = "queued"
    with _ReservationLeaseRenewer(
        connection,
        dedup_key,
        reservation_val,
        ttl_seconds=reservation_ttl,
        renew_interval=lease_renew_interval_seconds,
    ) as renewer:
        # Confirm ownership immediately before enqueueing
        if _decode_redis_str(connection.get(dedup_key)) != reservation_val:
            logger.error("Lost reservation ownership before enqueue for job_id=%s", reserved_job_id)
            raise JobReservationOwnershipError(
                "Reservation ownership was lost before job submission; please retry."
            )

        try:
            job = queue.enqueue(
                execute_scrape_job,
                kwargs={
                    "url": url,
                    "scrape_type": scrape_type,
                    "max_results": max_results,
                    "business_name": business_name,
                    "decision_maker": decision_maker,
                },
                job_id=reserved_job_id,
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
        except Exception as enqueue_exc:
            # Ambiguous enqueue outcome: Redis may have persisted the job before a client timeout
            # or dropped response. Reconcile `reserved_job_id` before deciding whether to promote
            # or release the reservation.
            reconciled_job = None
            job_absent = False
            try:
                reconciled_job = Job.fetch(reserved_job_id, connection=connection)
            except NoSuchJobError:
                job_absent = True
            except Exception as reconcile_exc:
                # Redis unavailable during reconciliation: NEVER assume absence, NEVER delete reservation,
                # and NEVER return an unconfirmed Job ID.
                logger.error(
                    "Ambiguous enqueue outcome for job_id=%s; reconciliation failed (%s). "
                    "Preserving reservation for safe expiry/reconciliation.",
                    reserved_job_id,
                    reconcile_exc.__class__.__name__,
                )
                raise QueueUnavailableError(
                    "Background job broker became unavailable during enqueue reconciliation; please retry."
                ) from reconcile_exc

            if job_absent:
                # Confirmed absent in Redis: release ONLY our own reservation and re-raise original enqueue error
                try:
                    _compare_and_delete_key(connection, dedup_key, reservation_val)
                except Exception as cleanup_exc:
                    logger.warning(
                        "Failed to release reservation for absent job_id=%s (%s); leaving to TTL expiry.",
                        reserved_job_id,
                        cleanup_exc.__class__.__name__,
                    )
                raise

            # Job exists in Redis: inspect its actual status safely
            try:
                actual_status, _ = _normalize_job_status(reconciled_job)
            except Exception as status_exc:
                logger.error(
                    "Ambiguous enqueue outcome for job_id=%s; status inspection failed (%s). "
                    "Preserving reservation.",
                    reserved_job_id,
                    status_exc.__class__.__name__,
                )
                raise QueueUnavailableError(
                    "Background job broker became unavailable during enqueue reconciliation; please retry."
                ) from status_exc

            if actual_status in ACTIVE_JOB_STATUSES:
                logger.warning(
                    "Reconciled active RQ job_id=%s (status=%s) after ambiguous enqueue exception (%s).",
                    reserved_job_id,
                    actual_status,
                    enqueue_exc.__class__.__name__,
                )
                job = reconciled_job
                reconciled_status = actual_status
            else:
                # Job exists but has already reached a terminal state (finished/failed/timed_out/canceled).
                # Do NOT report it as an active deduplicated job and do NOT create a duplicate.
                # Atomically verify ownership and release ONLY our reservation; if ownership was lost,
                # raise JobReservationOwnershipError without touching another caller's key.
                if renewer.ownership_lost:
                    logger.error(
                        "Reconciled terminal job_id=%s (status=%s) after ambiguous enqueue, "
                        "and reservation ownership was lost.",
                        reserved_job_id,
                        actual_status,
                    )
                    raise JobReservationOwnershipError(
                        "Reservation ownership was lost while reconciling a terminal job."
                    ) from enqueue_exc

                try:
                    released = _compare_and_delete_key_strict(connection, dedup_key, reservation_val)
                except QueueUnavailableError:
                    logger.error(
                        "Ambiguous enqueue outcome for terminal job_id=%s; Redis unavailable during "
                        "reservation cleanup. Preserving reservation.",
                        reserved_job_id,
                    )
                    raise
                except Exception as release_exc:
                    logger.error(
                        "Ambiguous enqueue outcome for terminal job_id=%s; reservation cleanup failed (%s). "
                        "Preserving reservation.",
                        reserved_job_id,
                        release_exc.__class__.__name__,
                    )
                    raise QueueUnavailableError(
                        "Background job broker became unavailable during enqueue reconciliation; please retry."
                    ) from release_exc

                if not released:
                    logger.error(
                        "Reconciled terminal job_id=%s (status=%s) after ambiguous enqueue, "
                        "and reservation ownership was lost before cleanup.",
                        reserved_job_id,
                        actual_status,
                    )
                    raise JobReservationOwnershipError(
                        "Reservation ownership was lost while reconciling a terminal job."
                    ) from enqueue_exc

                logger.warning(
                    "Reconciled terminal job_id=%s (status=%s) after ambiguous enqueue; "
                    "released own reservation and surfacing enqueue error.",
                    reserved_job_id,
                    actual_status,
                )
                raise

    # Verify ownership was NOT lost during prolonged enqueue and atomically promote
    # `"reserving:<job_id>"` -> `"<job_id>"` with `dedup_ttl`.
    # Never silently report success if ownership was lost or promotion fails.
    if renewer.ownership_lost:
        logger.error("Reservation ownership was lost during enqueue for job_id=%s", job.id)
        raise JobReservationOwnershipError(
            "Reservation ownership was lost before job commit could be confirmed."
        )

    try:
        promoted = _compare_and_swap_key_strict(connection, dedup_key, reservation_val, job.id, ex=dedup_ttl)
    except QueueUnavailableError:
        logger.error(
            "Failed to promote reservation for job_id=%s because Redis is unavailable; preserving reservation.",
            job.id,
        )
        raise
    except Exception as promote_exc:
        logger.error(
            "Failed to promote reservation for job_id=%s due to Redis error (%s); preserving reservation.",
            job.id,
            promote_exc.__class__.__name__,
        )
        raise QueueUnavailableError(
            "Background job broker became unavailable while confirming job reservation; please retry."
        ) from promote_exc

    if not promoted:
        logger.error("Failed to promote reservation for job_id=%s: ownership lost before commit", job.id)
        raise JobReservationOwnershipError(
            "Reservation ownership was lost before job commit could be confirmed."
        )

    logger.info(
        "Enqueued background job_id=%s type=%s max_results=%d status=%s",
        job.id,
        scrape_type,
        max_results,
        reconciled_status,
    )
    return {
        "job_id": job.id,
        "status": reconciled_status,
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
