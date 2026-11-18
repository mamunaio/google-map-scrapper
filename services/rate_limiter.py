"""
LeadHunter Shared Rate Limiter Module.
Supports Redis-backed atomic sliding-window rate limiting across multiple web workers
and instances, with a clean thread-safe in-memory fallback (with stale-key eviction)
for local development and unit tests.
"""

import logging
import os
import threading
import time
import uuid
from collections import deque

from services.runtime_config import get_bool_env, get_int_env, get_redis_url, is_production_env

logger = logging.getLogger("leadhunter.ratelimit")


class SharedSlidingWindowRateLimiter:
    """
    Sliding-window per-client rate limiter.
    - When `REDIS_URL` is configured (or an explicit Redis client is provided), stores request
      timestamps in a Redis sorted set (`leadhunter:ratelimit:<client_key>`) so limits are
      shared consistently across all Gunicorn workers and containers.
    - When Redis is not configured (local dev / unit tests), falls back to a thread-safe
      in-memory sliding window with stale-key eviction.
    - If Redis is configured but temporarily unreachable, logs an error and either fails
      closed (`RATE_LIMIT_FAIL_CLOSED=true`) or falls back to local in-memory limiting.
    """

    def __init__(self, redis_client=None):
        self._lock = threading.Lock()
        self._hits: dict[str, deque[float]] = {}
        self._injected_redis = redis_client
        self._cached_redis = None
        self._cached_redis_url = ""

    def _get_limits(self) -> tuple[int, int]:
        max_req = get_int_env("RATE_LIMIT_MAX_REQUESTS", 30, min_value=1, max_value=10000)
        window_sec = get_int_env("RATE_LIMIT_WINDOW_SECONDS", 60, min_value=1, max_value=3600)
        return max_req, window_sec

    def _get_redis(self):
        if self._injected_redis is not None:
            return self._injected_redis
        url = get_redis_url()
        if not url:
            return None
        if self._cached_redis is not None and self._cached_redis_url == url:
            return self._cached_redis
        try:
            import redis
            self._cached_redis = redis.Redis.from_url(
                url,
                socket_connect_timeout=2,
                socket_timeout=2,
                decode_responses=False,
            )
            self._cached_redis_url = url
            return self._cached_redis
        except Exception as exc:
            logger.warning("Failed to initialize Redis rate-limiter client: %s", exc)
            return None

    def set_redis_client(self, client):
        """Injects a Redis client (useful for multi-worker tests with FakeRedis)."""
        with self._lock:
            self._injected_redis = client

    def _check_memory(self, client_key: str, max_req: int, window_sec: int) -> tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - window_sec
        with self._lock:
            bucket = self._hits.get(client_key)
            if bucket is None:
                bucket = deque()
                self._hits[client_key] = bucket
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= max_req:
                retry_after = max(1, int(window_sec - (now - bucket[0])) + 1)
                return False, retry_after
            bucket.append(now)

            # Periodic stale-key eviction to prevent unbounded memory growth
            if len(self._hits) > 1000:
                stale_keys = [k for k, dq in self._hits.items() if not dq or dq[-1] <= cutoff]
                for k in stale_keys:
                    self._hits.pop(k, None)
            return True, 0

    def _check_redis(self, r_client, client_key: str, max_req: int, window_sec: int) -> tuple[bool, int]:
        now = time.time()
        cutoff = now - window_sec
        key = f"leadhunter:ratelimit:{client_key}"
        member = f"{now:.6f}:{uuid.uuid4().hex[:8]}"

        pipe = r_client.pipeline(transaction=True)
        pipe.zremrangebyscore(key, 0, cutoff)
        pipe.zcard(key)
        pipe.zrange(key, 0, 0, withscores=True)
        _, current_count, oldest = pipe.execute()

        if current_count >= max_req:
            if oldest:
                oldest_ts = float(oldest[0][1])
                retry_after = max(1, int(window_sec - (now - oldest_ts)) + 1)
            else:
                retry_after = window_sec
            return False, retry_after

        pipe2 = r_client.pipeline(transaction=True)
        pipe2.zadd(key, {member: now})
        pipe2.expire(key, window_sec + 5)
        pipe2.execute()
        return True, 0

    def check(self, client_key: str) -> tuple[bool, int]:
        max_req, window_sec = self._get_limits()
        r_client = self._get_redis()
        if r_client is not None:
            try:
                return self._check_redis(r_client, client_key, max_req, window_sec)
            except Exception as exc:
                logger.warning("Redis rate limiter unavailable (%s); handling fallback.", exc)
                if get_bool_env("RATE_LIMIT_FAIL_CLOSED", False) and is_production_env():
                    return False, window_sec
        return self._check_memory(client_key, max_req, window_sec)

    def reset(self):
        with self._lock:
            self._hits.clear()
        r_client = self._get_redis()
        if r_client is not None and self._injected_redis is not None:
            try:
                for key in r_client.scan_iter("leadhunter:ratelimit:*"):
                    r_client.delete(key)
            except Exception:
                pass
