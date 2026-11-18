"""
LeadHunter Shared Rate Limiter Module.
Supports Redis-backed atomic sliding-window rate limiting across multiple web workers
and instances, with a clean thread-safe in-memory fallback (with stale-key eviction)
for local development and unit tests.

Production Fail-Closed Policy:
- In production (`is_production_env() == True`), `RATE_LIMIT_FAIL_CLOSED` defaults to `True`.
- If Redis is unavailable or misconfigured in production, requests fail closed (`allowed=False`)
  rather than silently downgrading to per-process in-memory rate limiting.
"""

import logging
import threading
import time
import uuid
from collections import deque

import redis

from services.runtime_config import get_bool_env, get_int_env, get_redis_url, is_production_env

logger = logging.getLogger("leadhunter.ratelimit")

# Single-step atomic Redis Lua script:
# 1. Prunes expired timestamps <= cutoff
# 2. Counts active requests in window
# 3. If >= max_req, refreshes TTL and returns {0, retry_after} without inserting
# 4. Otherwise inserts current request member, refreshes TTL, and returns {1, 0}
SLIDING_WINDOW_LUA_SCRIPT = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local cutoff = tonumber(ARGV[2])
local max_req = tonumber(ARGV[3])
local window_sec = tonumber(ARGV[4])
local member = ARGV[5]

redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
local current_count = redis.call('ZCARD', key)
if current_count >= max_req then
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local retry_after = window_sec
    if oldest and oldest[2] then
        local elapsed = now - tonumber(oldest[2])
        retry_after = math.max(1, math.floor(window_sec - elapsed) + 1)
    end
    redis.call('EXPIRE', key, window_sec + 5)
    return {0, retry_after}
end

redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, window_sec + 5)
return {1, 0}
"""


class SharedSlidingWindowRateLimiter:
    """
    Atomic sliding-window per-client rate limiter.
    - When `REDIS_URL` is configured (or an explicit Redis client is provided), executes
      the complete prune + count + conditional insert + expire atomically inside Redis
      via Lua script (falling back to atomic WATCH/MULTI/EXEC only if the Redis emulator
      does not support EVAL, such as FakeRedis without lupa).
    - In production, Redis unavailability or misconfiguration fails closed by default
      (`RATE_LIMIT_FAIL_CLOSED=true`) and never silently downgrades to per-process memory.
    - In local development and unit tests without Redis, uses a thread-safe in-memory
      sliding window with stale-key eviction.
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

    def _should_fail_closed(self) -> bool:
        return get_bool_env("RATE_LIMIT_FAIL_CLOSED", default=is_production_env())

    def _get_redis(self):
        if self._injected_redis is not None:
            return self._injected_redis
        url = get_redis_url()
        if not url:
            return None
        if self._cached_redis is not None and self._cached_redis_url == url:
            return self._cached_redis
        self._cached_redis = redis.Redis.from_url(
            url,
            socket_connect_timeout=2,
            socket_timeout=2,
            decode_responses=False,
        )
        self._cached_redis_url = url
        return self._cached_redis

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

    def _check_redis_watch_cas(
        self,
        r_client,
        key: str,
        now: float,
        cutoff: float,
        max_req: int,
        window_sec: int,
        member: str,
    ) -> tuple[bool, int]:
        """
        Atomic optimistic-locking (WATCH/MULTI/EXEC) fallback used ONLY when a test
        Redis emulator does not support Lua EVAL (e.g., FakeRedis without lupa).
        All mutations occur atomically inside MULTI/EXEC with WatchError retry.
        """
        max_attempts = 25
        for _ in range(max_attempts):
            with r_client.pipeline() as pipe:
                try:
                    pipe.watch(key)
                    active_count = pipe.zcount(key, f"({cutoff}", "+inf")
                    if active_count >= max_req:
                        oldest = pipe.zrangebyscore(
                            key, f"({cutoff}", "+inf", start=0, num=1, withscores=True
                        )
                        pipe.unwatch()
                        if oldest:
                            oldest_ts = float(oldest[0][1])
                            retry_after = max(1, int(window_sec - (now - oldest_ts)) + 1)
                        else:
                            retry_after = window_sec
                        return False, retry_after

                    pipe.multi()
                    pipe.zremrangebyscore(key, "-inf", cutoff)
                    pipe.zadd(key, {member: now})
                    pipe.expire(key, window_sec + 5)
                    pipe.execute()
                    return True, 0
                except redis.WatchError:
                    continue

        # Contention exceeded bounded CAS retries — fail closed for safety
        return False, 1

    def _check_redis(self, r_client, client_key: str, max_req: int, window_sec: int) -> tuple[bool, int]:
        now = time.time()
        cutoff = now - window_sec
        key = f"leadhunter:ratelimit:{client_key}"
        member = f"{now:.6f}:{uuid.uuid4().hex[:10]}"

        try:
            res = r_client.eval(
                SLIDING_WINDOW_LUA_SCRIPT,
                1,
                key,
                f"{now:.6f}",
                f"{cutoff:.6f}",
                str(max_req),
                str(window_sec),
                member,
            )
            allowed = bool(int(res[0]))
            retry_after = int(res[1])
            return allowed, retry_after
        except redis.ResponseError as exc:
            # FakeRedis without lupa raises "unknown command 'eval'"; use atomic WATCH/MULTI/EXEC
            if "unknown command" in str(exc).lower() and "eval" in str(exc).lower():
                return self._check_redis_watch_cas(
                    r_client, key, now, cutoff, max_req, window_sec, member
                )
            raise

    def check(self, client_key: str) -> tuple[bool, int]:
        max_req, window_sec = self._get_limits()
        fail_closed = self._should_fail_closed()

        try:
            r_client = self._get_redis()
        except Exception as exc:
            logger.error("Redis rate limiter client initialization failed: %s", exc)
            if fail_closed:
                return False, window_sec
            return self._check_memory(client_key, max_req, window_sec)

        if r_client is not None:
            try:
                return self._check_redis(r_client, client_key, max_req, window_sec)
            except Exception as exc:
                logger.error("Redis rate limiter unavailable (%s); fail_closed=%s", exc, fail_closed)
                if fail_closed:
                    return False, window_sec
                return self._check_memory(client_key, max_req, window_sec)

        # No Redis configured: production fails closed (never silently downgrades to per-process memory)
        if is_production_env() and fail_closed:
            logger.error("Redis rate limiter is not configured in production; failing closed.")
            return False, window_sec

        return self._check_memory(client_key, max_req, window_sec)

    def reset(self):
        with self._lock:
            self._hits.clear()
        try:
            r_client = self._get_redis()
        except Exception:
            r_client = None
        if r_client is not None and self._injected_redis is not None:
            try:
                for key in r_client.scan_iter("leadhunter:ratelimit:*"):
                    r_client.delete(key)
            except Exception:
                pass
