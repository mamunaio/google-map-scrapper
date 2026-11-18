"""
Phase 10.1B — Gate 1: Live Redis 7 Lua EVAL Verification.

Executes the actual production Lua helpers against a real Redis 7 server (never mocks or
FakeRedis) and proves real `EVAL` execution via Redis `INFO server` and `INFO commandstats`:
  - services.job_queue._compare_and_swap_key_strict()
  - services.job_queue._compare_and_delete_key_strict()
  - services.job_queue._compare_and_extend_key()
  - services.rate_limiter.SharedSlidingWindowRateLimiter (SLIDING_WINDOW_LUA_SCRIPT)

Never prints REDIS_URL, credentials, or secrets.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import socket
import sys
import time
import uuid
from pathlib import Path

import redis

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from services.job_queue import (  # noqa: E402
    QueueUnavailableError,
    _compare_and_delete_key,
    _compare_and_delete_key_strict,
    _compare_and_extend_key,
    _compare_and_swap_key,
    _compare_and_swap_key_strict,
)
from services.rate_limiter import SharedSlidingWindowRateLimiter  # noqa: E402


def _get_command_calls(conn: redis.Redis, cmd_name: str) -> tuple[int, int]:
    """Reads `(calls, failed_calls)` for a Redis command from `INFO commandstats`."""
    stats = conn.info("commandstats")
    entry = stats.get(f"cmdstat_{cmd_name}") or {}
    return int(entry.get("calls", 0)), int(entry.get("failed_calls", 0))


def _decode(raw) -> str | None:
    if raw is None:
        return None
    if isinstance(raw, bytes):
        return raw.decode("utf-8")
    return str(raw)


def _find_closed_local_port() -> int:
    """Allocates and immediately closes an ephemeral localhost TCP port for real connection-refused testing."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def main() -> int:
    redis_url = os.getenv("REDIS_URL", "").strip()
    if not redis_url:
        print("FAIL: REDIS_URL environment variable is required for live Redis 7 verification.", file=sys.stderr)
        return 1

    conn = redis.Redis.from_url(
        redis_url,
        socket_connect_timeout=3,
        socket_timeout=3,
        decode_responses=False,
    )

    # Confirm real Redis server (not FakeRedis) and major version 7
    assert conn.ping() is True, "Redis PING failed"
    server_info = conn.info("server")
    redis_version = str(server_info.get("redis_version", ""))
    assert redis_version.startswith("7."), f"Expected live Redis 7.x server, got redis_version={redis_version!r}"
    assert "fakeredis" not in conn.__class__.__module__.lower(), "Refusing to run Gate 1 against FakeRedis"

    run_id = uuid.uuid4().hex[:12]
    prefix = f"leadhunter:ci:live-lua:{run_id}:"
    created_keys: set[str] = set()
    results: dict[str, str] = {}

    def track(suffix: str) -> str:
        k = f"{prefix}{suffix}"
        created_keys.add(k)
        return k

    try:
        eval_calls_before, eval_failed_before = _get_command_calls(conn, "eval")
        watch_calls_before, _ = _get_command_calls(conn, "watch")

        # ------------------------------------------------------------------
        # Scenario 1 & 2: _compare_and_swap_key_strict()
        # ------------------------------------------------------------------
        cas_key = track("cas")
        other_key = track("other-owner")
        conn.set(cas_key, "reserving:owner-A", ex=60)
        conn.set(other_key, "reserving:owner-B", ex=60)

        # Scenario 2: Non-matching owner cannot modify another owner's key
        mismatch_cas = _compare_and_swap_key_strict(conn, other_key, "reserving:wrong-owner", "hijacked", ex=120)
        assert mismatch_cas is False, "Expected False on non-matching CAS owner"
        assert _decode(conn.get(other_key)) == "reserving:owner-B", "Other owner's key was unexpectedly modified"
        results["cas_non_matching_owner_blocked"] = "PASS"

        # Scenario 1: Matching owner successfully performs CAS
        matched_cas = _compare_and_swap_key_strict(conn, cas_key, "reserving:owner-A", "job-confirmed-A", ex=180)
        assert matched_cas is True, "Expected True on matching CAS owner"
        assert _decode(conn.get(cas_key)) == "job-confirmed-A", "CAS did not update key value"
        cas_ttl = conn.ttl(cas_key)
        assert 100 <= cas_ttl <= 180, f"Expected refreshed CAS TTL in [100, 180], got {cas_ttl}"
        assert _decode(conn.get(other_key)) == "reserving:owner-B", "Unrelated owner key altered during CAS"
        results["cas_matching_owner_succeeded"] = "PASS"

        # ------------------------------------------------------------------
        # Scenario 3 & 4: _compare_and_delete_key_strict()
        # ------------------------------------------------------------------
        del_key = track("del")
        conn.set(del_key, "reserving:owner-C", ex=60)

        # Scenario 4: Non-matching owner cannot delete another owner's key
        mismatch_del = _compare_and_delete_key_strict(conn, del_key, "reserving:intruder")
        assert mismatch_del is False, "Expected False on non-matching delete owner"
        assert _decode(conn.get(del_key)) == "reserving:owner-C", "Non-matching delete removed or altered key"
        results["delete_non_matching_owner_blocked"] = "PASS"

        # Scenario 3: Matching owner successfully deletes its reservation
        matched_del = _compare_and_delete_key_strict(conn, del_key, "reserving:owner-C")
        assert matched_del is True, "Expected True on matching delete owner"
        assert conn.get(del_key) is None, "Matching delete did not remove key"
        assert _decode(conn.get(other_key)) == "reserving:owner-B", "Unrelated owner key altered during delete"
        results["delete_matching_owner_succeeded"] = "PASS"

        # ------------------------------------------------------------------
        # Scenario 5: _compare_and_extend_key()
        # ------------------------------------------------------------------
        ext_key = track("extend")
        conn.set(ext_key, "reserving:owner-D", ex=15)
        initial_ttl = conn.ttl(ext_key)
        assert 1 <= initial_ttl <= 15, f"Unexpected initial TTL: {initial_ttl}"

        # Non-matching owner cannot extend another owner's TTL
        mismatch_ext = _compare_and_extend_key(conn, ext_key, "reserving:intruder", ex=240)
        assert mismatch_ext is False, "Expected False on non-matching extend owner"
        ttl_after_mismatch = conn.ttl(ext_key)
        assert ttl_after_mismatch <= 15, f"Non-matching extend altered TTL to {ttl_after_mismatch}"

        # Matching owner extends reservation TTL
        matched_ext = _compare_and_extend_key(conn, ext_key, "reserving:owner-D", ex=240)
        assert matched_ext is True, "Expected True on matching extend owner"
        extended_ttl = conn.ttl(ext_key)
        assert extended_ttl >= 200, f"Expected extended TTL >= 200, got {extended_ttl}"
        assert _decode(conn.get(ext_key)) == "reserving:owner-D", "Extend mutated key value"
        results["extend_matching_and_non_matching_verified"] = "PASS"

        # ------------------------------------------------------------------
        # Scenario 7 (Proof of real Redis EVAL execution for job_queue Lua)
        # ------------------------------------------------------------------
        eval_calls_after_jq, eval_failed_after_jq = _get_command_calls(conn, "eval")
        watch_calls_after_jq, _ = _get_command_calls(conn, "watch")
        jq_eval_delta = eval_calls_after_jq - eval_calls_before
        jq_eval_failed_delta = eval_failed_after_jq - eval_failed_before
        jq_watch_delta = watch_calls_after_jq - watch_calls_before

        assert jq_eval_delta >= 6, f"Expected >= 6 live Redis EVAL calls for job_queue helpers, got {jq_eval_delta}"
        assert jq_eval_failed_delta == 0, f"Unexpected failed EVAL calls: {jq_eval_failed_delta}"
        assert jq_watch_delta == 0, f"Expected 0 WATCH fallback calls on live Redis 7, got {jq_watch_delta}"
        results["real_redis_eval_verified"] = "PASS"

        # ------------------------------------------------------------------
        # Scenario 6: Real Redis connection failure classification
        # ------------------------------------------------------------------
        closed_port = _find_closed_local_port()
        dead_conn = redis.Redis(
            host="127.0.0.1",
            port=closed_port,
            socket_connect_timeout=0.5,
            socket_timeout=0.5,
        )

        cas_unavailable_raised = False
        try:
            _compare_and_swap_key_strict(dead_conn, cas_key, "owner", "new", ex=60)
        except QueueUnavailableError:
            cas_unavailable_raised = True
        assert cas_unavailable_raised, "Expected QueueUnavailableError from _compare_and_swap_key_strict on dead Redis"

        del_unavailable_raised = False
        try:
            _compare_and_delete_key_strict(dead_conn, cas_key, "owner")
        except QueueUnavailableError:
            del_unavailable_raised = True
        assert del_unavailable_raised, "Expected QueueUnavailableError from _compare_and_delete_key_strict on dead Redis"

        # Legacy helpers must preserve backward-compatible False behavior
        assert _compare_and_swap_key(dead_conn, cas_key, "owner", "new", ex=60) is False
        assert _compare_and_delete_key(dead_conn, cas_key, "owner") is False
        results["connection_failure_classification_verified"] = "PASS"

        # ------------------------------------------------------------------
        # Additional Phase 10.1B check: Live Redis 7 SLIDING_WINDOW_LUA_SCRIPT
        # ------------------------------------------------------------------
        os.environ["RATE_LIMIT_MAX_REQUESTS"] = "5"
        os.environ["RATE_LIMIT_WINDOW_SECONDS"] = "30"
        rl_client_key = f"ci-live-lua-{run_id}"
        rl_redis_key = f"leadhunter:ratelimit:{rl_client_key}"
        created_keys.add(rl_redis_key)

        eval_before_rl, eval_failed_before_rl = _get_command_calls(conn, "eval")
        watch_before_rl, _ = _get_command_calls(conn, "watch")

        def _hit(_idx: int) -> tuple[bool, int]:
            limiter = SharedSlidingWindowRateLimiter(
                redis_client=redis.Redis.from_url(redis_url, socket_connect_timeout=3, socket_timeout=3)
            )
            return limiter.check(rl_client_key)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            outcomes = list(pool.map(_hit, range(12)))

        accepted = [ok for ok, _ in outcomes if ok]
        rejected = [(ok, ra) for ok, ra in outcomes if not ok]
        assert len(accepted) == 5, f"Expected exactly 5 accepted requests, got {len(accepted)}"
        assert len(rejected) == 7, f"Expected exactly 7 rejected requests, got {len(rejected)}"
        assert all(ra >= 1 for _, ra in rejected), f"Expected positive retry_after on rejections: {rejected}"
        rl_ttl = conn.ttl(rl_redis_key)
        assert 1 <= rl_ttl <= 35, f"Expected rate-limit key TTL in [1, 35], got {rl_ttl}"

        eval_after_rl, eval_failed_after_rl = _get_command_calls(conn, "eval")
        watch_after_rl, _ = _get_command_calls(conn, "watch")
        rl_eval_delta = eval_after_rl - eval_before_rl
        assert rl_eval_delta >= 12, f"Expected >= 12 live EVAL calls for rate limiter, got {rl_eval_delta}"
        assert (eval_failed_after_rl - eval_failed_before_rl) == 0
        assert (watch_after_rl - watch_before_rl) == 0
        results["rate_limiter_sliding_window_lua_verified"] = "PASS"

    finally:
        # Clean up ONLY keys created by this test run
        if created_keys:
            conn.delete(*sorted(created_keys))
        leftover = [k for k in created_keys if conn.exists(k)]
        if leftover:
            print(f"WARNING: Leftover test keys after cleanup: {len(leftover)}", file=sys.stderr)

    summary = {
        "gate": "Gate 1 — Live Redis 7 Lua EVAL",
        "status": "PASS",
        "redis_version": redis_version,
        "job_queue_eval_calls": jq_eval_delta,
        "job_queue_watch_fallback_calls": jq_watch_delta,
        "rate_limiter_eval_calls": rl_eval_delta,
        "cleaned_up_keys": len(created_keys),
        "scenarios": results,
    }
    print(json.dumps(summary, indent=2))

    step_summary_path = os.getenv("GITHUB_STEP_SUMMARY", "").strip()
    if step_summary_path:
        with open(step_summary_path, "a", encoding="utf-8") as fh:
            fh.write("## Gate 1 — Live Redis 7 Lua EVAL Verification: PASS\n\n")
            fh.write(f"- **Redis version:** `{redis_version}`\n")
            fh.write(f"- **Job queue Lua `EVAL` calls:** `{jq_eval_delta}` (`WATCH` fallback calls: `{jq_watch_delta}`)\n")
            fh.write(f"- **Rate limiter Lua `EVAL` calls:** `{rl_eval_delta}` (12 concurrent requests -> 5 accepted, 7 rejected)\n")
            fh.write(f"- **Isolated test keys cleaned up:** `{len(created_keys)}`\n\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
