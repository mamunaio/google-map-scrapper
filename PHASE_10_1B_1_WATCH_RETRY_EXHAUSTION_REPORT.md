# Phase 10.1B.1 — WATCH Retry Exhaustion Correction Report

**Date:** 2026-11-18  
**Repository:** `mamunaio/google-map-scrapper` (`D:\Github Files\google-map-scrapper`)  
**Branch:** `feature/lead-intelligence-phase-05-08`  
**Verified Starting HEAD:** `7cb9922022d69b1c4ae30638c8cd78bfe640894f`  
**`origin/main`:** Untouched at `d7ca71e103cc87e5659fcd9f010dd4f90bc56c61`

---

## 1. Root Cause

Independent review of commit `7cb9922022d69b1c4ae30638c8cd78bfe640894f` found that `_compare_and_delete_key_strict()` and `_compare_and_swap_key_strict()` in `services/job_queue.py` returned `False` after exhausting 10 consecutive `redis.WatchError` retries in the `WATCH`/`MULTI`/`EXEC` fallback path.

Because `redis.WatchError` indicates transaction invalidation under concurrent modification—not a completed atomic ownership comparison confirming mismatch—returning `False` violated the strict helper contract and could incorrectly produce HTTP `409` (`reservation_ownership_lost`) instead of retryable HTTP `503` (`queue_unavailable`).

---

## 2. Implemented Correction

**File modified:** `services/job_queue.py`

1. Preserved the 10-attempt bounded retry loop in both `_compare_and_delete_key_strict()` and `_compare_and_swap_key_strict()`.
2. Changed retry-exhaustion exit from `return False` to raising `QueueUnavailableError(...) from last_watch_exc`.
3. Reserved `return False` exclusively for a completed atomic check (Lua `EVAL` returning `0` or `pipe.get(key) != expected_value` under `WATCH`) confirming ownership mismatch.
4. Preserved genuine Redis error handling, Lua-unsupported fallback detection (`_is_lua_unsupported_error()`), and legacy `_compare_and_delete_key()` / `_compare_and_swap_key()` public `bool` wrappers (which continue converting strict exceptions to `False`).

---

## 3. Regression Tests Added

**File modified:** `tests/test_runtime_phase10_1b.py` (`test_watch_retry_exhaustion_raises_queue_unavailable_and_legacy_returns_false`; suite total increased from 30 to 31 tests)

- Forces `redis.WatchError` on all 10 transaction attempts using a pipeline wrapper over `FakeRedis`.
- Verifies `_compare_and_swap_key_strict()` attempts exactly 10 retries and raises `QueueUnavailableError`, leaving both the target key and another owner's key untouched.
- Verifies `_compare_and_delete_key_strict()` attempts exactly 10 retries and raises `QueueUnavailableError`, leaving both the target key and another owner's key untouched.
- Verifies legacy `_compare_and_swap_key()` and `_compare_and_delete_key()` still convert exhausted `WatchError` retries into `False` after 10 attempts without mutating any key.
- Verifies end-to-end API behavior (`POST /api/jobs`) when WATCH retries exhaust during active-job promotion: returns HTTP `503` (`code: "queue_unavailable"`, no `job_id`) instead of HTTP `409`, with the reservation preserved.

---

## 4. Verification Results

Executed on Windows host (`Python 3.14.10`, `pytest 9.2.0`, `redis-py 8.1.0`, `rq 3.0.0`, `fakeredis 2.40.0`):

| Check | Exact Command | Outcome |
| --- | --- | --- |
| Phase 10.1B targeted suite | `.\.venv\Scripts\python.exe -m pytest tests/test_runtime_phase10_1b.py -v` | **PASS** — `31 passed in 6.27s` (0 failed, 0 skipped, 0 warnings) |
| Full repository test suite | `.\.venv\Scripts\python.exe -m pytest -v` | **PASS** — `212 passed, 99 subtests passed in 21.09s` (0 failed, 0 skipped; 1 pre-existing Windows socket teardown warning in `services/security.py` `SafeBrowserProxy._run`) |
| Export schema parity | `.\.venv\Scripts\python.exe -m pytest tests/test_data_quality_remediation.py -k "schema or json_and_excel" -v` | **PASS** — `2 passed, 25 deselected in 1.31s` |
| Bytecode compilation | `.\.venv\Scripts\python.exe -m py_compile services/job_queue.py tests/test_runtime_phase10_1b.py` | **PASS** — exit code 0 |
| Python 3.12 AST compatibility | `ast.parse(..., feature_version=(3, 12))` on both modified files | **PASS** — `AST_PY312_OK` |
| Git diff whitespace/hygiene | `git diff --check` | **PASS** — exit code 0 |

---

## 5. Remaining Infrastructure Gates (Unchanged)

This Windows host has no local Redis server (`127.0.0.1:6379` closed) and no Docker/Podman daemon. Live Redis server Lua `EVAL` verification and live Linux Docker image build/smoke testing remain environment-gated for a Docker-enabled Linux CI runner or staging environment.
