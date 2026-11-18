# Phase 10.1B.1 — Ambiguous Enqueue Outcome Correction Report

**Date:** 2026-11-18  
**Repository:** `mamunaio/google-map-scrapper` (`D:\Github Files\google-map-scrapper`)  
**Branch:** `feature/lead-intelligence-phase-05-08`  
**Verified Pre-Edit Baseline HEAD:** `2e725ee42748ecff701db99b7bcb48b8a7f8c364`  
**`origin/main`:** Untouched at `d7ca71e103cc87e5659fcd9f010dd4f90bc56c61`

---

## 1. Root Cause & Finding Addressed

In `services/job_queue.py` (`enqueue_scrape_job()`), the exception handler around `queue.enqueue(..., job_id=reserved_job_id)` previously assumed that any raised exception meant the RQ job was never persisted in Redis and immediately released the reservation key via `_compare_and_delete_key(connection, dedup_key, reservation_val)`.

That assumption is unsafe during ambiguous network failures (for example, a Redis client read timeout or dropped TCP connection after Redis has already persisted the RQ job hash and queued the job). Releasing the reservation while the job is active in Redis would permit a subsequent caller to acquire a fresh reservation and enqueue a duplicate active job for the same payload.

---

## 2. Implemented Reconciliation State Machine

**File modified:** `services/job_queue.py` (`enqueue_scrape_job()`, lines 638–823)

When `queue.enqueue(..., job_id=reserved_job_id)` raises an exception (`enqueue_exc`), `enqueue_scrape_job()` now reconciles the pre-generated `reserved_job_id` before touching `dedup_key`:

| Reconciliation Outcome | Detection | Action on `dedup_key` | Caller Result |
| --- | --- | --- | --- |
| **1. Persisted & Active** (`queued`, `started`, `deferred`, `scheduled`) | `Job.fetch(reserved_job_id)` succeeds and `_normalize_job_status(job)` returns an active status | Verifies `not renewer.ownership_lost`, then atomically promotes `"reserving:<id>"` -> `"<id>"` with `dedup_ttl` via `_compare_and_swap_key()`. Never touches another owner's key. | Returns `{"job_id": job.id, "status": actual_status, "deduplicated": False, "workers_online": workers_online}` **only if** ownership & promotion succeed. Subsequent callers deduplicate against this confirmed active `job_id`. If ownership was lost, raises `JobReservationOwnershipError` (HTTP `409`). If Redis errors during promotion, preserves reservation and raises `QueueUnavailableError` (HTTP `503`). |
| **2. Confirmed Absent** | `Job.fetch(reserved_job_id)` raises `rq.exceptions.NoSuchJobError` | Releases **only** our own reservation via `_compare_and_delete_key(connection, dedup_key, reservation_val)` (never deletes another caller's reservation). | Re-raises the exact original `enqueue_exc` without replacing it with `NoSuchJobError`. |
| **3. Redis Unavailable During Reconciliation / Status Check** | `Job.fetch()`, `_normalize_job_status()`, or terminal cleanup raises a non-`NoSuchJobError` exception (e.g., `ConnectionError`, `TimeoutError`) | **Preserves reservation untouched** (never assumes absence, never deletes `dedup_key`). | Raises retryable `QueueUnavailableError` (maps to HTTP `503`, `code: "queue_unavailable"`, with **no** unconfirmed `job_id`). |
| **4. Persisted & Already Terminal** (`finished`, `failed`, `timed_out`, `canceled`) | `Job.fetch(reserved_job_id)` succeeds and `_normalize_job_status(job)` is not in `ACTIVE_JOB_STATUSES` | Checks `renewer.ownership_lost`; if still owned, atomically releases **only** our own reservation via `_compare_and_delete_key()`. If `renewer.ownership_lost` or CAS-delete returns `False`, leaves `dedup_key` untouched. | **Chosen terminal-job policy:** Does **not** report the terminal job as an active/deduplicated job and does **not** create a duplicate in the same call. If ownership was lost, raises `JobReservationOwnershipError` (HTTP `409`). Otherwise releases our own reservation so future submissions are unblocked and re-raises the original `enqueue_exc`. |

### Preserved Controls & Contracts
- `_ReservationLeaseRenewer` ownership-checked lease renewal remains active across both enqueue and reconciliation.
- Existing bounded waiting (`JobReservationConflictError` -> HTTP `409`), ownership loss (`JobReservationOwnershipError` -> HTTP `409`), and broker unavailability (`QueueUnavailableError` -> HTTP `503`) API mappings in `app.py` required no changes and remain intact.
- All Phase 10.1A security controls (SSRF protection, auth, rate limiting, DOM XSS, SSL/SMTP hardening) and approved `16 / 15 / 7 / CSV-16` export schemas are untouched.

---

## 3. Regression Tests Added

**File modified:** `tests/test_runtime_phase10_1b.py` (`TestRqJobLifecycleAndContracts`, 5 new deterministic test methods; suite total increased from 21 to 26 tests)

1. `test_ambiguous_enqueue_reconciles_persisted_active_job_and_deduplicates_second_caller`:
   - Simulates `Queue.enqueue()` persisting a `queued` job and then raising `TimeoutError`; verifies reconciliation promotes `dedup_key`, returns confirmed `job_id`, and a second caller deduplicates to the exact same `job_id` with `len(queue) == 1`.
   - Simulates `Queue.enqueue()` persisting a job that transitions to `started` before raising `ConnectionError`; verifies reconciled `status == "started"`, promoted `dedup_key`, and second-caller deduplication.
2. `test_ambiguous_enqueue_absent_job_releases_reservation_and_preserves_error`:
   - Simulates pre-write `RuntimeError` before any job hash is persisted; verifies reservation is deleted (`None`), queue remains empty, and original `RuntimeError` is re-raised intact.
3. `test_ambiguous_enqueue_redis_unavailable_during_reconciliation_preserves_reservation`:
   - Simulates `Queue.enqueue()` timeout followed by `Job.fetch()` `ConnectionError`; verifies reservation remains `reserving:<id>`, `QueueUnavailableError` is raised, and `POST /api/jobs` returns HTTP `503` (`code: "queue_unavailable"`) with no `job_id`.
   - Also simulates Redis `ConnectionError` during `_normalize_job_status()` after `Job.fetch()`; verifies reservation is preserved and `QueueUnavailableError` is raised.
4. `test_ambiguous_enqueue_never_overwrites_or_deletes_another_owners_reservation`:
   - Covers all three reconciliation branches (persisted active job, absent job, persisted terminal job) when another caller has replaced `dedup_key` with `reserving:other-owner-job-id`; verifies the other owner's reservation is never overwritten or deleted, and active/terminal ownership loss raises `JobReservationOwnershipError`.
5. `test_ambiguous_enqueue_reconciles_terminal_job_without_reporting_active_or_duplicating`:
   - Tests both `JobStatus.FINISHED` and `JobStatus.FAILED` after an ambiguous `TimeoutError`; verifies neither is returned as active/deduplicated, original `TimeoutError` is re-raised, own reservation is released (`None`), no duplicate job is created, and a subsequent fresh submission succeeds cleanly with a new job ID.

---

## 4. Verification Results

Executed on Windows host (`Python 3.14.10`, `pytest 9.2.0`, `redis-py 8.1.0`, `rq 3.0.0`, `fakeredis 2.40.0`):

| Check | Exact Command | Outcome |
| --- | --- | --- |
| Phase 10.1B targeted suite | `.\.venv\Scripts\python.exe -m pytest tests/test_runtime_phase10_1b.py -v` | **PASS** — `26 passed in 1.98s` (0 failed, 0 skipped, 0 warnings) |
| Full repository test suite | `.\.venv\Scripts\python.exe -m pytest -v` | **PASS** — `207 passed, 99 subtests passed in 17.10s` (0 failed, 0 skipped, 0 warnings) |
| Export schema parity | `.\.venv\Scripts\python.exe -m pytest tests/test_data_quality_remediation.py -k "schema or json_and_excel" -v` | **PASS** — `2 passed, 25 deselected in 1.22s` |
| Bytecode compilation | `.\.venv\Scripts\python.exe -m py_compile services/job_queue.py tests/test_runtime_phase10_1b.py` | **PASS** — exit code 0 |
| Python 3.12 AST syntax check | `ast.parse(..., feature_version=(3, 12))` on both modified files | **PASS** — `AST_PY312_OK` |
| Git diff whitespace/hygiene | `git diff --check` | **PASS** — exit code 0 |

---

## 5. Remaining Infrastructure Verification Gates (Unchanged)

This Windows host does not have a local Redis server binary (`127.0.0.1:6379` closed) or a Docker/Podman daemon installed. Accordingly, the following environment-gated checks remain to be executed on a Docker-enabled Linux CI runner or staging environment before production cutover:
1. **Live Redis server Lua `EVAL` verification** for atomic rate limiting (`SLIDING_WINDOW_LUA_SCRIPT`) and atomic CAS/extend/delete scripts in `services/job_queue.py`.
2. **Live Linux Docker image build & smoke test** (`Dockerfile`, Gunicorn web + RQ worker + Playwright Chromium + Redis).

No claims of live Redis Lua execution or Docker builds are made for this local run; all local reconciliation tests executed deterministically against `FakeRedis`.
