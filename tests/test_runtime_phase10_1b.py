"""
Phase 10.1B Runtime & Deployment Readiness Regression Test Suite.
Covers:
  - RQ job lifecycle: queued, started, finished (completed), failed, timed_out
  - Duplicate job submission & bounded retry policy
  - Redis unavailable & worker unavailable handling
  - Multiple concurrent requests & bounded browser concurrency
  - Container-safe Chromium flags & deterministic resource/proxy cleanup
  - Multi-worker shared Redis rate-limit consistency & opt-in TRUSTED_PROXY_HOPS
  - /healthz & /readyz liveness/readiness probes
  - Startup env validation, structured JSON logging, correlation IDs & PII-safe logging
  - Production WSGI (gunicorn.conf.py), Dockerfile, .dockerignore, render.yaml & pinned requirements verification
"""

import io
import json
import logging
import os
import pathlib
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch

import fakeredis
import openpyxl
from rq import SimpleWorker
from rq.job import Job, JobStatus

import app as app_module
from app import app, apply_trusted_proxy_middleware, rate_limiter
from services.browser_runtime import (
    BrowserConcurrencyError,
    acquire_browser_slot,
    get_active_browser_count,
    get_chromium_launch_args,
    reset_browser_concurrency_state,
)
from services.export_service import (
    BUSINESS_OPPORTUNITIES_COLUMNS,
    LEAD_TRACKER_COLUMNS,
    WEBSITE_AUDIT_COLUMNS,
)
from services.job_queue import (
    enqueue_scrape_job,
    get_job_queue,
    set_redis_connection,
)
from services.job_tasks import execute_scrape_job
from services.rate_limiter import SharedSlidingWindowRateLimiter
from services.runtime_config import (
    RuntimeConfigError,
    configure_logging,
    redact_email_for_log,
    redact_url_for_log,
    validate_startup_config,
)
from services.security import SafeBrowserProxy
from services.website_crawler import scrape_with_playwright_fallback


class _BasePhase101BTestCase(unittest.TestCase):
    def setUp(self):
        self._env_keys = (
            "LEADHUNTER_API_KEY",
            "LEADHUNTER_ENV",
            "FLASK_ENV",
            "RENDER",
            "FLASK_DEBUG",
            "REDIS_URL",
            "RQ_QUEUE_NAME",
            "REQUIRE_ACTIVE_WORKER",
            "JOB_TIMEOUT_SECONDS",
            "JOB_RESULT_TTL_SECONDS",
            "JOB_FAILURE_TTL_SECONDS",
            "JOB_DEDUP_TTL_SECONDS",
            "JOB_RESERVATION_TTL_SECONDS",
            "JOB_RESERVATION_WAIT_MS",
            "JOB_MAX_RETRIES",
            "WORKER_HEARTBEAT_MAX_AGE_SECONDS",
            "WORKER_TTL_SECONDS",
            "RATE_LIMIT_MAX_REQUESTS",
            "RATE_LIMIT_WINDOW_SECONDS",
            "RATE_LIMIT_FAIL_CLOSED",
            "TRUSTED_PROXY_HOPS",
            "BROWSER_MAX_CONCURRENCY",
            "BROWSER_ACQUIRE_TIMEOUT_SECONDS",
            "CHROMIUM_NO_SANDBOX",
            "LOG_LEVEL",
            "LOG_FORMAT",
            "MAX_CONTENT_LENGTH",
        )
        self._env_backup = {k: os.environ.get(k) for k in self._env_keys}
        os.environ["LEADHUNTER_API_KEY"] = "phase10-1b-test-secret-key"
        os.environ.pop("LEADHUNTER_ENV", None)
        os.environ.pop("FLASK_ENV", None)
        os.environ.pop("RENDER", None)
        os.environ.pop("FLASK_DEBUG", None)
        os.environ.pop("REDIS_URL", None)
        os.environ["REQUIRE_ACTIVE_WORKER"] = "false"
        os.environ["RATE_LIMIT_MAX_REQUESTS"] = "100"
        os.environ["RATE_LIMIT_WINDOW_SECONDS"] = "60"
        os.environ["TRUSTED_PROXY_HOPS"] = "0"
        os.environ["JOB_MAX_RETRIES"] = "2"

        self.fake_redis = fakeredis.FakeRedis()
        set_redis_connection(self.fake_redis)
        rate_limiter.set_redis_client(None)
        rate_limiter.reset()
        apply_trusted_proxy_middleware(app, hops=0)
        reset_browser_concurrency_state()
        self.client = app.test_client()
        self.auth = {"X-API-Key": "phase10-1b-test-secret-key"}

    def tearDown(self):
        set_redis_connection(None)
        rate_limiter.set_redis_client(None)
        rate_limiter.reset()
        apply_trusted_proxy_middleware(app, hops=0)
        reset_browser_concurrency_state()
        for k, v in self._env_backup.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# =============================================================================
# 1. RQ JOB LIFECYCLE, DEDUPLICATION, RETRIES, TIMEOUTS & EXPORT PARITY
# =============================================================================


class TestRqJobLifecycleAndContracts(_BasePhase101BTestCase):
    @patch("app.validate_and_sanitize_url", side_effect=lambda u: u)
    @patch("services.job_tasks.validate_and_sanitize_url", side_effect=lambda u: u)
    @patch("services.job_tasks.crawl_and_audit_website")
    def test_job_lifecycle_queued_started_completed_and_export_parity(self, mock_crawl, _v1, _v2):
        mock_crawl.return_value = {
            "Website": "https://dallas-hvac.example.com",
            "Website Status": "Online",
            "Email": "owner@dallas-hvac.example.com",
            "Contact Person": "Jane Miller",
            "Decision Maker": "Jane Miller (Owner)",
            "Email Status": "MX Only",
            "Email Verification": "MX Only",
            "Priority": "High",
            "Lead Score": 82,
            "Main Opportunity": "Missing Online Booking",
            "Notes": "MX Only email detected; phone available.",
            "Facebook": "",
            "Instagram": "",
            "LinkedIn": "",
            "About Page Link": "",
            "intelligence": {
                "seo": {"status": "Online", "seo_score": 85},
                "technical": {"ssl_certificate": {"status": "Valid"}, "mobile_usability": {"status": "Responsive"}},
                "performance": {"audit_status": "API Key Not Configured", "mobile_score": None},
                "opportunities": {
                    "priority": "High",
                    "lead_score": 82,
                    "main_gap": "Missing Online Booking",
                    "detected_opportunities": [
                        {
                            "Opportunity Category": "Booking",
                            "Finding": "Missing Online Booking",
                            "Evidence": "No booking widget detected",
                            "Confidence": "High",
                            "Research Status": "Detected",
                            "Recommended Service": "Online Booking Integration",
                        }
                    ],
                },
            },
        }

        # 1. Enqueue -> 202 Accepted, queued
        resp_create = self.client.post(
            "/api/jobs",
            json={"url": "https://dallas-hvac.example.com", "type": "website", "business_name": "Dallas HVAC"},
            headers=self.auth,
        )
        self.assertEqual(resp_create.status_code, 202)
        created = json.loads(resp_create.data)
        self.assertTrue(created["success"])
        self.assertEqual(created["status"], "queued")
        self.assertFalse(created["deduplicated"])
        job_id = created["job_id"]

        # 2. Poll while queued -> status=queued, /result -> 202
        resp_q = self.client.get(f"/api/jobs/{job_id}", headers=self.auth)
        self.assertEqual(resp_q.status_code, 200)
        self.assertEqual(json.loads(resp_q.data)["status"], "queued")
        resp_res_pending = self.client.get(f"/api/jobs/{job_id}/result", headers=self.auth)
        self.assertEqual(resp_res_pending.status_code, 202)

        # 3. Simulate started state
        rq_job = Job.fetch(job_id, connection=self.fake_redis)
        rq_job.set_status(JobStatus.STARTED)
        resp_started = self.client.get(f"/api/jobs/{job_id}", headers=self.auth)
        self.assertEqual(resp_started.status_code, 200)
        self.assertEqual(json.loads(resp_started.data)["status"], "started")
        self.assertEqual(self.client.get(f"/api/jobs/{job_id}/result", headers=self.auth).status_code, 202)

        # Reset back to queued and execute via real RQ SimpleWorker
        rq_job.set_status(JobStatus.QUEUED)
        worker = SimpleWorker([get_job_queue(conn=self.fake_redis)], connection=self.fake_redis)
        worker.work(burst=True)

        # 4. Poll finished -> 200 finished, /result -> 200 with lead payload
        resp_done = self.client.get(f"/api/jobs/{job_id}", headers=self.auth)
        self.assertEqual(resp_done.status_code, 200)
        done_body = json.loads(resp_done.data)
        self.assertEqual(done_body["status"], "finished")
        self.assertEqual(done_body["progress"]["progress_pct"], 100)

        resp_result = self.client.get(f"/api/jobs/{job_id}/result", headers=self.auth)
        self.assertEqual(resp_result.status_code, 200)
        res_body = json.loads(resp_result.data)
        self.assertTrue(res_body["success"])
        self.assertEqual(res_body["count"], 1)
        self.assertEqual(res_body["leads"][0]["Business Name"], "Dallas HVAC")
        self.assertEqual(res_body["leads"][0]["Email Status"], "MX Only")

        # 5. Verify approved 16/15/7 Excel & 16-col CSV export parity from async job result
        excel_resp = self.client.post(
            "/api/export-excel",
            json={"leads": res_body["leads"], "format_type": "standard_3_sheet"},
            headers=self.auth,
        )
        self.assertEqual(excel_resp.status_code, 200)
        wb = openpyxl.load_workbook(io.BytesIO(excel_resp.data))
        self.assertEqual(wb.sheetnames, ["Lead Tracker", "Website Audit", "Business Opportunities"])
        self.assertEqual([c.value for c in wb["Lead Tracker"][1]], LEAD_TRACKER_COLUMNS)
        self.assertEqual([c.value for c in wb["Website Audit"][1]], WEBSITE_AUDIT_COLUMNS)
        self.assertEqual([c.value for c in wb["Business Opportunities"][1]], BUSINESS_OPPORTUNITIES_COLUMNS)

        csv_resp = self.client.post("/api/export-csv", json={"leads": res_body["leads"]}, headers=self.auth)
        self.assertEqual(csv_resp.status_code, 200)
        header_cols = csv_resp.data.decode("utf-8-sig").splitlines()[0].split(",")
        self.assertEqual(len(header_cols), 16)

    @patch("app.validate_and_sanitize_url", side_effect=lambda u: u)
    @patch("services.job_tasks.validate_and_sanitize_url", side_effect=lambda u: u)
    @patch("services.job_tasks.crawl_and_audit_website", side_effect=RuntimeError("INTERNAL_SECRET_TRACE=xyz"))
    def test_job_failed_and_timed_out_states_sanitized(self, _mock_crawl, _v1, _v2):
        # 1. Failed job (0 retries so it fails immediately on first burst)
        os.environ["JOB_MAX_RETRIES"] = "0"
        resp = self.client.post(
            "/api/jobs",
            json={"url": "https://failing.example.com", "type": "website"},
            headers=self.auth,
        )
        self.assertEqual(resp.status_code, 202)
        job_id = json.loads(resp.data)["job_id"]

        worker = SimpleWorker([get_job_queue(conn=self.fake_redis)], connection=self.fake_redis)
        worker.work(burst=True)

        status_resp = self.client.get(f"/api/jobs/{job_id}", headers=self.auth)
        self.assertEqual(status_resp.status_code, 200)
        status_body = json.loads(status_resp.data)
        self.assertEqual(status_body["status"], "failed")
        self.assertNotIn("INTERNAL_SECRET_TRACE", status_body["error"] or "")

        result_resp = self.client.get(f"/api/jobs/{job_id}/result", headers=self.auth)
        self.assertEqual(result_resp.status_code, 500)
        self.assertNotIn("INTERNAL_SECRET_TRACE", json.loads(result_resp.data)["error"])

        # 2. Timed out job (real RQ JobTimeoutException raised during worker execution)
        from rq.timeouts import JobTimeoutException
        with patch("services.job_tasks.crawl_and_audit_website", side_effect=JobTimeoutException("Task exceeded 900s")):
            resp_to = self.client.post(
                "/api/jobs",
                json={"url": "https://timeout-site.example.com", "type": "website"},
                headers=self.auth,
            )
            self.assertEqual(resp_to.status_code, 202)
            timeout_job_id = json.loads(resp_to.data)["job_id"]

            worker2 = SimpleWorker([get_job_queue(conn=self.fake_redis)], connection=self.fake_redis)
            worker2.work(burst=True)

        timeout_status = self.client.get(f"/api/jobs/{timeout_job_id}", headers=self.auth)
        self.assertEqual(timeout_status.status_code, 200)
        self.assertEqual(json.loads(timeout_status.data)["status"], "timed_out")

        timeout_result = self.client.get(f"/api/jobs/{timeout_job_id}/result", headers=self.auth)
        self.assertEqual(timeout_result.status_code, 504)
        self.assertEqual(json.loads(timeout_result.data)["status"], "timed_out")

    @patch("app.validate_google_maps_url", side_effect=lambda u: u)
    def test_duplicate_job_submission_deduplicated_and_bounded_retries_configured(self, _mock_val):
        os.environ["JOB_MAX_RETRIES"] = "2"
        payload = {
            "url": "https://www.google.com/maps/search/HVAC+Dallas+TX",
            "type": "maps",
            "max_results": 20,
        }

        r1 = self.client.post("/api/jobs", json=payload, headers=self.auth)
        self.assertEqual(r1.status_code, 202)
        b1 = json.loads(r1.data)
        self.assertFalse(b1["deduplicated"])

        # Identical second submission while active MUST return existing job_id
        r2 = self.client.post("/api/jobs", json=payload, headers=self.auth)
        self.assertEqual(r2.status_code, 202)
        b2 = json.loads(r2.data)
        self.assertTrue(b2["deduplicated"])
        self.assertEqual(b2["job_id"], b1["job_id"])

        # Verify bounded retry metadata on the RQ job
        rq_job = Job.fetch(b1["job_id"], connection=self.fake_redis)
        self.assertEqual(rq_job.retries_left, 2)
        self.assertEqual(rq_job.retry_intervals, [10, 30])

        # Once job finishes, a new submission creates a fresh job
        rq_job.set_status(JobStatus.FINISHED)
        r3 = self.client.post("/api/jobs", json=payload, headers=self.auth)
        self.assertEqual(r3.status_code, 202)
        b3 = json.loads(r3.data)
        self.assertFalse(b3["deduplicated"])
        self.assertNotEqual(b3["job_id"], b1["job_id"])

    def test_job_ssrf_blocked_fast_and_non_retryable_in_task(self):
        # Fast-fail 400 on SSRF submission
        resp = self.client.post(
            "/api/jobs",
            json={"url": "http://169.254.169.254/latest/meta-data/", "type": "website"},
            headers=self.auth,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Security restriction", json.loads(resp.data)["error"])

        # Strict JSON integer max_results also enforced on /api/jobs
        resp_bad_max = self.client.post(
            "/api/jobs",
            data='{"url": "https://www.google.com/maps/search/hvac", "type": "maps", "max_results": "20"}',
            content_type="application/json",
            headers=self.auth,
        )
        self.assertEqual(resp_bad_max.status_code, 400)

        # Direct task invocation returns terminal 400 payload without raising retryable exception
        res = execute_scrape_job(url="http://127.0.0.1:8080/admin", scrape_type="website")
        self.assertFalse(res["success"])
        self.assertEqual(res["http_status"], 400)

    def test_redis_unavailable_and_worker_unavailable_handling(self):
        # 1. Redis unconfigured -> 503 queue_unavailable
        set_redis_connection(None)
        os.environ.pop("REDIS_URL", None)
        with patch("app.validate_and_sanitize_url", side_effect=lambda u: u):
            r_unconf = self.client.post(
                "/api/jobs",
                json={"url": "https://example.com", "type": "website"},
                headers=self.auth,
            )
            self.assertEqual(r_unconf.status_code, 503)
            self.assertEqual(json.loads(r_unconf.data)["code"], "queue_unavailable")

            self.assertEqual(self.client.get("/api/jobs/nonexistent-id", headers=self.auth).status_code, 503)
            self.assertEqual(self.client.get("/api/jobs/nonexistent-id/result", headers=self.auth).status_code, 503)

        # 2. Redis ping raises connection error -> 503 queue_unavailable
        broken_redis = MagicMock()
        broken_redis.ping.side_effect = ConnectionError("Redis refused connection")
        set_redis_connection(broken_redis)
        with patch("app.validate_and_sanitize_url", side_effect=lambda u: u):
            r_broken = self.client.post(
                "/api/jobs",
                json={"url": "https://example.com", "type": "website"},
                headers=self.auth,
            )
            self.assertEqual(r_broken.status_code, 503)
            self.assertEqual(json.loads(r_broken.data)["code"], "queue_unavailable")

        # 3. Redis healthy, REQUIRE_ACTIVE_WORKER=true, 0 workers online -> 503 worker_unavailable
        set_redis_connection(self.fake_redis)
        os.environ["REQUIRE_ACTIVE_WORKER"] = "true"
        with patch("app.validate_and_sanitize_url", side_effect=lambda u: u):
            r_noworker = self.client.post(
                "/api/jobs",
                json={"url": "https://example.com", "type": "website"},
                headers=self.auth,
            )
            self.assertEqual(r_noworker.status_code, 503)
            self.assertEqual(json.loads(r_noworker.data)["code"], "worker_unavailable")

        # Unknown job ID -> 404
        self.assertEqual(self.client.get("/api/jobs/does-not-exist-123", headers=self.auth).status_code, 404)

    def test_concurrent_duplicate_job_submissions_create_only_one_job_and_cleanup_on_failure(self):
        from services.job_queue import compute_job_dedup_key

        shared_server = fakeredis.FakeServer()
        target_url = "https://www.google.com/maps/search/HVAC+Dallas+TX"
        barrier = threading.Barrier(12)

        def submit_independent_caller(_idx):
            # Independent Redis client per caller sharing the same Redis server
            conn = fakeredis.FakeRedis(server=shared_server)
            barrier.wait(timeout=3.0)
            return enqueue_scrape_job(
                url=target_url,
                scrape_type="maps",
                max_results=20,
                conn=conn,
            )

        with ThreadPoolExecutor(max_workers=12) as ex:
            results = list(ex.map(submit_independent_caller, range(12)))

        job_ids = {r["job_id"] for r in results}
        fresh_count = sum(1 for r in results if not r["deduplicated"])
        dedup_count = sum(1 for r in results if r["deduplicated"])

        self.assertEqual(len(job_ids), 1, f"Expected exactly 1 unique job ID, got {job_ids}")
        self.assertEqual(fresh_count, 1)
        self.assertEqual(dedup_count, 11)

        inspect_conn = fakeredis.FakeRedis(server=shared_server)
        q = get_job_queue(conn=inspect_conn)
        self.assertEqual(len(q), 1)

        # Ensure reservation & lock cleanup if queue.enqueue fails
        dedup_key = compute_job_dedup_key(url="https://fail-enqueue.example.com", scrape_type="website", max_results=20)
        lock_key = f"{dedup_key}:lock"
        with patch("services.job_queue.Queue.enqueue", side_effect=RuntimeError("Simulated enqueue error")):
            with self.assertRaises(RuntimeError):
                enqueue_scrape_job(
                    url="https://fail-enqueue.example.com",
                    scrape_type="website",
                    max_results=20,
                    conn=inspect_conn,
                )
        self.assertIsNone(inspect_conn.get(dedup_key))
        self.assertIsNone(inspect_conn.get(lock_key))

        # Next submission after failed enqueue must succeed cleanly (not blocked)
        ok_after_fail = enqueue_scrape_job(
            url="https://fail-enqueue.example.com",
            scrape_type="website",
            max_results=20,
            conn=inspect_conn,
        )
        self.assertFalse(ok_after_fail["deduplicated"])

        # After previous job finishes or fails or expires, a new identical job is NOT blocked
        j = Job.fetch(ok_after_fail["job_id"], connection=inspect_conn)
        j.set_status(JobStatus.FAILED)
        after_failed = enqueue_scrape_job(
            url="https://fail-enqueue.example.com",
            scrape_type="website",
            max_results=20,
            conn=inspect_conn,
        )
        self.assertFalse(after_failed["deduplicated"])
        self.assertNotEqual(after_failed["job_id"], ok_after_fail["job_id"])

    def test_delayed_enqueue_waits_for_confirmation_or_returns_retryable_conflict_never_unconfirmed_id(self):
        from rq import Queue
        from services.job_queue import (
            JobReservationConflictError,
            RESERVING_PREFIX,
            compute_job_dedup_key,
        )

        shared_server = fakeredis.FakeServer()
        conn1 = fakeredis.FakeRedis(server=shared_server)
        conn2 = fakeredis.FakeRedis(server=shared_server)

        url = "https://www.google.com/maps/search/HVAC+Dallas+Delayed"
        dedup_key = compute_job_dedup_key(url=url, scrape_type="maps", max_results=20)

        orig_enqueue = Queue.enqueue
        caller1_in_enqueue = threading.Event()
        release_caller1 = threading.Event()
        results = {}

        def delayed_enqueue(self_q, *args, **kwargs):
            caller1_in_enqueue.set()
            release_caller1.wait(timeout=5.0)
            return orig_enqueue(self_q, *args, **kwargs)

        with patch.object(Queue, "enqueue", delayed_enqueue):
            t1 = threading.Thread(
                target=lambda: results.__setitem__(
                    "c1",
                    enqueue_scrape_job(url=url, scrape_type="maps", max_results=20, conn=conn1),
                )
            )
            t1.start()
            self.assertTrue(caller1_in_enqueue.wait(timeout=3.0))

            # Verify reservation key exists in reserving:<job_id> state
            raw_res = conn1.get(dedup_key).decode("utf-8")
            self.assertTrue(raw_res.startswith(RESERVING_PREFIX))

            # Scenario A: Caller B's bounded wait expires while Caller A remains in-flight
            # -> MUST raise retryable JobReservationConflictError, NEVER return an unconfirmed Job ID
            with self.assertRaises(JobReservationConflictError):
                enqueue_scrape_job(
                    url=url,
                    scrape_type="maps",
                    max_results=20,
                    conn=conn2,
                    reservation_wait_seconds=0.05,
                )

            # Verify API layer maps in-flight wait expiry to HTTP 409 retryable with NO job_id
            set_redis_connection(conn2)
            os.environ["JOB_RESERVATION_WAIT_MS"] = "40"
            with patch("app.validate_google_maps_url", side_effect=lambda u: u):
                r_conflict = self.client.post(
                    "/api/jobs",
                    json={"url": url, "type": "maps", "max_results": 20},
                    headers=self.auth,
                )
            self.assertEqual(r_conflict.status_code, 409)
            conflict_body = json.loads(r_conflict.data)
            self.assertFalse(conflict_body["success"])
            self.assertEqual(conflict_body["code"], "reservation_in_progress")
            self.assertTrue(conflict_body["retryable"])
            self.assertNotIn("job_id", conflict_body)
            self.assertIn("Retry-After", r_conflict.headers)

            # Scenario B: Caller C waits while Caller A commits -> receives CONFIRMED winning job_id
            t_waiter = threading.Thread(
                target=lambda: results.__setitem__(
                    "c3",
                    enqueue_scrape_job(
                        url=url,
                        scrape_type="maps",
                        max_results=20,
                        conn=conn2,
                        reservation_wait_seconds=2.0,
                    ),
                )
            )
            t_waiter.start()
            release_caller1.set()
            t1.join(timeout=3.0)
            t_waiter.join(timeout=3.0)

        # Exactly ONE active job exists in the queue and BOTH Caller A and confirmed waiter share its ID
        q = get_job_queue(conn=conn1)
        self.assertEqual(len(q), 1)
        self.assertEqual(results["c1"]["job_id"], results["c3"]["job_id"])
        self.assertFalse(results["c1"]["deduplicated"])
        self.assertTrue(results["c3"]["deduplicated"])
        self.assertEqual(q.job_ids, [results["c1"]["job_id"]])
        self.assertEqual(conn1.get(dedup_key).decode("utf-8"), results["c1"]["job_id"])

        # Expired (missing) RQ job hash on committed dedup key allows clean atomic replacement
        old_job = Job.fetch(results["c1"]["job_id"], connection=conn1)
        old_job.delete(remove_from_queue=True)
        after_expired = enqueue_scrape_job(url=url, scrape_type="maps", max_results=20, conn=conn2)
        self.assertFalse(after_expired["deduplicated"])
        self.assertNotEqual(after_expired["job_id"], results["c1"]["job_id"])

    def test_waiting_caller_acquires_and_enqueues_when_first_owner_fails(self):
        from rq import Queue

        shared_server = fakeredis.FakeServer()
        conn_a = fakeredis.FakeRedis(server=shared_server)
        conn_b = fakeredis.FakeRedis(server=shared_server)
        url = "https://fail-then-takeover.example.com"

        orig_enqueue = Queue.enqueue
        a_in_enqueue = threading.Event()
        let_a_fail = threading.Event()
        call_count = {"n": 0}
        outcomes = {}

        def first_fails_second_succeeds(self_q, *args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                a_in_enqueue.set()
                let_a_fail.wait(timeout=5.0)
                raise RuntimeError("Transient enqueue failure for Caller A")
            return orig_enqueue(self_q, *args, **kwargs)

        with patch.object(Queue, "enqueue", first_fails_second_succeeds):
            def run_a():
                try:
                    outcomes["a"] = enqueue_scrape_job(url=url, scrape_type="website", max_results=20, conn=conn_a)
                except RuntimeError as exc:
                    outcomes["a_error"] = str(exc)

            def run_b():
                outcomes["b"] = enqueue_scrape_job(
                    url=url,
                    scrape_type="website",
                    max_results=20,
                    conn=conn_b,
                    reservation_wait_seconds=2.0,
                )

            ta = threading.Thread(target=run_a)
            ta.start()
            self.assertTrue(a_in_enqueue.wait(timeout=3.0))

            tb = threading.Thread(target=run_b)
            tb.start()
            time.sleep(0.05)  # Ensure Caller B is actively waiting on Caller A's reservation
            let_a_fail.set()
            ta.join(timeout=3.0)
            tb.join(timeout=3.0)

        self.assertIn("Transient enqueue failure", outcomes.get("a_error", ""))
        self.assertIn("b", outcomes)
        self.assertFalse(outcomes["b"]["deduplicated"])
        q = get_job_queue(conn=conn_b)
        self.assertEqual(len(q), 1)
        self.assertEqual(q.job_ids, [outcomes["b"]["job_id"]])

    def test_prolonged_enqueue_lease_renewal_and_lost_ownership_error_and_owner_safe_cleanup(self):
        from rq import Queue
        from services.job_queue import (
            JobReservationOwnershipError,
            RESERVING_PREFIX,
            _compare_and_delete_key,
            _compare_and_extend_key,
            compute_job_dedup_key,
        )

        shared_server = fakeredis.FakeServer()
        conn = fakeredis.FakeRedis(server=shared_server)

        # 1. Lease renewal keeps reservation alive during delayed enqueue (TTL approaches expiry)
        url_renew = "https://lease-renew.example.com"
        dedup_renew = compute_job_dedup_key(url=url_renew, scrape_type="website", max_results=20)
        orig_enqueue = Queue.enqueue
        extend_calls = {"count": 0}
        orig_extend = _compare_and_extend_key
        renewed_evt = threading.Event()

        def tracked_extend(c, k, expected, ex):
            ok = orig_extend(c, k, expected, ex)
            if ok and k == dedup_renew:
                extend_calls["count"] += 1
                renewed_evt.set()
            return ok

        def slow_enqueue_until_renewed(self_q, *args, **kwargs):
            # Hold until background lease renewer has renewed at least once
            self.assertTrue(renewed_evt.wait(timeout=2.0))
            return orig_enqueue(self_q, *args, **kwargs)

        with patch("services.job_queue._compare_and_extend_key", side_effect=tracked_extend), \
             patch.object(Queue, "enqueue", slow_enqueue_until_renewed):
            res_renewed = enqueue_scrape_job(
                url=url_renew,
                scrape_type="website",
                max_results=20,
                conn=conn,
                reservation_ttl_seconds=2,
                lease_renew_interval_seconds=0.05,
            )

        self.assertGreaterEqual(extend_calls["count"], 1)
        self.assertFalse(res_renewed["deduplicated"])
        self.assertEqual(conn.get(dedup_renew).decode("utf-8"), res_renewed["job_id"])

        # 2. Reservation ownership lost before promotion -> MUST raise JobReservationOwnershipError
        # (never silently report success, and never overwrite another owner's reservation)
        url_lost = "https://lost-ownership.example.com"
        dedup_lost = compute_job_dedup_key(url=url_lost, scrape_type="website", max_results=20)
        hijack_val = f"{RESERVING_PREFIX}other-active-owner"

        def enqueue_while_ownership_lost(self_q, *args, **kwargs):
            j = orig_enqueue(self_q, *args, **kwargs)
            # Simulate external ownership takeover before promotion
            conn.set(dedup_lost, hijack_val, ex=300)
            return j

        with patch.object(Queue, "enqueue", enqueue_while_ownership_lost):
            with self.assertRaises(JobReservationOwnershipError):
                enqueue_scrape_job(url=url_lost, scrape_type="website", max_results=20, conn=conn)

        # Other owner's reservation must remain intact (not overwritten!)
        self.assertEqual(conn.get(dedup_lost).decode("utf-8"), hijack_val)

        # 3. Enqueue failure cleanup never deletes another owner's reservation
        url_owner_safe = "https://owner-safe.example.com"
        dedup_safe = compute_job_dedup_key(url=url_owner_safe, scrape_type="website", max_results=20)
        other_owner_val = f"{RESERVING_PREFIX}other-caller-job-id"

        def fail_after_owner_swap(self_q, *args, **kwargs):
            conn.set(dedup_safe, other_owner_val, ex=300)
            raise RuntimeError("Simulated delayed enqueue failure")

        with patch.object(Queue, "enqueue", fail_after_owner_swap):
            with self.assertRaises(RuntimeError):
                enqueue_scrape_job(url=url_owner_safe, scrape_type="website", max_results=20, conn=conn)

        self.assertEqual(conn.get(dedup_safe).decode("utf-8"), other_owner_val)
        self.assertFalse(_compare_and_delete_key(conn, dedup_safe, f"{RESERVING_PREFIX}wrong-id"))
        self.assertEqual(conn.get(dedup_safe).decode("utf-8"), other_owner_val)
        self.assertTrue(_compare_and_delete_key(conn, dedup_safe, other_owner_val))
        self.assertIsNone(conn.get(dedup_safe))

    def test_ambiguous_enqueue_reconciles_persisted_active_job_and_deduplicates_second_caller(self):
        from rq import Queue
        from rq.job import Job, JobStatus
        from services.job_queue import compute_job_dedup_key

        shared_server = fakeredis.FakeServer()
        conn1 = fakeredis.FakeRedis(server=shared_server)
        conn2 = fakeredis.FakeRedis(server=shared_server)
        orig_enqueue = Queue.enqueue

        # Case 1: Job persisted as `queued`, then client experiences lost response / timeout
        url_queued = "https://ambiguous-persisted-queued.example.com"
        dedup_queued = compute_job_dedup_key(url=url_queued, scrape_type="maps", max_results=20)
        persisted_ids = []

        def persist_then_timeout(self_q, *args, **kwargs):
            created = orig_enqueue(self_q, *args, **kwargs)
            persisted_ids.append(created.id)
            raise TimeoutError("Simulated Redis client read timeout after server write")

        with patch.object(Queue, "enqueue", persist_then_timeout):
            first = enqueue_scrape_job(url=url_queued, scrape_type="maps", max_results=20, conn=conn1)

        self.assertEqual(len(persisted_ids), 1)
        self.assertEqual(first["job_id"], persisted_ids[0])
        self.assertEqual(first["status"], "queued")
        self.assertFalse(first["deduplicated"])
        # Reservation must be promoted to the confirmed job_id
        self.assertEqual(conn1.get(dedup_queued).decode("utf-8"), persisted_ids[0])

        # Second caller submitting the same payload MUST resolve to the same active job (no duplicate)
        second = enqueue_scrape_job(url=url_queued, scrape_type="maps", max_results=20, conn=conn2)
        self.assertTrue(second["deduplicated"])
        self.assertEqual(second["job_id"], persisted_ids[0])
        self.assertEqual(second["status"], "queued")
        q = get_job_queue(conn=conn1)
        self.assertEqual(len(q), 1)
        self.assertEqual(q.job_ids, [persisted_ids[0]])

        # Case 2: Job persisted and already picked up by worker (`started`) before reconciliation
        url_started = "https://ambiguous-persisted-started.example.com"
        dedup_started = compute_job_dedup_key(url=url_started, scrape_type="website", max_results=20)
        started_ids = []

        def persist_started_then_drop(self_q, *args, **kwargs):
            created = orig_enqueue(self_q, *args, **kwargs)
            created.set_status(JobStatus.STARTED)
            started_ids.append(created.id)
            raise ConnectionError("Simulated dropped TCP response after enqueue")

        with patch.object(Queue, "enqueue", persist_started_then_drop):
            reconciled_started = enqueue_scrape_job(
                url=url_started,
                scrape_type="website",
                max_results=20,
                conn=conn1,
            )

        self.assertEqual(reconciled_started["job_id"], started_ids[0])
        self.assertEqual(reconciled_started["status"], "started")
        self.assertFalse(reconciled_started["deduplicated"])
        self.assertEqual(conn1.get(dedup_started).decode("utf-8"), started_ids[0])
        # Second caller deduplicates against the reconciled started job
        follow_up = enqueue_scrape_job(url=url_started, scrape_type="website", max_results=20, conn=conn2)
        self.assertTrue(follow_up["deduplicated"])
        self.assertEqual(follow_up["job_id"], started_ids[0])
        self.assertEqual(follow_up["status"], "started")
        self.assertIsNotNone(Job.fetch(started_ids[0], connection=conn1))

    def test_ambiguous_enqueue_absent_job_releases_reservation_and_preserves_error(self):
        from rq import Queue
        from services.job_queue import compute_job_dedup_key

        conn = fakeredis.FakeRedis()
        url = "https://ambiguous-absent.example.com"
        dedup_key = compute_job_dedup_key(url=url, scrape_type="website", max_results=20)

        def fail_before_write(self_q, *args, **kwargs):
            raise RuntimeError("Pre-write serialization error before Redis persist")

        with patch.object(Queue, "enqueue", fail_before_write):
            with self.assertRaisesRegex(RuntimeError, "Pre-write serialization error"):
                enqueue_scrape_job(url=url, scrape_type="website", max_results=20, conn=conn)

        self.assertIsNone(conn.get(dedup_key))
        self.assertEqual(len(get_job_queue(conn=conn)), 0)

    def test_ambiguous_enqueue_redis_unavailable_during_reconciliation_preserves_reservation(self):
        import redis
        from rq import Queue
        from rq.job import Job
        from services.job_queue import (
            QueueUnavailableError,
            RESERVING_PREFIX,
            compute_job_dedup_key,
        )

        conn = fakeredis.FakeRedis()
        url = "https://ambiguous-redis-down.example.com"
        dedup_key = compute_job_dedup_key(url=url, scrape_type="website", max_results=20)

        def fail_enqueue_timeout(self_q, *args, **kwargs):
            raise redis.exceptions.TimeoutError("Socket timeout during enqueue")

        def fail_fetch_down(*args, **kwargs):
            raise redis.exceptions.ConnectionError("Redis unreachable during reconciliation")

        with patch.object(Queue, "enqueue", fail_enqueue_timeout), \
             patch.object(Job, "fetch", side_effect=fail_fetch_down):
            with self.assertRaises(QueueUnavailableError):
                enqueue_scrape_job(url=url, scrape_type="website", max_results=20, conn=conn)

        # Reservation MUST be preserved (not deleted!) because job existence could not be confirmed
        preserved = conn.get(dedup_key)
        self.assertIsNotNone(preserved)
        self.assertTrue(preserved.decode("utf-8").startswith(RESERVING_PREFIX))

        # Verify HTTP API maps this to retryable 503 with NO unconfirmed job_id
        url_api = "https://ambiguous-redis-down-api.example.com"
        dedup_api = compute_job_dedup_key(url=url_api, scrape_type="website", max_results=20)
        with patch("app.validate_and_sanitize_url", side_effect=lambda u: u), \
             patch("services.job_queue.get_redis_connection", return_value=conn), \
             patch.object(Queue, "enqueue", fail_enqueue_timeout), \
             patch.object(Job, "fetch", side_effect=fail_fetch_down):
            resp = self.client.post(
                "/api/jobs",
                json={"url": url_api, "scrape_type": "website"},
                headers=self.auth,
            )
            self.assertEqual(resp.status_code, 503)
            body = resp.get_json()
            self.assertEqual(body["code"], "queue_unavailable")
            self.assertNotIn("job_id", body)
        self.assertIsNotNone(conn.get(dedup_api))
        self.assertTrue(conn.get(dedup_api).decode("utf-8").startswith(RESERVING_PREFIX))

        # Also verify Redis failure during status inspection after Job.fetch preserves reservation
        url_status_down = "https://ambiguous-status-down.example.com"
        dedup_status = compute_job_dedup_key(url=url_status_down, scrape_type="website", max_results=20)
        orig_enqueue = Queue.enqueue

        def persist_then_timeout(self_q, *args, **kwargs):
            orig_enqueue(self_q, *args, **kwargs)
            raise redis.exceptions.TimeoutError("Socket timeout after write")

        with patch.object(Queue, "enqueue", persist_then_timeout), \
             patch("services.job_queue._normalize_job_status", side_effect=redis.exceptions.ConnectionError("Status read failed")):
            with self.assertRaises(QueueUnavailableError):
                enqueue_scrape_job(url=url_status_down, scrape_type="website", max_results=20, conn=conn)
        self.assertIsNotNone(conn.get(dedup_status))
        self.assertTrue(conn.get(dedup_status).decode("utf-8").startswith(RESERVING_PREFIX))

    def test_ambiguous_enqueue_never_overwrites_or_deletes_another_owners_reservation(self):
        from rq import Queue
        from rq.job import JobStatus
        from services.job_queue import (
            JobReservationOwnershipError,
            RESERVING_PREFIX,
            compute_job_dedup_key,
        )

        conn = fakeredis.FakeRedis()
        orig_enqueue = Queue.enqueue
        other_owner = f"{RESERVING_PREFIX}other-owner-job-id"

        # Case 1: Persisted active job, but another caller replaced dedup_key before reconciliation
        url_active = "https://ambiguous-hijack-active.example.com"
        dedup_active = compute_job_dedup_key(url=url_active, scrape_type="website", max_results=20)

        def persist_active_hijack_and_raise(self_q, *args, **kwargs):
            orig_enqueue(self_q, *args, **kwargs)
            conn.set(dedup_active, other_owner, ex=300)
            raise TimeoutError("Lost response after active enqueue")

        with patch.object(Queue, "enqueue", persist_active_hijack_and_raise):
            with self.assertRaises(JobReservationOwnershipError):
                enqueue_scrape_job(url=url_active, scrape_type="website", max_results=20, conn=conn)
        self.assertEqual(conn.get(dedup_active).decode("utf-8"), other_owner)

        # Case 2: Absent job, another caller replaced dedup_key before cleanup
        url_absent = "https://ambiguous-hijack-absent.example.com"
        dedup_absent = compute_job_dedup_key(url=url_absent, scrape_type="website", max_results=20)

        def absent_hijack_and_raise(self_q, *args, **kwargs):
            conn.set(dedup_absent, other_owner, ex=300)
            raise RuntimeError("Enqueue failed before persist")

        with patch.object(Queue, "enqueue", absent_hijack_and_raise):
            with self.assertRaises(RuntimeError):
                enqueue_scrape_job(url=url_absent, scrape_type="website", max_results=20, conn=conn)
        self.assertEqual(conn.get(dedup_absent).decode("utf-8"), other_owner)

        # Case 3: Persisted terminal job, another caller replaced dedup_key before reconciliation
        url_term = "https://ambiguous-hijack-terminal.example.com"
        dedup_term = compute_job_dedup_key(url=url_term, scrape_type="website", max_results=20)

        def persist_terminal_hijack_and_raise(self_q, *args, **kwargs):
            created = orig_enqueue(self_q, *args, **kwargs)
            created.set_status(JobStatus.FINISHED)
            conn.set(dedup_term, other_owner, ex=300)
            raise TimeoutError("Lost response after job already finished")

        with patch.object(Queue, "enqueue", persist_terminal_hijack_and_raise):
            with self.assertRaises(JobReservationOwnershipError):
                enqueue_scrape_job(url=url_term, scrape_type="website", max_results=20, conn=conn)
        self.assertEqual(conn.get(dedup_term).decode("utf-8"), other_owner)

    def test_ambiguous_enqueue_reconciles_terminal_job_without_reporting_active_or_duplicating(self):
        from rq import Queue
        from rq.job import JobStatus
        from services.job_queue import compute_job_dedup_key

        conn = fakeredis.FakeRedis()
        orig_enqueue = Queue.enqueue

        for terminal_status, label in [
            (JobStatus.FINISHED, "finished"),
            (JobStatus.FAILED, "failed"),
        ]:
            url = f"https://ambiguous-terminal-{label}.example.com"
            dedup_key = compute_job_dedup_key(url=url, scrape_type="website", max_results=20)
            created_ids = []

            def persist_terminal_then_timeout(self_q, *args, _st=terminal_status, _ids=created_ids, **kwargs):
                created = orig_enqueue(self_q, *args, **kwargs)
                created.set_status(_st)
                _ids.append(created.id)
                raise TimeoutError(f"Lost response after job transitioned to {_st}")

            with patch.object(Queue, "enqueue", persist_terminal_then_timeout):
                with self.assertRaisesRegex(TimeoutError, "Lost response"):
                    enqueue_scrape_job(url=url, scrape_type="website", max_results=20, conn=conn)

            # Own reservation MUST be cleanly released (not stuck on a terminal job)
            self.assertIsNone(conn.get(dedup_key))
            self.assertEqual(len(created_ids), 1)

            # Subsequent fresh submission succeeds cleanly with a new job ID
            fresh = enqueue_scrape_job(url=url, scrape_type="website", max_results=20, conn=conn)
            self.assertFalse(fresh["deduplicated"])
            self.assertNotEqual(fresh["job_id"], created_ids[0])
            self.assertEqual(fresh["status"], "queued")
            self.assertEqual(conn.get(dedup_key).decode("utf-8"), fresh["job_id"])

    def test_strict_cas_and_delete_helpers_distinguish_match_mismatch_and_redis_unavailable(self):
        import redis
        from services.job_queue import (
            QueueUnavailableError,
            _compare_and_delete_key,
            _compare_and_delete_key_strict,
            _compare_and_swap_key,
            _compare_and_swap_key_strict,
        )

        conn = fakeredis.FakeRedis()
        conn.set("k:cas", "owner-1", ex=60)
        conn.set("k:del", "owner-1", ex=60)

        # 1. Genuine mismatch -> False (key untouched)
        self.assertFalse(_compare_and_swap_key_strict(conn, "k:cas", "wrong-owner", "new-val", ex=60))
        self.assertEqual(conn.get("k:cas").decode("utf-8"), "owner-1")
        self.assertFalse(_compare_and_delete_key_strict(conn, "k:del", "wrong-owner"))
        self.assertEqual(conn.get("k:del").decode("utf-8"), "owner-1")

        # 2. Redis unavailable on Lua EVAL path -> strict raises QueueUnavailableError; legacy returns False
        with patch.object(conn, "eval", side_effect=redis.exceptions.ConnectionError("Redis connection dropped")):
            with self.assertRaises(QueueUnavailableError):
                _compare_and_swap_key_strict(conn, "k:cas", "owner-1", "new-val", ex=60)
            with self.assertRaises(QueueUnavailableError):
                _compare_and_delete_key_strict(conn, "k:del", "owner-1")
            # Legacy helpers preserve backward-compatible False return
            self.assertFalse(_compare_and_swap_key(conn, "k:cas", "owner-1", "new-val", ex=60))
            self.assertFalse(_compare_and_delete_key(conn, "k:del", "owner-1"))
        self.assertEqual(conn.get("k:cas").decode("utf-8"), "owner-1")
        self.assertEqual(conn.get("k:del").decode("utf-8"), "owner-1")

        # 3. Redis non-EVAL ResponseError -> strict raises QueueUnavailableError
        with patch.object(conn, "eval", side_effect=redis.exceptions.ResponseError("READONLY replica")):
            with self.assertRaises(QueueUnavailableError):
                _compare_and_swap_key_strict(conn, "k:cas", "owner-1", "new-val", ex=60)
            with self.assertRaises(QueueUnavailableError):
                _compare_and_delete_key_strict(conn, "k:del", "owner-1")

        # 4. Redis unavailable on WATCH/MULTI/EXEC fallback path -> strict raises QueueUnavailableError
        with patch.object(conn, "pipeline", side_effect=redis.exceptions.ConnectionError("Pipeline down")):
            with self.assertRaises(QueueUnavailableError):
                _compare_and_swap_key_strict(conn, "k:cas", "owner-1", "new-val", ex=60)
            with self.assertRaises(QueueUnavailableError):
                _compare_and_delete_key_strict(conn, "k:del", "owner-1")
        self.assertEqual(conn.get("k:cas").decode("utf-8"), "owner-1")
        self.assertEqual(conn.get("k:del").decode("utf-8"), "owner-1")

        # 5. Genuine match -> True (atomic update/delete succeeds)
        self.assertTrue(_compare_and_swap_key_strict(conn, "k:cas", "owner-1", "promoted-val", ex=60))
        self.assertEqual(conn.get("k:cas").decode("utf-8"), "promoted-val")
        self.assertTrue(_compare_and_delete_key_strict(conn, "k:del", "owner-1"))
        self.assertIsNone(conn.get("k:del"))

    def test_redis_connection_failure_during_active_promotion_returns_503_and_preserves_reservation(self):
        import redis
        from rq import Queue
        from services.job_queue import RESERVING_PREFIX, compute_job_dedup_key

        orig_enqueue = Queue.enqueue

        # Verify BOTH real-Redis Lua EVAL failure path and WATCH/MULTI/EXEC pipeline fallback failure path
        for failure_mode in ("eval_error", "pipeline_error"):
            conn = fakeredis.FakeRedis()
            url = f"https://active-promote-redis-down-{failure_mode}.example.com"
            dedup_key = compute_job_dedup_key(url=url, scrape_type="website", max_results=20)
            armed = {"fail_cas": False}
            orig_eval = conn.eval
            orig_pipeline = conn.pipeline

            def persist_active_then_arm_and_timeout(self_q, *args, _armed=armed, **kwargs):
                orig_enqueue(self_q, *args, **kwargs)
                _armed["fail_cas"] = True
                raise TimeoutError("Lost response after active enqueue")

            def maybe_fail_eval(*args, _armed=armed, _orig=orig_eval, **kwargs):
                if _armed["fail_cas"]:
                    raise redis.exceptions.ConnectionError("Redis disconnected during CAS promotion")
                return _orig(*args, **kwargs)

            def maybe_fail_pipeline(*args, _armed=armed, _orig=orig_pipeline, **kwargs):
                if _armed["fail_cas"]:
                    raise redis.exceptions.ConnectionError("Redis pipeline disconnected during CAS promotion")
                return _orig(*args, **kwargs)

            target_attr = "eval" if failure_mode == "eval_error" else "pipeline"
            side_effect_fn = maybe_fail_eval if failure_mode == "eval_error" else maybe_fail_pipeline

            with patch("app.validate_and_sanitize_url", side_effect=lambda u: u), \
                 patch("services.job_queue.get_redis_connection", return_value=conn), \
                 patch.object(Queue, "enqueue", persist_active_then_arm_and_timeout), \
                 patch.object(conn, target_attr, side_effect=side_effect_fn):
                resp = self.client.post(
                    "/api/jobs",
                    json={"url": url, "scrape_type": "website"},
                    headers=self.auth,
                )

            self.assertEqual(resp.status_code, 503, f"Expected 503 for {failure_mode}")
            body = resp.get_json()
            self.assertEqual(body["code"], "queue_unavailable")
            self.assertNotIn("job_id", body)
            # Reservation MUST NOT be deleted when Redis fails during promotion
            preserved = conn.get(dedup_key)
            self.assertIsNotNone(preserved)
            self.assertTrue(preserved.decode("utf-8").startswith(RESERVING_PREFIX))

    def test_redis_connection_failure_during_terminal_cleanup_returns_503_and_preserves_reservation(self):
        import redis
        from rq import Queue
        from rq.job import JobStatus
        from services.job_queue import RESERVING_PREFIX, compute_job_dedup_key

        orig_enqueue = Queue.enqueue

        for failure_mode in ("eval_error", "pipeline_error"):
            conn = fakeredis.FakeRedis()
            url = f"https://terminal-cleanup-redis-down-{failure_mode}.example.com"
            dedup_key = compute_job_dedup_key(url=url, scrape_type="website", max_results=20)
            armed = {"fail_del": False}
            orig_eval = conn.eval
            orig_pipeline = conn.pipeline

            def persist_terminal_then_arm_and_timeout(self_q, *args, _armed=armed, **kwargs):
                created = orig_enqueue(self_q, *args, **kwargs)
                created.set_status(JobStatus.FINISHED)
                _armed["fail_del"] = True
                raise TimeoutError("Lost response after job finished")

            def maybe_fail_eval(*args, _armed=armed, _orig=orig_eval, **kwargs):
                if _armed["fail_del"]:
                    raise redis.exceptions.ConnectionError("Redis disconnected during terminal cleanup")
                return _orig(*args, **kwargs)

            def maybe_fail_pipeline(*args, _armed=armed, _orig=orig_pipeline, **kwargs):
                if _armed["fail_del"]:
                    raise redis.exceptions.ConnectionError("Redis pipeline disconnected during terminal cleanup")
                return _orig(*args, **kwargs)

            target_attr = "eval" if failure_mode == "eval_error" else "pipeline"
            side_effect_fn = maybe_fail_eval if failure_mode == "eval_error" else maybe_fail_pipeline

            with patch("app.validate_and_sanitize_url", side_effect=lambda u: u), \
                 patch("services.job_queue.get_redis_connection", return_value=conn), \
                 patch.object(Queue, "enqueue", persist_terminal_then_arm_and_timeout), \
                 patch.object(conn, target_attr, side_effect=side_effect_fn):
                resp = self.client.post(
                    "/api/jobs",
                    json={"url": url, "scrape_type": "website"},
                    headers=self.auth,
                )

            self.assertEqual(resp.status_code, 503, f"Expected 503 for {failure_mode}")
            body = resp.get_json()
            self.assertEqual(body["code"], "queue_unavailable")
            self.assertNotIn("job_id", body)
            # Reservation MUST NOT be deleted when Redis fails during terminal cleanup
            preserved = conn.get(dedup_key)
            self.assertIsNotNone(preserved)
            self.assertTrue(preserved.decode("utf-8").startswith(RESERVING_PREFIX))

    def test_genuine_cas_and_delete_ownership_mismatches_return_409_and_preserve_other_owner(self):
        from rq import Queue
        from rq.job import JobStatus
        from services.job_queue import RESERVING_PREFIX, compute_job_dedup_key

        conn = fakeredis.FakeRedis()
        orig_enqueue = Queue.enqueue
        other_owner = f"{RESERVING_PREFIX}other-legitimate-owner"

        # 1. Genuine CAS ownership mismatch during active-job promotion -> HTTP 409 (NOT 503)
        url_cas = "https://genuine-cas-mismatch-http409.example.com"
        dedup_cas = compute_job_dedup_key(url=url_cas, scrape_type="website", max_results=20)

        def persist_active_and_swap_owner(self_q, *args, **kwargs):
            orig_enqueue(self_q, *args, **kwargs)
            conn.set(dedup_cas, other_owner, ex=300)
            raise TimeoutError("Lost response after active enqueue while ownership changed")

        with patch("app.validate_and_sanitize_url", side_effect=lambda u: u), \
             patch("services.job_queue.get_redis_connection", return_value=conn), \
             patch.object(Queue, "enqueue", persist_active_and_swap_owner):
            resp_cas = self.client.post(
                "/api/jobs",
                json={"url": url_cas, "scrape_type": "website"},
                headers=self.auth,
            )

        self.assertEqual(resp_cas.status_code, 409)
        body_cas = resp_cas.get_json()
        self.assertEqual(body_cas["code"], "reservation_ownership_lost")
        self.assertTrue(body_cas["retryable"])
        self.assertNotIn("job_id", body_cas)
        self.assertEqual(conn.get(dedup_cas).decode("utf-8"), other_owner)

        # 2. Genuine owner-safe delete mismatch during terminal-job reconciliation -> HTTP 409 (NOT 503)
        url_del = "https://genuine-delete-mismatch-http409.example.com"
        dedup_del = compute_job_dedup_key(url=url_del, scrape_type="website", max_results=20)

        def persist_terminal_and_swap_owner(self_q, *args, **kwargs):
            created = orig_enqueue(self_q, *args, **kwargs)
            created.set_status(JobStatus.FINISHED)
            conn.set(dedup_del, other_owner, ex=300)
            raise TimeoutError("Lost response after terminal job while ownership changed")

        with patch("app.validate_and_sanitize_url", side_effect=lambda u: u), \
             patch("services.job_queue.get_redis_connection", return_value=conn), \
             patch.object(Queue, "enqueue", persist_terminal_and_swap_owner):
            resp_del = self.client.post(
                "/api/jobs",
                json={"url": url_del, "scrape_type": "website"},
                headers=self.auth,
            )

        self.assertEqual(resp_del.status_code, 409)
        body_del = resp_del.get_json()
        self.assertEqual(body_del["code"], "reservation_ownership_lost")
        self.assertTrue(body_del["retryable"])
        self.assertNotIn("job_id", body_del)
        # Other owner's reservation MUST remain completely untouched
        self.assertEqual(conn.get(dedup_del).decode("utf-8"), other_owner)

    def test_watch_retry_exhaustion_raises_queue_unavailable_and_legacy_returns_false(self):
        import redis
        from rq import Queue
        from services.job_queue import (
            QueueUnavailableError,
            RESERVING_PREFIX,
            _compare_and_delete_key,
            _compare_and_delete_key_strict,
            _compare_and_swap_key,
            _compare_and_swap_key_strict,
            compute_job_dedup_key,
        )

        conn = fakeredis.FakeRedis()
        conn.set("k:watch:cas", "owner-1", ex=60)
        conn.set("k:watch:del", "owner-1", ex=60)
        conn.set("k:watch:other", "other-owner-value", ex=60)
        orig_pipeline = conn.pipeline

        class _AlwaysWatchErrorPipeline:
            def __init__(self, real_pipe, counter):
                self._pipe = real_pipe
                self._counter = counter

            def __enter__(self):
                self._pipe.__enter__()
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                return self._pipe.__exit__(exc_type, exc_val, exc_tb)

            def watch(self, *names):
                return self._pipe.watch(*names)

            def unwatch(self):
                return self._pipe.unwatch()

            def get(self, name):
                return self._pipe.get(name)

            def multi(self):
                return self._pipe.multi()

            def set(self, *args, **kwargs):
                return self._pipe.set(*args, **kwargs)

            def delete(self, *args, **kwargs):
                return self._pipe.delete(*args, **kwargs)

            def execute(self):
                self._counter["attempts"] += 1
                raise redis.WatchError("Simulated concurrent modification on watched key")

        # 1. _compare_and_swap_key_strict exhausts all 10 WATCH retries -> QueueUnavailableError
        cas_counter = {"attempts": 0}
        with patch.object(conn, "pipeline", side_effect=lambda: _AlwaysWatchErrorPipeline(orig_pipeline(), cas_counter)):
            with self.assertRaises(QueueUnavailableError):
                _compare_and_swap_key_strict(conn, "k:watch:cas", "owner-1", "promoted-val", ex=60)
        self.assertEqual(cas_counter["attempts"], 10)
        self.assertEqual(conn.get("k:watch:cas").decode("utf-8"), "owner-1")
        self.assertEqual(conn.get("k:watch:other").decode("utf-8"), "other-owner-value")

        # 2. _compare_and_delete_key_strict exhausts all 10 WATCH retries -> QueueUnavailableError
        del_counter = {"attempts": 0}
        with patch.object(conn, "pipeline", side_effect=lambda: _AlwaysWatchErrorPipeline(orig_pipeline(), del_counter)):
            with self.assertRaises(QueueUnavailableError):
                _compare_and_delete_key_strict(conn, "k:watch:del", "owner-1")
        self.assertEqual(del_counter["attempts"], 10)
        self.assertEqual(conn.get("k:watch:del").decode("utf-8"), "owner-1")
        self.assertEqual(conn.get("k:watch:other").decode("utf-8"), "other-owner-value")

        # 3. Legacy wrappers still convert strict WatchError exhaustion into False (no mutation)
        legacy_cas_counter = {"attempts": 0}
        with patch.object(
            conn, "pipeline", side_effect=lambda: _AlwaysWatchErrorPipeline(orig_pipeline(), legacy_cas_counter)
        ):
            self.assertFalse(_compare_and_swap_key(conn, "k:watch:cas", "owner-1", "promoted-val", ex=60))
        self.assertEqual(legacy_cas_counter["attempts"], 10)
        self.assertEqual(conn.get("k:watch:cas").decode("utf-8"), "owner-1")

        legacy_del_counter = {"attempts": 0}
        with patch.object(
            conn, "pipeline", side_effect=lambda: _AlwaysWatchErrorPipeline(orig_pipeline(), legacy_del_counter)
        ):
            self.assertFalse(_compare_and_delete_key(conn, "k:watch:del", "owner-1"))
        self.assertEqual(legacy_del_counter["attempts"], 10)
        self.assertEqual(conn.get("k:watch:del").decode("utf-8"), "owner-1")

        # 4. End-to-end API mapping: WATCH exhaustion during active promotion returns HTTP 503 (NOT 409)
        url_watch = "https://watch-exhaustion-http503.example.com"
        dedup_watch = compute_job_dedup_key(url=url_watch, scrape_type="website", max_results=20)
        orig_enqueue = Queue.enqueue
        armed = {"watch_fail": False}
        api_counter = {"attempts": 0}

        def persist_then_arm_watch(self_q, *args, **kwargs):
            orig_enqueue(self_q, *args, **kwargs)
            armed["watch_fail"] = True
            raise TimeoutError("Lost response after active enqueue")

        def maybe_watch_conflict_pipeline(*args, **kwargs):
            real_pipe = orig_pipeline(*args, **kwargs)
            if armed["watch_fail"]:
                return _AlwaysWatchErrorPipeline(real_pipe, api_counter)
            return real_pipe

        with patch("app.validate_and_sanitize_url", side_effect=lambda u: u), \
             patch("services.job_queue.get_redis_connection", return_value=conn), \
             patch.object(Queue, "enqueue", persist_then_arm_watch), \
             patch.object(conn, "pipeline", side_effect=maybe_watch_conflict_pipeline):
            resp = self.client.post(
                "/api/jobs",
                json={"url": url_watch, "scrape_type": "website"},
                headers=self.auth,
            )

        self.assertEqual(api_counter["attempts"], 10)
        self.assertEqual(resp.status_code, 503)
        body = resp.get_json()
        self.assertEqual(body["code"], "queue_unavailable")
        self.assertNotIn("job_id", body)
        preserved = conn.get(dedup_watch)
        self.assertIsNotNone(preserved)
        self.assertTrue(preserved.decode("utf-8").startswith(RESERVING_PREFIX))


# =============================================================================
# 2. CONCURRENCY, BROWSER LAUNCH FLAGS & DETERMINISTIC CLEANUP
# =============================================================================


class TestBrowserConcurrencyAndCleanup(_BasePhase101BTestCase):
    def test_chromium_launch_args_include_disable_dev_shm_usage_and_conditional_sandbox(self):
        os.environ["CHROMIUM_NO_SANDBOX"] = "false"
        with patch("services.browser_runtime.is_running_in_container", return_value=False):
            args_local = get_chromium_launch_args()
            self.assertIn("--disable-dev-shm-usage", args_local)
            self.assertIn("--disable-gpu", args_local)
            self.assertNotIn("--no-sandbox", args_local)

        with patch("services.browser_runtime.is_running_in_container", return_value=True):
            args_container = get_chromium_launch_args()
            self.assertIn("--disable-dev-shm-usage", args_container)
            self.assertIn("--no-sandbox", args_container)
            self.assertIn("--disable-setuid-sandbox", args_container)

    def test_bounded_browser_concurrency_and_timeout_under_concurrent_requests(self):
        os.environ["BROWSER_MAX_CONCURRENCY"] = "1"
        reset_browser_concurrency_state()

        started_evt = threading.Event()
        release_evt = threading.Event()
        errors = []

        def hold_slot():
            with acquire_browser_slot(timeout=2.0):
                started_evt.set()
                release_evt.wait(timeout=3.0)

        t = threading.Thread(target=hold_slot)
        t.start()
        self.assertTrue(started_evt.wait(timeout=2.0))
        self.assertEqual(get_active_browser_count(), 1)

        # Second concurrent caller times out cleanly with BrowserConcurrencyError
        with self.assertRaises(BrowserConcurrencyError):
            with acquire_browser_slot(timeout=0.15):
                pass

        release_evt.set()
        t.join(timeout=2.0)
        self.assertEqual(get_active_browser_count(), 0)

        # Multiple concurrent scraping job submissions succeed cleanly without race conditions
        with patch("app.validate_and_sanitize_url", side_effect=lambda u: u):
            def submit_one(i):
                res = enqueue_scrape_job(
                    url=f"https://biz-{i}.example.com",
                    scrape_type="website",
                    conn=self.fake_redis,
                )
                return res["job_id"]

            with ThreadPoolExecutor(max_workers=5) as ex:
                ids = list(ex.map(submit_one, range(5)))
            self.assertEqual(len(set(ids)), 5)

    def test_playwright_cleanup_and_slot_release_on_crash_and_proxy_shutdown(self):
        os.environ["BROWSER_MAX_CONCURRENCY"] = "1"
        reset_browser_concurrency_state()

        mock_page = MagicMock()
        mock_page.goto.side_effect = TimeoutError("Navigation timed out")
        mock_context = MagicMock()
        mock_context.new_page.return_value = mock_page
        mock_browser = MagicMock()
        mock_browser.new_context.return_value = mock_context

        mock_pw = MagicMock()
        mock_pw.chromium.launch.return_value = mock_browser
        mock_pw_cm = MagicMock()
        mock_pw_cm.__enter__.return_value = mock_pw
        mock_pw_cm.__exit__.return_value = False

        with patch("services.website_crawler.validate_and_sanitize_url", side_effect=lambda u: u), \
             patch("services.website_crawler.sync_playwright", return_value=mock_pw_cm):
            res = scrape_with_playwright_fallback("https://slow-site.example.com")

        self.assertEqual(res[0], "")
        # Chromium launched with container-safe args
        _, launch_kwargs = mock_pw.chromium.launch.call_args
        self.assertTrue(launch_kwargs["headless"])
        self.assertIn("--disable-dev-shm-usage", launch_kwargs["args"])
        # All Playwright resources closed and concurrency slot released
        mock_page.close.assert_called_once()
        mock_context.close.assert_called_once()
        mock_browser.close.assert_called_once()
        self.assertEqual(get_active_browser_count(), 0)

        # SafeBrowserProxy uses bounded ThreadPoolExecutor and cleans up cleanly on exit
        with SafeBrowserProxy(allow_public_hosts=True, max_worker_threads=8) as proxy:
            self.assertIsNotNone(proxy._executor)
        self.assertIsNone(proxy._executor)


# =============================================================================
# 3. MULTI-WORKER SHARED REDIS RATE LIMITER & TRUSTED PROXY HOPS
# =============================================================================


class TestMultiWorkerRateLimiterAndProxyFix(_BasePhase101BTestCase):
    def test_rate_limit_consistent_across_multiple_web_workers_sharing_redis(self):
        os.environ["RATE_LIMIT_MAX_REQUESTS"] = "4"
        os.environ["RATE_LIMIT_WINDOW_SECONDS"] = "60"

        # Two independent rate limiter instances simulating 2 Gunicorn worker processes
        worker_a = SharedSlidingWindowRateLimiter(redis_client=self.fake_redis)
        worker_b = SharedSlidingWindowRateLimiter(redis_client=self.fake_redis)

        self.assertEqual(worker_a.check("198.51.100.10")[0], True)
        self.assertEqual(worker_b.check("198.51.100.10")[0], True)
        self.assertEqual(worker_a.check("198.51.100.10")[0], True)
        self.assertEqual(worker_b.check("198.51.100.10")[0], True)

        # 5th request hits shared limit on BOTH workers
        allowed_a, retry_a = worker_a.check("198.51.100.10")
        allowed_b, retry_b = worker_b.check("198.51.100.10")
        self.assertFalse(allowed_a)
        self.assertFalse(allowed_b)
        self.assertGreaterEqual(retry_a, 1)
        self.assertGreaterEqual(retry_b, 1)

        # Different client IP is unaffected
        self.assertTrue(worker_a.check("203.0.113.55")[0])

    @patch("app.crawl_and_audit_website", return_value={"Website": "https://example.com", "Email": ""})
    def test_trusted_proxy_hops_opt_in_behavior(self, _mock_crawl):
        os.environ["RATE_LIMIT_MAX_REQUESTS"] = "2"
        os.environ["RATE_LIMIT_WINDOW_SECONDS"] = "60"
        rate_limiter.set_redis_client(self.fake_redis)
        rate_limiter.reset()

        # When TRUSTED_PROXY_HOPS=1, distinct clients behind 1 proxy get separate buckets
        apply_trusted_proxy_middleware(app, hops=1)
        for ip in ("198.51.100.1", "198.51.100.1", "198.51.100.2", "198.51.100.2"):
            r = self.client.post(
                "/api/audit",
                json={"url": "https://example.com"},
                headers={**self.auth, "X-Forwarded-For": ip},
            )
            self.assertEqual(r.status_code, 200)

        # 3rd request from client 1 is rate-limited
        r_limit = self.client.post(
            "/api/audit",
            json={"url": "https://example.com"},
            headers={**self.auth, "X-Forwarded-For": "198.51.100.1"},
        )
        self.assertEqual(r_limit.status_code, 429)

        # Invalid TRUSTED_PROXY_HOPS rejected
        with self.assertRaises(ValueError):
            apply_trusted_proxy_middleware(app, hops=-1)
        with self.assertRaises(ValueError):
            apply_trusted_proxy_middleware(app, hops=99)

    def test_redis_rate_limiter_atomic_lua_script_invocation_and_concurrent_saturation(self):
        from services.rate_limiter import SLIDING_WINDOW_LUA_SCRIPT

        os.environ["RATE_LIMIT_MAX_REQUESTS"] = "5"
        os.environ["RATE_LIMIT_WINDOW_SECONDS"] = "60"

        # 1. Verify single atomic Lua EVAL invocation against real-Redis-compatible client
        lua_redis = MagicMock()
        lua_redis.eval.side_effect = [[1, 0], [0, 42]]
        limiter_lua = SharedSlidingWindowRateLimiter(redis_client=lua_redis)

        self.assertEqual(limiter_lua.check("198.51.100.7"), (True, 0))
        self.assertEqual(limiter_lua.check("198.51.100.7"), (False, 42))
        self.assertEqual(lua_redis.eval.call_count, 2)
        first_args = lua_redis.eval.call_args_list[0][0]
        self.assertEqual(first_args[0], SLIDING_WINDOW_LUA_SCRIPT)
        self.assertEqual(first_args[1], 1)
        self.assertEqual(first_args[2], "leadhunter:ratelimit:198.51.100.7")

        # 2. High-concurrency test: 24 simultaneous requests across independent worker limiters
        # sharing one Redis server must allow EXACTLY 5 (zero race overshoot)
        shared_server = fakeredis.FakeServer()
        barrier = threading.Barrier(24)

        def concurrent_hit(_idx):
            conn = fakeredis.FakeRedis(server=shared_server)
            lim = SharedSlidingWindowRateLimiter(redis_client=conn)
            barrier.wait(timeout=3.0)
            return lim.check("203.0.113.88")

        with ThreadPoolExecutor(max_workers=24) as ex:
            outcomes = list(ex.map(concurrent_hit, range(24)))

        allowed_count = sum(1 for allowed, _ in outcomes if allowed)
        blocked = [retry for allowed, retry in outcomes if not allowed]
        self.assertEqual(allowed_count, 5, f"Expected exactly 5 allowed under concurrency, got {allowed_count}")
        self.assertEqual(len(blocked), 19)
        self.assertTrue(all(r >= 1 for r in blocked))

        inspect_conn = fakeredis.FakeRedis(server=shared_server)
        self.assertEqual(inspect_conn.zcard("leadhunter:ratelimit:203.0.113.88"), 5)

    def test_rate_limiter_fails_closed_in_production_and_falls_back_in_local_dev(self):
        os.environ["RATE_LIMIT_MAX_REQUESTS"] = "2"
        os.environ["RATE_LIMIT_WINDOW_SECONDS"] = "60"
        os.environ.pop("RATE_LIMIT_FAIL_CLOSED", None)

        broken_redis = MagicMock()
        broken_redis.eval.side_effect = ConnectionError("Redis connection refused")

        # 1. Production with unreachable Redis -> MUST fail closed (never silently fall back to memory)
        os.environ["LEADHUNTER_ENV"] = "production"
        prod_limiter = SharedSlidingWindowRateLimiter(redis_client=broken_redis)
        allowed, retry_after = prod_limiter.check("198.51.100.20")
        self.assertFalse(allowed)
        self.assertEqual(retry_after, 60)

        # Verify API endpoint returns 429 when production Redis rate limiter fails
        rate_limiter.set_redis_client(broken_redis)
        resp_prod = self.client.post("/api/audit", json={"url": "https://example.com"}, headers=self.auth)
        self.assertEqual(resp_prod.status_code, 429)

        # 2. Production with REDIS_URL unset -> MUST fail closed (never downgrade to per-process memory)
        os.environ.pop("REDIS_URL", None)
        prod_no_redis = SharedSlidingWindowRateLimiter(redis_client=None)
        allowed_no_redis, _ = prod_no_redis.check("198.51.100.21")
        self.assertFalse(allowed_no_redis)

        # 3. Local dev with unreachable Redis -> gracefully falls back to in-memory limiter
        os.environ.pop("LEADHUNTER_ENV", None)
        dev_limiter = SharedSlidingWindowRateLimiter(redis_client=broken_redis)
        self.assertEqual(dev_limiter.check("127.0.0.1"), (True, 0))
        self.assertEqual(dev_limiter.check("127.0.0.1"), (True, 0))
        self.assertEqual(dev_limiter.check("127.0.0.1")[0], False)


# =============================================================================
# 4. HEALTH / READINESS, STARTUP VALIDATION, LOGGING & DEPLOYMENT CONFIG
# =============================================================================


class TestHealthReadinessLoggingAndDeploymentConfig(_BasePhase101BTestCase):
    def test_healthz_and_readyz_endpoints(self):
        # /healthz works unauthenticated
        r_health = self.client.get("/healthz")
        self.assertEqual(r_health.status_code, 200)
        self.assertEqual(json.loads(r_health.data)["status"], "ok")
        self.assertIn("X-Request-ID", r_health.headers)

        # /readyz returns 200 when API key, Redis, and Chromium are ready
        os.environ["REDIS_URL"] = "redis://127.0.0.1:6379/0"
        with patch("app.check_chromium_available", return_value=(True, "Chromium OK")):
            r_ready = self.client.get("/readyz")
            self.assertEqual(r_ready.status_code, 200)
            body = json.loads(r_ready.data)
            self.assertEqual(body["status"], "ready")
            self.assertTrue(body["checks"]["api_key_configured"])
            self.assertTrue(body["checks"]["redis"]["ok"])
            self.assertNotIn("phase10-1b-test-secret-key", r_ready.data.decode("utf-8"))

        # Missing API key -> 503
        os.environ.pop("LEADHUNTER_API_KEY", None)
        with patch("app.check_chromium_available", return_value=(True, "Chromium OK")):
            r_no_key = self.client.get("/readyz")
            self.assertEqual(r_no_key.status_code, 503)
            self.assertFalse(json.loads(r_no_key.data)["checks"]["api_key_configured"])

        # Redis unreachable -> 503
        os.environ["LEADHUNTER_API_KEY"] = "phase10-1b-test-secret-key"
        broken_redis = MagicMock()
        broken_redis.ping.side_effect = ConnectionError("down")
        set_redis_connection(broken_redis)
        with patch("app.check_chromium_available", return_value=(True, "Chromium OK")):
            r_no_redis = self.client.get("/readyz")
            self.assertEqual(r_no_redis.status_code, 503)
            self.assertFalse(json.loads(r_no_redis.data)["checks"]["redis"]["ok"])

        # REQUIRE_ACTIVE_WORKER=true with 0 workers -> 503
        set_redis_connection(self.fake_redis)
        os.environ["REQUIRE_ACTIVE_WORKER"] = "true"
        with patch("app.check_chromium_available", return_value=(True, "Chromium OK")):
            r_no_worker = self.client.get("/readyz")
            self.assertEqual(r_no_worker.status_code, 503)
            self.assertFalse(json.loads(r_no_worker.data)["checks"]["workers"]["ok"])

    def test_startup_env_validation_and_pii_safe_structured_logging(self):
        # Missing required production secret fails clearly without exposing secrets
        os.environ["LEADHUNTER_ENV"] = "production"
        os.environ.pop("LEADHUNTER_API_KEY", None)
        os.environ.pop("REDIS_URL", None)
        with self.assertRaises(RuntimeConfigError) as ctx:
            validate_startup_config(require_api_key_in_prod=True, require_redis_in_prod=True)
        err_text = str(ctx.exception)
        self.assertIn("LEADHUNTER_API_KEY", err_text)
        self.assertIn("REDIS_URL", err_text)

        # Valid production config succeeds
        os.environ["LEADHUNTER_API_KEY"] = "prod-secret-value-never-logged"
        os.environ["REDIS_URL"] = "redis://redis:6379/0"
        summary = validate_startup_config(require_api_key_in_prod=True, require_redis_in_prod=True)
        self.assertTrue(summary["production"])
        self.assertTrue(summary["api_key_configured"])
        self.assertTrue(summary["redis_configured"])

        # PII & URL redaction helpers
        self.assertEqual(redact_email_for_log("owner@company.com"), "present")
        self.assertEqual(redact_email_for_log(""), "none")
        self.assertEqual(
            redact_url_for_log("https://user:pass@example.com/maps?api_key=SECRET123#frag"),
            "https://example.com/maps",
        )

        # Structured JSON log formatting with correlation ID
        os.environ["LOG_FORMAT"] = "json"
        lh_logger = configure_logging()
        stream = io.StringIO()
        lh_logger.handlers[0].stream = stream
        lh_logger.info("structured test event")
        parsed_log = json.loads(stream.getvalue().strip())
        self.assertEqual(parsed_log["message"], "structured test event")
        self.assertIn("request_id", parsed_log)
        self.assertIn("job_id", parsed_log)
        self.assertIn("timestamp", parsed_log)

    def test_deployment_artifacts_and_gunicorn_config_valid(self):
        root = pathlib.Path(__file__).resolve().parent.parent

        # 1. Dockerfile checks
        dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("FROM python:3.12-slim-bookworm", dockerfile)
        self.assertIn("playwright install --with-deps chromium", dockerfile)
        self.assertIn("USER appuser", dockerfile)
        self.assertIn("gunicorn", dockerfile)
        self.assertIn("/healthz", dockerfile)

        # 2. .dockerignore excludes secrets, tests & pilot exports
        dockerignore = (root / ".dockerignore").read_text(encoding="utf-8")
        for pat in (".git/", ".venv/", ".env", "tests/", "*.xlsx", "*.csv", "*.json"):
            self.assertIn(pat, dockerignore)

        # 3. render.yaml uses Docker for web + worker + managed Redis with noeviction
        render_yaml = (root / "render.yaml").read_text(encoding="utf-8")
        self.assertIn("runtime: docker", render_yaml)
        self.assertIn("dockerfilePath: ./Dockerfile", render_yaml)
        self.assertIn("dockerCommand: python worker.py", render_yaml)
        self.assertIn("type: redis", render_yaml)
        self.assertIn("maxmemoryPolicy: noeviction", render_yaml)
        self.assertIn("healthCheckPath: /healthz", render_yaml)
        self.assertIn("LEADHUNTER_API_KEY", render_yaml)
        self.assertNotIn("env: python", render_yaml)

        # 4. requirements.txt pins every package with == and includes certifi, urllib3, redis, rq, whitenoise, gunicorn
        req_lines = [
            ln.strip()
            for ln in (root / "requirements.txt").read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        for ln in req_lines:
            self.assertIn("==", ln, f"Unpinned dependency in requirements.txt: {ln}")
        req_joined = "\n".join(req_lines).lower()
        for pkg in ("flask==", "playwright==", "certifi==", "urllib3==", "redis==", "rq==", "whitenoise==", "gunicorn=="):
            self.assertIn(pkg, req_joined)

        # 5. gunicorn.conf.py loads cleanly and defines expected production settings
        import importlib.util
        spec = importlib.util.spec_from_file_location("gunicorn_conf_test", str(root / "gunicorn.conf.py"))
        gconf = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gconf)
        self.assertTrue(gconf.bind.startswith("0.0.0.0:"))
        self.assertEqual(gconf.worker_class, "gthread")
        self.assertGreaterEqual(gconf.timeout, 30)
        self.assertGreaterEqual(gconf.graceful_timeout, 10)
        self.assertEqual(gconf.accesslog, "-")
        self.assertEqual(gconf.errorlog, "-")

        # 6. worker.py creates a valid RQ worker against FakeRedis & role-aware Docker/Render health checks
        import worker as worker_module
        w = worker_module.create_worker(conn=self.fake_redis)
        self.assertEqual(w.queue_names(), ["leadhunter"])

        # Role-aware Dockerfile HEALTHCHECK & Render config verification (Findings 2 & 4)
        self.assertIn("SERVICE_ROLE", dockerfile)
        self.assertIn("run_worker_healthcheck", dockerfile)
        self.assertIn("RATE_LIMIT_FAIL_CLOSED", render_yaml)
        self.assertIn("value: web", render_yaml)
        self.assertIn("value: worker", render_yaml)

    def test_worker_healthcheck_and_readyz_reflect_registered_and_missing_workers(self):
        import worker as worker_module

        os.environ["LEADHUNTER_ENV"] = "production"
        os.environ["REDIS_URL"] = "redis://127.0.0.1:6379/0"
        os.environ.pop("REQUIRE_ACTIVE_WORKER", None)  # Production defaults to requiring active worker

        # 1. No worker registered -> worker healthcheck False & /readyz returns 503
        healthy_none, details_none = worker_module.run_worker_healthcheck(conn=self.fake_redis)
        self.assertFalse(healthy_none)
        self.assertEqual(details_none["online"], 0)

        with patch("app.check_chromium_available", return_value=(True, "Chromium OK")):
            r_unready = self.client.get("/readyz")
            self.assertEqual(r_unready.status_code, 503)
            body_unready = json.loads(r_unready.data)
            self.assertFalse(body_unready["checks"]["workers"]["ok"])
            self.assertEqual(body_unready["checks"]["workers"]["online"], 0)

        # 2. Register active RQ worker birth + heartbeat -> worker healthcheck True & /readyz returns 200
        rq_worker = worker_module.create_worker(conn=self.fake_redis)
        rq_worker.register_birth()
        rq_worker.heartbeat()
        try:
            healthy_up, details_up = worker_module.run_worker_healthcheck(conn=self.fake_redis)
            self.assertTrue(healthy_up)
            self.assertEqual(details_up["online"], 1)

            with patch("app.check_chromium_available", return_value=(True, "Chromium OK")):
                r_ready = self.client.get("/readyz")
                self.assertEqual(r_ready.status_code, 200)
                body_ready = json.loads(r_ready.data)
                self.assertTrue(body_ready["checks"]["workers"]["ok"])
                self.assertEqual(body_ready["checks"]["workers"]["online"], 1)
        finally:
            rq_worker.register_death()

        # 3. After worker death -> unhealthy again
        healthy_after, details_after = worker_module.run_worker_healthcheck(conn=self.fake_redis)
        self.assertFalse(healthy_after)
        self.assertEqual(details_after["online"], 0)

        # 4. Redis down -> worker healthcheck False cleanly
        broken_redis = MagicMock()
        broken_redis.ping.side_effect = ConnectionError("Redis offline")
        healthy_down, details_down = worker_module.run_worker_healthcheck(conn=broken_redis)
        self.assertFalse(healthy_down)
        self.assertFalse(details_down["redis_ok"])

    def test_worker_heartbeat_freshness_missing_dead_and_exception_fail_closed(self):
        from datetime import datetime, timedelta, timezone
        import worker as worker_module
        from services.job_queue import check_worker_health

        os.environ["LEADHUNTER_ENV"] = "production"
        os.environ["REDIS_URL"] = "redis://127.0.0.1:6379/0"
        os.environ["WORKER_HEARTBEAT_MAX_AGE_SECONDS"] = "120"
        os.environ["WORKER_TTL_SECONDS"] = "120"
        os.environ.pop("REQUIRE_ACTIVE_WORKER", None)

        # Verify worker_ttl is wired consistently into RQ 3.0 worker construction
        rq_worker = worker_module.create_worker(conn=self.fake_redis)
        self.assertEqual(rq_worker.worker_ttl, 120)

        fixed_now = datetime(2026, 11, 18, 12, 0, 0, tzinfo=timezone.utc)
        fresh_hb = (fixed_now - timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        stale_hb = (fixed_now - timedelta(seconds=125)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        rq_worker.register_birth()
        rq_worker.heartbeat()
        try:
            # 1. Fresh heartbeat (30s <= 120s) -> healthy & /readyz returns 200
            self.fake_redis.hset(rq_worker.key, "last_heartbeat", fresh_hb)
            ok_fresh, det_fresh = worker_module.run_worker_healthcheck(conn=self.fake_redis, now_utc=fixed_now)
            self.assertTrue(ok_fresh)
            self.assertEqual(det_fresh["online"], 1)

            # 2. Stale heartbeat (125s > 120s) while Redis key still exists -> UNHEALTHY & /readyz 503
            self.fake_redis.hset(rq_worker.key, "last_heartbeat", stale_hb)
            ok_stale, det_stale = worker_module.run_worker_healthcheck(conn=self.fake_redis, now_utc=fixed_now)
            self.assertFalse(ok_stale)
            self.assertEqual(det_stale["online"], 0)
            self.assertIn("stale/unhealthy ignored", det_stale["detail"])

            # Verify /readyz returns 503 with stale heartbeat using real clock (30 min ago)
            very_stale_hb = (datetime.now(timezone.utc) - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            self.fake_redis.hset(rq_worker.key, "last_heartbeat", very_stale_hb)
            with patch("app.check_chromium_available", return_value=(True, "Chromium OK")):
                r_stale = self.client.get("/readyz")
                self.assertEqual(r_stale.status_code, 503)
                self.assertFalse(json.loads(r_stale.data)["checks"]["workers"]["ok"])

            # 3. Missing last_heartbeat field -> UNHEALTHY & /readyz 503
            self.fake_redis.hdel(rq_worker.key, "last_heartbeat")
            ok_missing, det_missing = worker_module.run_worker_healthcheck(conn=self.fake_redis, now_utc=fixed_now)
            self.assertFalse(ok_missing)
            self.assertEqual(det_missing["online"], 0)
            with patch("app.check_chromium_available", return_value=(True, "Chromium OK")):
                self.assertEqual(self.client.get("/readyz").status_code, 503)

            # 4. Dead worker state even with fresh heartbeat -> UNHEALTHY & /readyz 503
            self.fake_redis.hset(rq_worker.key, "last_heartbeat", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
            self.fake_redis.hset(rq_worker.key, "state", "dead")
            ok_dead, det_dead = worker_module.run_worker_healthcheck(conn=self.fake_redis)
            self.assertFalse(ok_dead)
            self.assertEqual(det_dead["online"], 0)
            with patch("app.check_chromium_available", return_value=(True, "Chromium OK")):
                self.assertEqual(self.client.get("/readyz").status_code, 503)
        finally:
            rq_worker.register_death()

        # 5. get_state() raising exception -> UNHEALTHY (fail-closed)
        bad_state_worker = MagicMock()
        bad_state_worker.get_state.side_effect = RuntimeError("state read failed")
        bad_state_worker.last_heartbeat = fixed_now
        with patch("services.job_queue.Worker.all", return_value=[bad_state_worker]):
            res_bad_state = check_worker_health(conn=self.fake_redis, now_utc=fixed_now)
            self.assertFalse(res_bad_state["ok"])
            self.assertEqual(res_bad_state["online"], 0)

        # 6. last_heartbeat property raising exception -> UNHEALTHY (fail-closed)
        class BrokenHeartbeatWorker:
            def get_state(self):
                return "idle"

            @property
            def last_heartbeat(self):
                raise RuntimeError("heartbeat read failed")

        with patch("services.job_queue.Worker.all", return_value=[BrokenHeartbeatWorker()]):
            res_bad_hb = check_worker_health(conn=self.fake_redis, now_utc=fixed_now)
            self.assertFalse(res_bad_hb["ok"])
            self.assertEqual(res_bad_hb["online"], 0)

    def test_load_local_dotenv_respects_precedence_and_skips_production(self):
        import tempfile
        from pathlib import Path
        from services.runtime_config import PROJECT_ROOT, load_local_dotenv

        self.assertTrue((PROJECT_ROOT / "app.py").is_file())
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text(
                "# Comment line\n"
                "LEADHUNTER_TEST_DOTENV_KEY='quoted-secret-val'\n"
                "export LEADHUNTER_TEST_DOTENV_PORT=5055 # inline comment\n"
                "LEADHUNTER_TEST_DOTENV_EXISTING=from-file\n",
                encoding="utf-8",
            )
            os.environ.pop("LEADHUNTER_TEST_DOTENV_KEY", None)
            os.environ.pop("LEADHUNTER_TEST_DOTENV_PORT", None)
            os.environ["LEADHUNTER_TEST_DOTENV_EXISTING"] = "from-env"
            try:
                loaded = load_local_dotenv(env_path=env_file)
                self.assertTrue(loaded)
                self.assertEqual(os.environ.get("LEADHUNTER_TEST_DOTENV_KEY"), "quoted-secret-val")
                self.assertEqual(os.environ.get("LEADHUNTER_TEST_DOTENV_PORT"), "5055")
                # Explicit env var MUST NOT be overridden when override=False
                self.assertEqual(os.environ.get("LEADHUNTER_TEST_DOTENV_EXISTING"), "from-env")

                # Automatic loading (env_path=None) skips in production mode
                os.environ["LEADHUNTER_ENV"] = "production"
                self.assertFalse(load_local_dotenv())
            finally:
                os.environ.pop("LEADHUNTER_TEST_DOTENV_KEY", None)
                os.environ.pop("LEADHUNTER_TEST_DOTENV_PORT", None)
                os.environ.pop("LEADHUNTER_TEST_DOTENV_EXISTING", None)
                os.environ.pop("LEADHUNTER_ENV", None)


if __name__ == "__main__":
    unittest.main()
