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
            "JOB_MAX_RETRIES",
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

        # 6. worker.py creates a valid RQ worker against FakeRedis
        import worker as worker_module
        w = worker_module.create_worker(conn=self.fake_redis)
        self.assertEqual(w.queue_names(), ["leadhunter"])


if __name__ == "__main__":
    unittest.main()
