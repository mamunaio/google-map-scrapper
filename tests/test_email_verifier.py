"""
LeadHunter Studio — Batch Email Verification Feature Tests.

Covers:
1. All 4 verification outcomes (`Valid`, `Risky`, `Invalid`, `Unknown`) and honesty guarantees
   (MX-only never `Valid`, uncertain/blocked/timeout never `Valid`, zero emails ever sent).
2. Disposable domain, role-based prefix, catch-all detection, null MX, NXDOMAIN, SSRF-blocked MX.
3. Provider-independent extensibility (custom / future paid provider registration).
4. Batch duplicate suppression, per-domain caching, and live progress/remaining/outcome counts.
5. RQ background job execution & Redis queue deduplication (`POST /api/jobs/verify-emails`,
   `GET /api/jobs/<id>`, `GET /api/jobs/<id>/result`) with dual-mode API & UI session auth.
6. Export schema preservation (8-col Lead Tracker CSV / 3-sheet XLSX: 8, 15, 7 cols).
7. Real Chromium UI workflow: Verify Emails button, Unverified-only targeting, progress &
   remaining counts, final Valid/Risky/Invalid/Unknown counts, and status filtering.
"""

import io
import os
import socket
import smtplib
import unittest
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import fakeredis
import openpyxl
from rq import SimpleWorker

from app import app, rate_limiter
from services.email_verifier import (
    EmailVerificationResult,
    FreeEmailVerificationProvider,
    STATUS_INVALID,
    STATUS_RISKY,
    STATUS_UNKNOWN,
    STATUS_VALID,
    get_email_verification_provider,
    is_disposable_domain,
    is_role_based_local_part,
    register_email_verification_provider,
    verify_email_address,
    verify_email_batch,
)
from services.export_service import (
    LEAD_TRACKER_COLUMNS,
    generate_lead_tracker_csv,
    generate_styled_excel,
    normalize_email_status,
)
from services.job_queue import (
    enqueue_email_verification_job,
    get_job_queue,
    get_job_result_payload,
    get_job_status_payload,
    set_redis_connection,
)
from services.security import SecurityError


def _make_mx(exchange: str, preference: int = 10):
    rec = MagicMock()
    rec.preference = preference
    rec.exchange = exchange
    return rec


class TestFreeEmailVerificationEngine(unittest.TestCase):
    def setUp(self):
        self.provider = FreeEmailVerificationProvider(
            dns_timeout=2,
            smtp_timeout=2,
            max_retries=0,
            domain_delay_ms=0,
            enable_smtp_probe=True,
        )

    def test_invalid_syntax_cases(self):
        for bad in ("", "not-an-email", "missing-domain@", "@missing-local.com", "a b@example.com"):
            with self.subTest(email=bad):
                res = self.provider.verify(bad)
                self.assertEqual(res.status, STATUS_INVALID)
                self.assertEqual(res.method, "syntax")
                self.assertFalse(res.checks["syntax_valid"])
                self.assertTrue(res.verified_at)

    @patch("services.email_verifier.dns.resolver.resolve")
    def test_nxdomain_and_no_mx_and_null_mx_are_invalid(self, mock_resolve):
        # 1. Non-existent domain (NXDOMAIN) -> Invalid
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()
        res_nx = self.provider.verify("alice@nonexistent-domain-xyz123.com")
        self.assertEqual(res_nx.status, STATUS_INVALID)
        self.assertEqual(res_nx.method, "dns_domain")
        self.assertFalse(res_nx.checks["domain_exists"])

        # 2. Domain resolves A record but has NoAnswer for MX -> Invalid (no mail service)
        mock_resolve.side_effect = [dns.resolver.NoAnswer(), [MagicMock()]]
        res_nomx = self.provider.verify("alice@no-mx-domain.com")
        self.assertEqual(res_nomx.status, STATUS_INVALID)
        self.assertEqual(res_nomx.method, "dns_mx")
        self.assertTrue(res_nomx.checks["domain_exists"])
        self.assertFalse(res_nomx.checks["has_mx"])

        # 3. RFC 7505 Null MX ("0 .") -> Invalid
        mock_resolve.side_effect = None
        mock_resolve.return_value = [_make_mx(".", preference=0)]
        res_null = self.provider.verify("alice@null-mx.com")
        self.assertEqual(res_null.status, STATUS_INVALID)
        self.assertEqual(res_null.method, "dns_mx")
        self.assertIn("null MX", res_null.details)

    @patch("services.email_verifier.resolve_and_validate_public_ips", side_effect=SecurityError("Private IP blocked"))
    @patch("services.email_verifier.dns.resolver.resolve")
    def test_ssrf_private_mx_blocked_as_invalid(self, mock_resolve, _mock_pin):
        mock_resolve.return_value = [_make_mx("internal.local.", 10)]
        res = self.provider.verify("alice@internal-mx.com")
        self.assertEqual(res.status, STATUS_INVALID)
        self.assertEqual(res.method, "dns_mx_security")

    @patch("services.email_verifier.dns.resolver.resolve")
    def test_dns_timeout_and_nameserver_failure_are_unknown_never_valid(self, mock_resolve):
        for exc in (dns.resolver.LifetimeTimeout(), dns.exception.Timeout(), dns.resolver.NoNameservers()):
            with self.subTest(exc=exc.__class__.__name__):
                mock_resolve.side_effect = exc
                res = self.provider.verify("alice@slow-dns.com")
                self.assertEqual(res.status, STATUS_UNKNOWN)
                self.assertNotEqual(res.status, STATUS_VALID)

    @patch("services.email_verifier.resolve_and_validate_public_ips", return_value=["93.184.216.34"])
    @patch("services.email_verifier.dns.resolver.resolve")
    def test_disposable_domain_classified_as_risky(self, mock_resolve, _mock_pin):
        mock_resolve.return_value = [_make_mx("mx.mailinator.com.", 10)]
        self.assertTrue(is_disposable_domain("mailinator.com"))
        self.assertTrue(is_disposable_domain("sub.yopmail.com"))
        res = self.provider.verify("tempuser@mailinator.com")
        self.assertEqual(res.status, STATUS_RISKY)
        self.assertEqual(res.method, "disposable_domain")
        self.assertTrue(res.checks["is_disposable"])

    @patch("services.email_verifier.resolve_and_validate_public_ips", return_value=["93.184.216.34"])
    @patch("services.email_verifier.dns.resolver.resolve")
    @patch("services.email_verifier.smtplib.SMTP")
    def test_smtp_outcomes_valid_risky_invalid_unknown_and_never_sends_email(
        self, mock_smtp_cls, mock_resolve, _mock_pin
    ):
        mock_resolve.return_value = [_make_mx("mail.acme-hvac.com.", 10)]
        smtp = MagicMock()
        smtp.ehlo.return_value = (250, b"OK")
        smtp.mail.return_value = (250, b"OK")
        mock_smtp_cls.return_value = smtp

        # 1. Non-catch-all, non-role, non-disposable, explicit 250 -> Valid
        smtp.rcpt.side_effect = [(550, b"No such user"), (250, b"OK")]
        res_valid = self.provider.verify("sarah.connor@acme-hvac.com")
        self.assertEqual(res_valid.status, STATUS_VALID)
        self.assertEqual(res_valid.method, "dns_mx_smtp")
        self.assertTrue(res_valid.checks["smtp_checked"])
        self.assertEqual(res_valid.checks["smtp_code"], 250)
        # Never sends actual email content
        smtp.data.assert_not_called()
        smtp.sendmail.assert_not_called()
        smtp.send_message.assert_not_called()

        # 2. Role-based address accepted with 250 -> Risky (never Valid)
        smtp.rcpt.side_effect = [(550, b"No such user"), (250, b"OK")]
        self.assertTrue(is_role_based_local_part("info"))
        self.assertTrue(is_role_based_local_part("support+billing"))
        res_role = self.provider.verify("info@acme-hvac.com")
        self.assertEqual(res_role.status, STATUS_RISKY)
        self.assertEqual(res_role.method, "dns_mx_smtp_role")
        self.assertTrue(res_role.checks["is_role_based"])

        # 3. Catch-all server (random probe returns 250) -> Risky
        smtp.rcpt.side_effect = [(250, b"OK catch-all")]
        res_catchall = self.provider.verify("sarah.connor@acme-hvac.com")
        self.assertEqual(res_catchall.status, STATUS_RISKY)
        self.assertEqual(res_catchall.method, "dns_mx_smtp_catchall")
        self.assertTrue(res_catchall.checks["is_catch_all"])

        # 4. Permanent mailbox rejection (550) on non-catch-all -> Invalid
        smtp.rcpt.side_effect = [(550, b"No such user"), (550, b"User unknown")]
        res_550 = self.provider.verify("ghost@acme-hvac.com")
        self.assertEqual(res_550.status, STATUS_INVALID)
        self.assertEqual(res_550.checks["smtp_code"], 550)

        # 5. Temporary greylisting / 451 -> Unknown (never Valid)
        smtp.rcpt.side_effect = [(550, b"No such user"), (451, b"Try again later")]
        res_451 = self.provider.verify("sarah.connor@acme-hvac.com")
        self.assertEqual(res_451.status, STATUS_UNKNOWN)
        self.assertEqual(res_451.checks["smtp_code"], 451)

        # 5b. Inconclusive catch-all probe (451 on probe, 250 on target) -> Unknown (NEVER Valid)
        smtp.rcpt.side_effect = [(451, b"Temp error on probe"), (250, b"OK")]
        res_inconclusive_probe = self.provider.verify("sarah.connor@acme-hvac.com")
        self.assertEqual(res_inconclusive_probe.status, STATUS_UNKNOWN)
        self.assertNotEqual(res_inconclusive_probe.status, STATUS_VALID)
        self.assertEqual(res_inconclusive_probe.method, "dns_mx_smtp_inconclusive")
        self.assertIn("catch-all probe was inconclusive", res_inconclusive_probe.details)

        # 6. Port 25 timeout / blocked -> Unknown (MX alone MUST NEVER classify as Valid)
        mock_smtp_cls.side_effect = socket.timeout("timed out")
        res_timeout = self.provider.verify("sarah.connor@acme-hvac.com")
        self.assertEqual(res_timeout.status, STATUS_UNKNOWN)
        self.assertIn("MX validation alone does not prove mailbox existence", res_timeout.details)

        # 7. SMTP probe explicitly disabled -> MX-only MUST be Unknown (never Valid)
        mx_only_provider = FreeEmailVerificationProvider(
            dns_timeout=2, smtp_timeout=2, max_retries=0, domain_delay_ms=0, enable_smtp_probe=False
        )
        res_mx_only = mx_only_provider.verify("sarah.connor@acme-hvac.com")
        self.assertEqual(res_mx_only.status, STATUS_UNKNOWN)
        self.assertEqual(res_mx_only.method, "dns_mx_only")

    def test_provider_abstraction_supports_pluggable_third_party_provider(self):
        class StubPaidProvider:
            name = "stub_zerobounce"

            def verify(self, email: str, *, context=None) -> EmailVerificationResult:
                return EmailVerificationResult(
                    email=email,
                    normalized_email=email.strip().lower(),
                    status=STATUS_VALID,
                    method="external_api",
                    verified_at="2026-11-18T00:00:00+00:00",
                    details="Verified by stub paid API",
                    provider=self.name,
                    checks={"api_verified": True},
                )

        register_email_verification_provider("stub_zerobounce", StubPaidProvider)
        provider = get_email_verification_provider("stub_zerobounce")
        self.assertEqual(provider.name, "stub_zerobounce")
        res = verify_email_address("ceo@company.example", provider_name="stub_zerobounce")
        self.assertEqual(res.status, STATUS_VALID)
        self.assertEqual(res.provider, "stub_zerobounce")

        with self.assertRaises(ValueError):
            get_email_verification_provider("nonexistent_provider_xyz")

    def test_batch_duplicate_suppression_and_progress_counts(self):
        call_log = []

        class CountingProvider:
            name = "counting_stub"

            def verify(self, email: str, *, context=None) -> EmailVerificationResult:
                call_log.append(email.lower())
                low = email.lower()
                if low.startswith("valid@"):
                    st = STATUS_VALID
                elif low.startswith("info@"):
                    st = STATUS_RISKY
                elif low.startswith("bad@"):
                    st = STATUS_INVALID
                else:
                    st = STATUS_UNKNOWN
                return EmailVerificationResult(
                    email=email,
                    normalized_email=low,
                    status=st,
                    method="stub",
                    verified_at="2026-11-18T00:00:00+00:00",
                    details=f"status={st}",
                    provider=self.name,
                )

        progress_updates = []
        items = [
            {"row_index": 0, "email": "valid@acme.example"},
            {"row_index": 1, "email": "VALID@acme.example"},  # duplicate (case-insensitive)
            {"row_index": 2, "email": "info@acme.example"},
            {"row_index": 3, "email": "bad@acme.example"},
            {"row_index": 4, "email": "maybe@acme.example"},
        ]
        summary = verify_email_batch(
            items,
            provider=CountingProvider(),
            progress_callback=lambda proc, tot, cnts: progress_updates.append((proc, tot, cnts)),
        )
        # 5 items, 1 duplicate -> only 4 provider calls
        self.assertEqual(len(call_log), 4)
        self.assertEqual(summary["total"], 5)
        self.assertEqual(summary["processed"], 5)
        self.assertEqual(summary["remaining"], 0)
        self.assertEqual(summary["unique_checked"], 4)
        self.assertEqual(summary["duplicates_suppressed"], 1)
        self.assertEqual(summary["counts"], {"Valid": 2, "Risky": 1, "Invalid": 1, "Unknown": 1})
        self.assertTrue(summary["results"][1]["deduplicated"])
        self.assertEqual(summary["results"][1]["row_index"], 1)
        self.assertEqual(progress_updates[-1][0], 5)
        self.assertEqual(progress_updates[-1][1], 5)


class TestEmailVerificationApiQueueExportAndUi(unittest.TestCase):
    def setUp(self):
        self._orig_env = dict(os.environ)
        self.api_key = "email-verify-test-secret-123456"
        os.environ["LEADHUNTER_API_KEY"] = self.api_key
        os.environ["UI_AUTO_SESSION"] = "false"
        os.environ["CONTAINER"] = "true"
        os.environ["LEADHUNTER_ENV"] = "development"
        os.environ["REQUIRE_ACTIVE_WORKER"] = "false"
        os.environ["RATE_LIMIT_MAX_REQUESTS"] = "200"
        os.environ["RATE_LIMIT_READ_MAX_REQUESTS"] = "500"
        for k in ("FLASK_ENV", "RENDER", "REDIS_URL"):
            os.environ.pop(k, None)
        self.fake_redis = fakeredis.FakeRedis()
        set_redis_connection(self.fake_redis)
        rate_limiter.set_redis_client(self.fake_redis)
        rate_limiter.reset()

    def tearDown(self):
        set_redis_connection(None)
        rate_limiter.set_redis_client(None)
        os.environ.clear()
        os.environ.update(self._orig_env)
        rate_limiter.reset()

    def test_verify_emails_api_auth_validation_rq_worker_execution_and_dedup(self):
        client = app.test_client()

        # 1. Unauthenticated request rejected with 401
        r_unauth = client.post(
            "/api/jobs/verify-emails",
            json={"items": [{"row_index": 0, "email": "alice@example.com"}]},
        )
        self.assertEqual(r_unauth.status_code, 401)

        # 2. Malformed payloads rejected with 400
        x_hdrs = {"X-API-Key": self.api_key}
        self.assertEqual(client.post("/api/jobs/verify-emails", json={"items": []}, headers=x_hdrs).status_code, 400)
        self.assertEqual(
            client.post("/api/jobs/verify-emails", json={"items": [{"row_index": -1, "email": "a@b.co"}]}, headers=x_hdrs).status_code,
            400,
        )
        self.assertEqual(
            client.post(
                "/api/jobs/verify-emails",
                json={"items": [{"row_index": 0, "email": "a@b.co"}], "provider": "unknown_provider"},
                headers=x_hdrs,
            ).status_code,
            400,
        )

        # 3. Authenticated submission via explicit UI session + CSRF + same-origin works
        so_post = {"Origin": "http://localhost", "Sec-Fetch-Site": "same-origin"}
        r_login = client.post("/api/ui-session", json={}, headers={**so_post, "X-API-Key": self.api_key})
        self.assertEqual(r_login.status_code, 200)
        csrf = r_login.get_json()["csrf_token"]

        payload = {
            "items": [
                {"row_index": 0, "email": "sarah@acme.example"},
                {"row_index": 2, "email": "info@acme.example"},
                {"row_index": 3, "email": "bad-syntax"},
                {"row_index": 4, "email": "timeout@acme.example"},
            ]
        }
        r_enq = client.post("/api/jobs/verify-emails", json=payload, headers={**so_post, "X-CSRF-Token": csrf})
        self.assertEqual(r_enq.status_code, 202, r_enq.data)
        enq_data = r_enq.get_json()
        job_id = enq_data["job_id"]
        self.assertEqual(enq_data["job_type"], "email_verification")
        self.assertFalse(enq_data["deduplicated"])

        # Duplicate active batch submission deduplicates cleanly
        r_dup = client.post("/api/jobs/verify-emails", json=payload, headers={**so_post, "X-CSRF-Token": csrf})
        self.assertEqual(r_dup.status_code, 202)
        self.assertTrue(r_dup.get_json()["deduplicated"])
        self.assertEqual(r_dup.get_json()["job_id"], job_id)

        # 4. Execute queued job with RQ SimpleWorker using mocked provider outcomes
        def fake_verify(email, *, context=None):
            mapping = {
                "sarah@acme.example": (STATUS_VALID, "dns_mx_smtp"),
                "info@acme.example": (STATUS_RISKY, "dns_mx_smtp_role"),
                "bad-syntax": (STATUS_INVALID, "syntax"),
                "timeout@acme.example": (STATUS_UNKNOWN, "dns_mx_smtp_inconclusive"),
            }
            st, mth = mapping[email]
            return EmailVerificationResult(
                email=email,
                normalized_email=email.lower(),
                status=st,
                method=mth,
                verified_at="2026-11-18T12:00:00+00:00",
                details=f"detail:{st}",
                provider="free_dns_smtp",
            )

        with patch.object(FreeEmailVerificationProvider, "verify", side_effect=fake_verify):
            worker = SimpleWorker([get_job_queue(conn=self.fake_redis)], connection=self.fake_redis)
            worker.work(burst=True)

        # 5. Poll status & fetch result using Bearer auth (existing read bucket + compatibility)
        bearer = {"Authorization": f"Bearer {self.api_key}"}
        r_status = client.get(f"/api/jobs/{job_id}", headers=bearer)
        self.assertEqual(r_status.status_code, 200)
        st_json = r_status.get_json()
        self.assertEqual(st_json["status"], "finished")
        self.assertEqual(st_json["progress"]["processed_count"], 4)
        self.assertEqual(st_json["progress"]["remaining_count"], 0)
        self.assertEqual(st_json["progress"]["counts"], {"Valid": 1, "Risky": 1, "Invalid": 1, "Unknown": 1})

        r_res = client.get(f"/api/jobs/{job_id}/result", headers=bearer)
        self.assertEqual(r_res.status_code, 200)
        res_json = r_res.get_json()
        self.assertTrue(res_json["success"])
        self.assertEqual(res_json["counts"], {"Valid": 1, "Risky": 1, "Invalid": 1, "Unknown": 1})
        self.assertEqual(len(res_json["results"]), 4)
        self.assertEqual([x["status"] for x in res_json["results"]], ["Valid", "Risky", "Invalid", "Unknown"])

    def test_export_schemas_preserved_with_new_verification_statuses(self):
        # Legacy mappings untouched
        self.assertEqual(normalize_email_status("Valid (MX Only)", "a@b.com"), "MX Only")
        self.assertEqual(normalize_email_status("MX Only", "a@b.com"), "MX Only")
        self.assertEqual(normalize_email_status("Verified", "a@b.com"), "Verified")
        self.assertEqual(normalize_email_status("Valid", "a@b.com"), "Valid")
        self.assertEqual(normalize_email_status("Risky", "a@b.com"), "Risky")
        self.assertEqual(normalize_email_status("Invalid", "a@b.com"), "Invalid")
        self.assertEqual(normalize_email_status("Invalid", "not-an-email"), "Invalid")
        self.assertEqual(normalize_email_status("Verified", "not-an-email"), "Not Found")
        self.assertEqual(normalize_email_status("Unknown", "a@b.com"), "Unknown")

        leads = [
            {
                "Business Name": "Alpha HVAC",
                "Contact Person": "Sarah Connor",
                "Website": "https://alpha.example.com",
                "Phone": "+1-214-555-0101",
                "City": "Dallas",
                "State": "TX",
                "Category": "HVAC contractor",
                "Rating": 4.9,
                "Notes": "Preserved underlying note",
                "Email": "sarah@alpha.example.com",
                "Email Status": "Valid",
                "email_verification_details": {
                    "status": "Valid",
                    "method": "dns_mx_smtp",
                    "verified_at": "2026-11-18T12:00:00+00:00",
                    "details": "Confirmed",
                },
            },
            {
                "Business Name": "Beta Plumbing",
                "Website": "https://beta.example.com",
                "Email": "info@beta.example.com",
                "Email Status": "Risky",
            },
            {
                "Business Name": "Gamma Air",
                "Website": "https://gamma.example.com",
                "Email": "bad@gamma.example.com",
                "Email Status": "Invalid",
            },
            {
                "Business Name": "Delta Cooling",
                "Website": "https://delta.example.com",
                "Email": "owner@delta.example.com",
                "Email Status": "Unknown",
            },
        ]
        csv_text = generate_lead_tracker_csv(leads)
        header_cols = csv_text.splitlines()[0].split(",")
        self.assertEqual(header_cols, LEAD_TRACKER_COLUMNS)
        self.assertEqual(len(header_cols), 8)

        wb = openpyxl.load_workbook(generate_styled_excel(leads, format_type="standard_3_sheet"))
        self.assertEqual(wb.sheetnames, ["Lead Tracker", "Website Audit", "Business Opportunities"])
        ws1, ws2, ws3 = wb.worksheets[0], wb.worksheets[1], wb.worksheets[2]
        sheet1_headers = [ws1.cell(row=1, column=c).value for c in range(1, ws1.max_column + 1)]
        self.assertEqual(sheet1_headers, LEAD_TRACKER_COLUMNS)
        self.assertEqual(len(sheet1_headers), 8)
        self.assertEqual(ws2.max_column, 15)
        self.assertEqual(ws3.max_column, 7)
        # Col 4 is Email Status in the 8-column Lead Tracker schema
        exported_statuses = [ws1.cell(row=r, column=4).value for r in range(2, 6)]
        self.assertEqual(exported_statuses, ["Valid", "Risky", "Invalid", "Unknown"])
        # Underlying fields remain preserved untouched on lead records
        self.assertEqual(leads[0]["Category"], "HVAC contractor")
        self.assertEqual(leads[0]["Rating"], 4.9)
        self.assertEqual(leads[0]["Notes"], "Preserved underlying note")
        self.assertEqual(leads[0]["email_verification_details"]["method"], "dns_mx_smtp")

    def test_frontend_verify_emails_workflow_counts_and_filter_in_chromium(self):
        from playwright.sync_api import sync_playwright

        rendered_html = app.test_client().get("/").data.decode("utf-8")

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                page = browser.new_page()
                page.route(
                    "**/*",
                    lambda route: route.fulfill(status=200, body="", content_type="application/javascript")
                    if not route.request.url.startswith(("http://localhost", "about:", "data:"))
                    else route.continue_(),
                )
                page.route(
                    "http://localhost/",
                    lambda route: route.fulfill(status=200, body=rendered_html, content_type="text/html; charset=utf-8"),
                )
                page.goto("http://localhost/", wait_until="domcontentloaded")

                res = page.evaluate("""async () => {
                    const origSetTimeout = window.setTimeout;
                    window.setTimeout = (fn, ms) => origSetTimeout(fn, 1);

                    uiCsrfToken = 'csrf-verify-ui-token';
                    uiSessionActive = true;
                    inputType = 'file';
                    uploadedData = [
                        { 'Business Name': 'Biz Unv 1', 'Contact Person': 'Sarah Connor', 'Website': 'https://u1.example.com', 'Phone': '214-555-0101', 'City': 'Dallas', 'State': 'TX', 'Contact Email': 'sarah@u1.example.com', 'Email Status': 'Unverified', 'Email Verification': 'Unverified', 'Rating': 4.9, 'Category': 'HVAC', intelligence: null },
                        { 'Business Name': 'Biz Already Verified', 'Website': 'https://v1.example.com', 'Contact Email': 'owner@v1.example.com', 'Email Status': 'Verified', 'Email Verification': 'Verified', intelligence: null },
                        { 'Business Name': 'Biz Unv 2', 'Website': 'https://u2.example.com', 'Contact Email': 'info@u2.example.com', 'Email Status': 'Unverified', 'Email Verification': 'Unverified', intelligence: null },
                        { 'Business Name': 'Biz Unv 3 Malformed', 'Website': 'https://u3.example.com', 'Contact Email': 'not-an-email', 'Email Status': 'Unverified', 'Email Verification': 'Unverified', intelligence: null },
                        { 'Business Name': 'Biz Unv 4', 'Website': 'https://u4.example.com', 'Contact Email': 'slow@u4.example.com', 'Email Status': 'Unverified', 'Email Verification': 'Unverified', intelligence: null },
                        { 'Business Name': 'Biz No Email', 'Website': 'https://n1.example.com', 'Contact Email': '', 'Email Status': 'Not Found', 'Email Verification': 'Not Found', intelligence: null }
                    ];
                    renderTable();
                    const tableHeaders = Array.from(document.querySelectorAll('#tableHeadRow th'))
                        .slice(1)
                        .map(th => th.textContent.trim());
                    const initialBadge = document.getElementById('verifyEmailsCountBadge').textContent;

                    let submittedPayload = null;
                    let pollCalls = 0;
                    window.fetch = async (url, opts = {}) => {
                        const mkJson = (status, obj) => ({
                            ok: status >= 200 && status < 300,
                            status,
                            headers: { get: (k) => k.toLowerCase() === 'content-type' ? 'application/json' : null },
                            json: async () => obj
                        });
                        if (url === '/api/jobs/verify-emails' && opts.method === 'POST') {
                            submittedPayload = JSON.parse(opts.body);
                            return mkJson(202, { success: true, job_id: 'vjob-1', job_type: 'email_verification', status: 'queued' });
                        }
                        if (url === '/api/jobs/vjob-1') {
                            pollCalls += 1;
                            if (pollCalls === 1) {
                                return mkJson(200, {
                                    success: true,
                                    job_id: 'vjob-1',
                                    status: 'started',
                                    progress: { processed_count: 2, remaining_count: 2, total_count: 4, counts: { Valid: 1, Risky: 1, Invalid: 0, Unknown: 0 }, message: 'Halfway' }
                                });
                            }
                            return mkJson(200, {
                                success: true,
                                job_id: 'vjob-1',
                                status: 'finished',
                                progress: { processed_count: 4, remaining_count: 0, total_count: 4, counts: { Valid: 1, Risky: 1, Invalid: 1, Unknown: 1 }, message: 'Done' }
                            });
                        }
                        if (url === '/api/jobs/vjob-1/result') {
                            return mkJson(200, {
                                success: true,
                                total: 4,
                                processed: 4,
                                remaining: 0,
                                duplicates_suppressed: 0,
                                counts: { Valid: 1, Risky: 1, Invalid: 1, Unknown: 1 },
                                results: [
                                    { row_index: 0, email: 'sarah@u1.example.com', status: 'Valid', method: 'dns_mx_smtp', verified_at: '2026-11-18T12:00:00Z', details: 'Confirmed', provider: 'free_dns_smtp', checks: {} },
                                    { row_index: 2, email: 'info@u2.example.com', status: 'Risky', method: 'dns_mx_smtp_role', verified_at: '2026-11-18T12:00:00Z', details: 'Role address', provider: 'free_dns_smtp', checks: {} },
                                    { row_index: 3, email: 'not-an-email', status: 'Invalid', method: 'syntax', verified_at: '2026-11-18T12:00:00Z', details: 'Invalid syntax', provider: 'free_dns_smtp', checks: {} },
                                    { row_index: 4, email: 'slow@u4.example.com', status: 'Unknown', method: 'dns_mx_smtp_inconclusive', verified_at: '2026-11-18T12:00:00Z', details: 'Port 25 timed out', provider: 'free_dns_smtp', checks: {} }
                                ]
                            });
                        }
                        return mkJson(404, { success: false, error: 'Not found' });
                    };

                    await startBatchEmailVerification();

                    // Test filtering by verification status
                    const countVisible = () => Array.from(document.querySelectorAll('.table-row-item')).filter(r => r.style.display !== 'none').length;
                    document.getElementById('verificationStatusFilter').value = 'valid';
                    filterTableRows();
                    const visibleValid = countVisible();

                    document.getElementById('verificationStatusFilter').value = 'risky';
                    filterTableRows();
                    const visibleRisky = countVisible();

                    document.getElementById('verificationStatusFilter').value = 'invalid';
                    filterTableRows();
                    const visibleInvalid = countVisible();

                    document.getElementById('verificationStatusFilter').value = 'unknown';
                    filterTableRows();
                    const visibleUnknown = countVisible();

                    document.getElementById('verificationStatusFilter').value = 'all';
                    filterTableRows();
                    const visibleAll = countVisible();

                    return {
                        tableHeaders,
                        initialBadge,
                        submittedIndices: submittedPayload.items.map(i => i.row_index),
                        processedText: document.getElementById('emailVerifyProcessed').textContent,
                        remainingText: document.getElementById('emailVerifyRemaining').textContent,
                        counts: {
                            Valid: document.getElementById('emailVerifyCountValid').textContent,
                            Risky: document.getElementById('emailVerifyCountRisky').textContent,
                            Invalid: document.getElementById('emailVerifyCountInvalid').textContent,
                            Unknown: document.getElementById('emailVerifyCountUnknown').textContent
                        },
                        afterBadge: document.getElementById('verifyEmailsCountBadge').textContent,
                        btnDisabledAfter: document.getElementById('btnVerifyEmails').disabled,
                        row0DetailsMethod: uploadedData[0].email_verification_details?.method,
                        row0PreservedRating: uploadedData[0]['Rating'],
                        row0PreservedCategory: uploadedData[0]['Category'],
                        row1PreservedStatus: uploadedData[1]['Email Status'],
                        visibleValid,
                        visibleRisky,
                        visibleInvalid,
                        visibleUnknown,
                        visibleAll
                    };
                }""")

                self.assertEqual(res["tableHeaders"], LEAD_TRACKER_COLUMNS)
                self.assertEqual(res["initialBadge"], "4")
                # Strictly targeted ONLY the 4 Unverified rows (including malformed 'not-an-email', excluding Verified & Not Found)
                self.assertEqual(res["submittedIndices"], [0, 2, 3, 4])
                self.assertEqual(res["processedText"], "4")
                self.assertEqual(res["remainingText"], "0")
                self.assertEqual(res["counts"], {"Valid": "1", "Risky": "1", "Invalid": "1", "Unknown": "1"})
                self.assertEqual(res["afterBadge"], "0")
                self.assertTrue(res["btnDisabledAfter"])
                self.assertEqual(res["row0DetailsMethod"], "dns_mx_smtp")
                self.assertEqual(res["row0PreservedRating"], 4.9)
                self.assertEqual(res["row0PreservedCategory"], "HVAC")
                self.assertEqual(res["row1PreservedStatus"], "Verified")
                self.assertEqual(res["visibleValid"], 1)
                self.assertEqual(res["visibleRisky"], 1)
                self.assertEqual(res["visibleInvalid"], 1)
                self.assertEqual(res["visibleUnknown"], 1)
                self.assertEqual(res["visibleAll"], 6)
            finally:
                browser.close()


if __name__ == "__main__":
    unittest.main()
