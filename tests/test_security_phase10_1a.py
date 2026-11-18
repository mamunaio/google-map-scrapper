"""
Phase 10.1A Security Hardening Regression Test Suite
Covers:
  - CRIT-01: Playwright Fallback SSRF & DNS Rebinding Protection
  - CRIT-03: API Authentication, Rate Limiting, Input Validation & Debug Hardening
  - HIGH-01: DOM-Based XSS Remediation (static + real Chromium DOM verification)
  - HIGH-02: Raw SSL & SMTP Socket SSRF / DNS Pinning Hardening
"""

import json
import os
import re
import socket
import ssl
import unittest
from unittest.mock import MagicMock, patch

import pytest

import app as app_module
from app import app, rate_limiter, should_enable_debug
from services.email_service import verify_email_smtp
from services.security import (
    SafeBrowserProxy,
    SecurityError,
    create_pinned_public_socket,
    create_public_website_route_interceptor,
    is_ip_allowed,
    is_safe_public_browser_url,
    resolve_and_validate_public_ips,
    safe_http_get,
    validate_and_sanitize_url,
)
from services.technical_audit import inspect_ssl_certificate
from services.website_crawler import find_candidate_pages, scrape_with_playwright_fallback


# =============================================================================
# 1. CRIT-01 — SSRF & DNS REBINDING TESTS (Playwright Fallback & Proxy)
# =============================================================================


class TestCrit01PlaywrightSSRF(unittest.TestCase):
    def test_localhost_and_loopback_blocked(self):
        targets = [
            "http://localhost/",
            "http://127.0.0.1:8080/admin",
            "http://0.0.0.0/",
            "http://sub.localhost/secret",
        ]
        for url in targets:
            with self.subTest(url=url):
                with self.assertRaises(SecurityError):
                    validate_and_sanitize_url(url)
                safe, _ = is_safe_public_browser_url(url, is_main_document=True)
                self.assertFalse(safe)
                with self.assertRaises(SecurityError):
                    scrape_with_playwright_fallback(url)

    def test_rfc1918_private_ranges_blocked(self):
        targets = [
            "http://10.0.0.1/internal",
            "http://172.16.0.10/metrics",
            "http://192.168.1.1/router",
        ]
        for url in targets:
            with self.subTest(url=url):
                with self.assertRaises(SecurityError):
                    validate_and_sanitize_url(url)
                safe, _ = is_safe_public_browser_url(url, is_main_document=True)
                self.assertFalse(safe)
                with self.assertRaises(SecurityError):
                    scrape_with_playwright_fallback(url)

    def test_ipv6_loopback_and_link_local_blocked(self):
        for ip in ["::1", "fe80::1", "fc00::1", "fd12:3456::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254"]:
            with self.subTest(ip=ip):
                self.assertFalse(is_ip_allowed(ip))

        for url in ["http://[::1]:8000/", "http://[fe80::1]/", "http://[fc00::1]/"]:
            with self.subTest(url=url):
                safe, _ = is_safe_public_browser_url(url, is_main_document=True)
                self.assertFalse(safe)
                with self.assertRaises(SecurityError):
                    validate_and_sanitize_url(url)

    def test_cloud_metadata_blocked(self):
        metadata_urls = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/computeMetadata/v1/",
        ]
        for url in metadata_urls:
            with self.subTest(url=url):
                with self.assertRaises(SecurityError):
                    validate_and_sanitize_url(url)
                safe, _ = is_safe_public_browser_url(url, is_main_document=True)
                self.assertFalse(safe)
                with self.assertRaises(SecurityError):
                    scrape_with_playwright_fallback(url)

    def test_proxy_public_mode_blocks_private_loopback_ipv6_metadata_and_dns_rebinding(self):
        with SafeBrowserProxy(allow_public_hosts=True) as proxy:
            host, port = "127.0.0.1", proxy.port

            def send_proxy_request(raw_req: bytes) -> bytes:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(3)
                    s.connect((host, port))
                    s.sendall(raw_req)
                    return s.recv(4096)

            # Direct blocked targets via HTTP & CONNECT
            blocked_requests = [
                b"GET http://127.0.0.1:8080/admin HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
                b"GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n",
                b"CONNECT 10.0.0.1:443 HTTP/1.1\r\nHost: 10.0.0.1:443\r\n\r\n",
                b"CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n",
                b"CONNECT localhost:5000 HTTP/1.1\r\nHost: localhost:5000\r\n\r\n",
            ]
            for req in blocked_requests:
                resp = send_proxy_request(req)
                self.assertTrue(resp.startswith(b"HTTP/1.1 403"), f"Expected 403 for {req!r}, got {resp!r}")

            # DNS Rebinding: domain initially passes pre-flight as public, then rebinds to 169.254.169.254
            rebind_calls = [
                [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))],
                [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80))],
            ]
            with patch("services.security.socket.getaddrinfo", side_effect=rebind_calls):
                # 1st lookup succeeds validation
                self.assertEqual(validate_and_sanitize_url("http://rebind.attacker-test.com/"), "http://rebind.attacker-test.com/")
                # 2nd lookup inside proxy detects rebinding and returns 403 Forbidden
                resp = send_proxy_request(
                    b"GET http://rebind.attacker-test.com/secret HTTP/1.1\r\nHost: rebind.attacker-test.com\r\n\r\n"
                )
                self.assertTrue(resp.startswith(b"HTTP/1.1 403"), f"Expected 403 on DNS rebinding, got {resp!r}")

    def test_malicious_redirects_blocked(self):
        # 1. HTTP redirect to internal/metadata host blocked by safe_http_get
        mock_redir = MagicMock()
        mock_redir.is_redirect = True
        mock_redir.headers = {"location": "http://169.254.169.254/latest/meta-data/"}

        with patch("services.security.socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]), \
             patch("requests.Session.get", return_value=mock_redir):
            with self.assertRaises(SecurityError):
                safe_http_get("https://public-site.example.com/start")

        # 2. Playwright route interceptor blocks navigation redirect to internal host
        mock_page = MagicMock()
        interceptor = create_public_website_route_interceptor(mock_page)

        mock_route = MagicMock()
        mock_route.request.url = "http://127.0.0.1:5000/internal-redirect"
        mock_route.request.is_navigation_request.return_value = True
        mock_route.request.frame = mock_page.main_frame

        interceptor(mock_route)
        mock_route.abort.assert_called_once_with("blockedbyclient")
        mock_route.continue_.assert_not_called()

    def test_malicious_candidate_page_urls_blocked(self):
        html = """
        <html><body>
            <a href="javascript:alert(1)">Contact Us</a>
            <a href="file:///etc/passwd">About Us</a>
            <a href="data:text/html,<h1>Contact</h1>">Contact</a>
            <a href="http://169.254.169.254/contact">Contact Metadata</a>
            <a href="/contact">Legit Contact</a>
        </body></html>
        """
        candidates = find_candidate_pages(html, "https://public-hvac.example.com/")
        # Only same-origin HTTP/HTTPS candidate links should survive
        self.assertEqual(candidates, ["https://public-hvac.example.com/contact"])

    def test_playwright_subresource_requests_to_internal_destinations_blocked(self):
        mock_page = MagicMock()
        interceptor = create_public_website_route_interceptor(mock_page)

        internal_subresources = [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://127.0.0.1:8080/api/internal",
            "http://10.0.0.5/logo.png",
            "http://192.168.0.1/status",
            "http://[::1]:9000/metrics",
            "file:///C:/Windows/win.ini",
        ]
        for sub_url in internal_subresources:
            with self.subTest(sub_url=sub_url):
                mock_route = MagicMock()
                mock_route.request.url = sub_url
                mock_route.request.is_navigation_request.return_value = False
                mock_route.request.frame = MagicMock()
                interceptor(mock_route)
                mock_route.abort.assert_called_once_with("blockedbyclient")
                mock_route.continue_.assert_not_called()

        # Public subresource resolving to public IP is allowed
        with patch("services.security.socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]):
            mock_route_ok = MagicMock()
            mock_route_ok.request.url = "https://cdn.public-example.com/app.js"
            mock_route_ok.request.is_navigation_request.return_value = False
            mock_route_ok.request.frame = MagicMock()
            interceptor(mock_route_ok)
            mock_route_ok.continue_.assert_called_once()
            mock_route_ok.abort.assert_not_called()

    def test_playwright_fallback_uses_proxy_route_interceptor_and_cleans_up_on_exception(self):
        mock_page = MagicMock()
        mock_page.goto.side_effect = RuntimeError("Simulated navigation crash")
        mock_context = MagicMock()
        mock_context.new_page.return_value = mock_page
        mock_browser = MagicMock()
        mock_browser.new_context.return_value = mock_context

        mock_pw = MagicMock()
        mock_pw.chromium.launch.return_value = mock_browser
        mock_pw_cm = MagicMock()
        mock_pw_cm.__enter__.return_value = mock_pw
        mock_pw_cm.__exit__.return_value = False

        proxy_exited = {"called": False}
        orig_exit = SafeBrowserProxy.__exit__

        def tracked_exit(self_proxy, *args):
            proxy_exited["called"] = True
            return orig_exit(self_proxy, *args)

        with patch("services.security.socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]), \
             patch("services.website_crawler.sync_playwright", return_value=mock_pw_cm), \
             patch.object(SafeBrowserProxy, "__exit__", tracked_exit):
            res = scrape_with_playwright_fallback("https://public-hvac.example.com/")

        # Should fail safely without crashing caller
        self.assertEqual(res[0], "")
        # Verify browser context received local SafeBrowserProxy configuration
        _, ctx_kwargs = mock_browser.new_context.call_args
        self.assertIn("proxy", ctx_kwargs)
        self.assertTrue(ctx_kwargs["proxy"]["server"].startswith("http://127.0.0.1:"))
        # Verify Playwright route interceptor was registered
        mock_page.route.assert_called_once()
        self.assertEqual(mock_page.route.call_args[0][0], "**/*")
        # Verify strict resource cleanup even on navigation failure
        mock_page.close.assert_called_once()
        mock_context.close.assert_called_once()
        mock_browser.close.assert_called_once()
        self.assertTrue(proxy_exited["called"])


# =============================================================================
# 2. CRIT-03 — AUTHENTICATION, RATE LIMITING, INPUT VALIDATION & DEBUG TESTS
# =============================================================================


class TestCrit03AuthRateLimitAndValidation(unittest.TestCase):
    def setUp(self):
        self._env_backup = {
            k: os.environ.get(k)
            for k in (
                "LEADHUNTER_API_KEY",
                "LEADHUNTER_ENV",
                "FLASK_ENV",
                "RENDER",
                "FLASK_DEBUG",
                "RATE_LIMIT_MAX_REQUESTS",
                "RATE_LIMIT_WINDOW_SECONDS",
            )
        }
        os.environ["LEADHUNTER_API_KEY"] = "super-secret-phase10-1a-key"
        os.environ.pop("LEADHUNTER_ENV", None)
        os.environ.pop("FLASK_ENV", None)
        os.environ.pop("RENDER", None)
        os.environ.pop("FLASK_DEBUG", None)
        os.environ["RATE_LIMIT_MAX_REQUESTS"] = "30"
        os.environ["RATE_LIMIT_WINDOW_SECONDS"] = "60"
        rate_limiter.reset()
        self.client = app.test_client()

    def tearDown(self):
        for k, v in self._env_backup.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        rate_limiter.reset()

    def test_anonymous_request_rejected_on_all_protected_endpoints(self):
        endpoints = [
            ("/api/scrape", {"url": "https://example.com", "type": "website"}),
            ("/api/audit", {"url": "https://example.com"}),
            ("/api/export-excel", {"leads": [{"Business Name": "Test"}]}),
            ("/api/export-csv", {"leads": [{"Business Name": "Test"}]}),
        ]
        for path, payload in endpoints:
            with self.subTest(path=path):
                resp = self.client.post(path, json=payload)
                self.assertEqual(resp.status_code, 401)
                body = json.loads(resp.data)
                self.assertFalse(body["success"])

    def test_invalid_credential_rejected(self):
        for headers in [
            {"X-API-Key": "wrong-key"},
            {"Authorization": "Bearer wrong-key"},
            {"Authorization": "Basic dXNlcjpwYXNz"},
        ]:
            with self.subTest(headers=headers):
                resp = self.client.post("/api/audit", json={"url": "https://example.com"}, headers=headers)
                self.assertEqual(resp.status_code, 401)

    @patch("app.crawl_and_audit_website", return_value={"Website": "https://example.com", "Email": ""})
    def test_valid_credential_accepted_x_api_key_and_bearer(self, _mock_crawl):
        resp1 = self.client.post(
            "/api/audit",
            json={"url": "https://example.com"},
            headers={"X-API-Key": "super-secret-phase10-1a-key"},
        )
        self.assertEqual(resp1.status_code, 200)

        resp2 = self.client.post(
            "/api/audit",
            json={"url": "https://example.com"},
            headers={"Authorization": "Bearer super-secret-phase10-1a-key"},
        )
        self.assertEqual(resp2.status_code, 200)

    def test_missing_production_secret_fails_closed(self):
        os.environ.pop("LEADHUNTER_API_KEY", None)
        for env_key, env_val in [("LEADHUNTER_ENV", "production"), ("FLASK_ENV", "production"), ("RENDER", "true")]:
            with self.subTest(env=f"{env_key}={env_val}"):
                os.environ.pop("LEADHUNTER_ENV", None)
                os.environ.pop("FLASK_ENV", None)
                os.environ.pop("RENDER", None)
                os.environ[env_key] = env_val
                resp = self.client.post(
                    "/api/scrape",
                    json={"url": "https://example.com", "type": "website"},
                    headers={"X-API-Key": "anything"},
                )
                self.assertEqual(resp.status_code, 503)
                body = json.loads(resp.data)
                self.assertFalse(body["success"])
                self.assertIn("not configured", body["error"].lower())

    @patch("app.crawl_and_audit_website", return_value={"Website": "https://example.com", "Email": ""})
    def test_rate_limit_enforced_and_ignores_spoofed_x_forwarded_for(self, _mock_crawl):
        os.environ["RATE_LIMIT_MAX_REQUESTS"] = "3"
        os.environ["RATE_LIMIT_WINDOW_SECONDS"] = "60"
        rate_limiter.reset()

        for i in range(3):
            resp = self.client.post(
                "/api/audit",
                json={"url": "https://example.com"},
                headers={
                    "X-API-Key": "super-secret-phase10-1a-key",
                    "X-Forwarded-For": f"203.0.113.{i + 1}",  # Spoofed IP must NOT bypass rate limit
                },
            )
            self.assertEqual(resp.status_code, 200)

        resp_blocked = self.client.post(
            "/api/audit",
            json={"url": "https://example.com"},
            headers={
                "X-API-Key": "super-secret-phase10-1a-key",
                "X-Forwarded-For": "198.51.100.99",
            },
        )
        self.assertEqual(resp_blocked.status_code, 429)
        self.assertIn("Retry-After", resp_blocked.headers)

    def test_malformed_and_out_of_range_inputs_rejected_and_500_sanitized(self):
        auth = {"X-API-Key": "super-secret-phase10-1a-key"}

        # Non-JSON / malformed JSON
        r_bad_json = self.client.post("/api/scrape", data="not-json", content_type="application/json", headers=auth)
        self.assertEqual(r_bad_json.status_code, 400)

        # JSON array instead of object
        r_list_json = self.client.post("/api/scrape", data="[1,2,3]", content_type="application/json", headers=auth)
        self.assertEqual(r_list_json.status_code, 400)

        # Invalid type & out-of-range max_results
        invalid_payloads = [
            {"url": "https://example.com", "type": "ssh"},
            {"url": "https://example.com", "type": "maps", "max_results": 0},
            {"url": "https://example.com", "type": "maps", "max_results": -5},
            {"url": "https://example.com", "type": "maps", "max_results": 51},
            {"url": "https://example.com", "type": "maps", "max_results": "abc"},
            {"url": "https://example.com", "type": "maps", "max_results": True},
            {"url": "https://example.com", "type": "website", "business_name": 12345},
        ]
        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                resp = self.client.post("/api/scrape", json=payload, headers=auth)
                self.assertEqual(resp.status_code, 400)

        # Export validation
        self.assertEqual(self.client.post("/api/export-excel", json={"leads": ["not-a-dict"]}, headers=auth).status_code, 400)
        self.assertEqual(
            self.client.post("/api/export-excel", json={"leads": [{"Business Name": "A"}], "format_type": "invalid"}, headers=auth).status_code,
            400,
        )
        self.assertEqual(self.client.post("/api/export-csv", json={"leads": []}, headers=auth).status_code, 400)

        # Oversized payload returns 413 JSON error
        orig_max = app.config.get("MAX_CONTENT_LENGTH")
        try:
            app.config["MAX_CONTENT_LENGTH"] = 128
            big_payload = json.dumps({"url": "https://example.com/" + "a" * 300})
            resp_413 = self.client.post("/api/audit", data=big_payload, content_type="application/json", headers=auth)
            self.assertEqual(resp_413.status_code, 413)
            body_413 = json.loads(resp_413.data)
            self.assertFalse(body_413["success"])
        finally:
            app.config["MAX_CONTENT_LENGTH"] = orig_max

        # Internal 500 error must NOT leak raw internal exception details
        with patch("app.crawl_and_audit_website", side_effect=RuntimeError("SECRET_DB_DSN=postgres://admin:pw@10.0.0.5/db")):
            resp_500 = self.client.post("/api/audit", json={"url": "https://example.com"}, headers=auth)
            self.assertEqual(resp_500.status_code, 500)
            body = json.loads(resp_500.data)
            self.assertNotIn("SECRET_DB_DSN", body["error"])
            self.assertNotIn("postgres://", body["error"])

    def test_debug_mode_disabled_by_default_and_never_enabled_in_production(self):
        # Disabled by default
        os.environ.pop("FLASK_DEBUG", None)
        self.assertFalse(should_enable_debug())

        # Explicitly enabled locally only when not in production
        os.environ["FLASK_DEBUG"] = "true"
        self.assertTrue(should_enable_debug())

        # Never enabled in production even when FLASK_DEBUG=true
        for env_key, env_val in [("LEADHUNTER_ENV", "production"), ("FLASK_ENV", "production"), ("RENDER", "true")]:
            os.environ.pop("LEADHUNTER_ENV", None)
            os.environ.pop("FLASK_ENV", None)
            os.environ.pop("RENDER", None)
            os.environ[env_key] = env_val
            self.assertFalse(should_enable_debug(), f"Debug must be False when {env_key}={env_val}")


# =============================================================================
# 3. HIGH-01 — DOM-BASED XSS TESTS (Static + Live Headless Chromium DOM)
# =============================================================================


class TestHigh01DomXssRemediation(unittest.TestCase):
    def test_template_has_zero_innerhtml_and_zero_inline_data_handlers(self):
        client = app.test_client()
        resp = client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode("utf-8")

        # Zero dynamic innerHTML assignments anywhere in template script
        self.assertNotIn(".innerHTML", html)
        # Zero inline onclick string interpolation with scraped variables
        self.assertNotRegex(html, r'onclick="copyText\(')
        self.assertNotRegex(html, r'onclick="openIntelModal\(')
        # Must include strict external URL sanitizer
        self.assertIn("function sanitizeExternalUrl(", html)
        self.assertIn("rel = 'noopener noreferrer'", html)

    def test_xss_payloads_never_execute_in_real_chromium_dom_and_safe_text_preserved(self):
        from playwright.sync_api import sync_playwright

        client = app.test_client()
        rendered_html = client.get("/").data.decode("utf-8")

        malicious_lead = {
            "Business Name": "<img src=x onerror=\"window.__xssTriggered='biz'\"> Acme & Sons HVAC",
            "Website": "javascript:window.__xssTriggered='web'",
            "Contact Person": "<svg onload=\"window.__xssTriggered='dm'\">Mary-Anne O'Connor",
            "Decision Maker": "<svg onload=\"window.__xssTriggered='dm'\">Mary-Anne O'Connor",
            "Email": "'); window.__xssTriggered='email'; //owner@acme-hvac.com",
            "Email Status": "MX Only",
            "Email Verification": "MX Only",
            "Priority": "High",
            "Lead Score": 88,
            "Main Opportunity": "<img src=x onerror=\"window.__xssTriggered='gap'\"> Missing Online Booking",
            "Facebook": "javascript:window.__xssTriggered='fb'",
            "LinkedIn": "data:text/html,<script>window.__xssTriggered='li'</script>",
            "intelligence": {
                "lead_score": 88,
                "priority_tier": "High Priority",
                "seo": {"seo_score": 72, "robots_sitemap": {"has_sitemap_xml": False}},
                "technical": {
                    "ssl_certificate": {
                        "status": "Valid",
                        "evidence": "<img src=x onerror=\"window.__xssTriggered='ssl'\"> Sectigo CA",
                    },
                    "mobile_usability": {"status": "<script>window.__xssTriggered='mob'</script>Responsive"},
                },
                "features": {
                    "booking": {
                        "category": "<img src=x onerror=\"window.__xssTriggered='feat'\"> Online Booking",
                        "status": "Detected",
                        "providers": ["<img src=x onerror=\"window.__xssTriggered='prov'\"> Calendly"],
                    }
                },
                "opportunities": {
                    "lead_score": 88,
                    "priority_tier": "High Priority",
                    "main_gap": "<img src=x onerror=\"window.__xssTriggered='gap'\"> Missing Online Booking",
                    "detected_opportunities": [
                        {
                            "Recommended Service": "<img src=x onerror=\"window.__xssTriggered='svc'\"> Booking Setup",
                            "Confidence Level": "High",
                            "Evidence Description": "<img src=x onerror=\"window.__xssTriggered='ev'\"> No scheduler link found",
                            "Potential Business Impact": "<script>window.__xssTriggered='imp'</script> Higher conversion",
                        }
                    ],
                    "outreach_hooks": [
                        "<img src=x onerror=\"window.__xssTriggered='hook'\"> Saw your site lacks booking"
                    ],
                },
            },
        }

        legit_lead = {
            "Business Name": "Safe Dallas Air Co.",
            "Website": "https://safedallasair.example.com/home",
            "Decision Maker": "Jose Luis Mondragon",
            "Email": "info@safedallasair.example.com",
            "Email Status": "Verified",
            "Priority": "Medium",
            "Main Opportunity": "Missing Meta Description",
            "Facebook": "https://facebook.com/safedallasair",
            "LinkedIn": "https://linkedin.com/company/safedallasair",
            "intelligence": {"lead_score": 65, "opportunities": {"main_gap": "Missing Meta Description"}},
        }

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                page = browser.new_page()
                # Abort all external CDN requests so test runs offline and instantaneously
                page.route("**/*", lambda route: route.abort() if route.request.url.startswith(("http://", "https://")) else route.continue_())
                page.set_content(rendered_html, wait_until="domcontentloaded")

                audit_result = page.evaluate(
                    """([malLead, okLead]) => {
                        window.__xssTriggered = false;
                        inputType = 'manual';
                        finalData = [malLead, okLead];
                        renderTable();
                        // Exercise terminal logger with XSS payload
                        log('<img src=x onerror="window.__xssTriggered=\\'log\\'"> Failed: test');
                        // Exercise Intelligence Modal with malicious record
                        openIntelModal(0);

                        const tbody = document.getElementById('resultsTableBody');
                        const modal = document.getElementById('intelModal');
                        const logBox = document.getElementById('logBox');

                        const allLinks = Array.from(document.querySelectorAll('a[href]')).map(a => a.getAttribute('href') || '');
                        const unsafeLinks = allLinks.filter(h => /^(javascript|data|vbscript):/i.test(h.trim()));

                        const row0Text = tbody.rows[0] ? tbody.rows[0].textContent : '';
                        const row1Text = tbody.rows[1] ? tbody.rows[1].textContent : '';
                        const row1WebLink = tbody.rows[1] ? tbody.rows[1].querySelector('a[href^="https://safedallasair.example.com"]') : null;
                        const modalWebHref = document.getElementById('modalWebsiteLink').getAttribute('href');
                        const modalText = modal.textContent;
                        const logText = logBox.textContent;

                        // Ensure no injected <img> or <svg onload> XSS nodes exist inside dynamic containers
                        const injectedImgs = document.querySelectorAll('#resultsTableBody img, #intelModal img, #logBox img').length;

                        return {
                            xssTriggered: window.__xssTriggered,
                            unsafeLinks,
                            injectedImgs,
                            row0Text,
                            row1Text,
                            row1WebHref: row1WebLink ? row1WebLink.getAttribute('href') : null,
                            row1WebRel: row1WebLink ? row1WebLink.getAttribute('rel') : null,
                            modalWebHref,
                            modalText,
                            logText,
                        };
                    }""",
                    [malicious_lead, legit_lead],
                )

                # Zero XSS execution across all sinks
                self.assertFalse(audit_result["xssTriggered"], f"XSS executed: {audit_result['xssTriggered']}")
                self.assertEqual(audit_result["unsafeLinks"], [], f"Unsafe hrefs found: {audit_result['unsafeLinks']}")
                self.assertEqual(audit_result["injectedImgs"], 0)
                # Malicious javascript: website URL must not set href in modal
                self.assertIsNone(audit_result["modalWebHref"])
                # Safe literal text rendering preserved (HTML tags rendered as text, not parsed)
                self.assertIn("Acme & Sons HVAC", audit_result["row0Text"])
                self.assertIn("Mary-Anne O'Connor", audit_result["row0Text"])
                self.assertIn("owner@acme-hvac.com", audit_result["row0Text"])
                self.assertIn("No scheduler link found", audit_result["modalText"])
                self.assertIn("Failed: test", audit_result["logText"])
                # Legitimate HTTPS link preserved with safe target/rel
                self.assertEqual(audit_result["row1WebHref"], "https://safedallasair.example.com/home")
                self.assertEqual(audit_result["row1WebRel"], "noopener noreferrer")
            finally:
                browser.close()


# =============================================================================
# 4. HIGH-02 — RAW SSL / SMTP SOCKET SSRF & DNS PINNING TESTS
# =============================================================================


class TestHigh02SslAndSmtpSocketHardening(unittest.TestCase):
    def _mock_mx(self, exchange: str):
        mx = MagicMock()
        mx.preference = 10
        mx.exchange = exchange
        return [mx]

    def test_smtp_private_mx_rejected_without_connecting(self):
        for private_ip in ["10.0.0.5", "172.16.5.20", "192.168.1.50"]:
            with self.subTest(private_ip=private_ip):
                with patch("dns.resolver.resolve", return_value=self._mock_mx("mx.private-test.com.")), \
                     patch("services.security.socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", (private_ip, 25))]), \
                     patch("smtplib.SMTP") as mock_smtp:
                    ok, status = verify_email_smtp("user@private-test.com")
                    self.assertFalse(ok)
                    self.assertEqual(status, "Invalid")
                    mock_smtp.assert_not_called()

    def test_smtp_loopback_and_metadata_mx_rejected_without_connecting(self):
        cases = [
            ("localhost.", None),
            ("mx.loopback-test.com.", [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 25))]),
            ("mx.ipv6-loopback.com.", [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 25, 0, 0))]),
            ("mx.metadata-test.com.", [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 25))]),
        ]
        for exchange, gai_res in cases:
            with self.subTest(exchange=exchange):
                with patch("dns.resolver.resolve", return_value=self._mock_mx(exchange)), \
                     patch("services.security.socket.getaddrinfo", return_value=gai_res or []), \
                     patch("smtplib.SMTP") as mock_smtp:
                    ok, status = verify_email_smtp("user@blocked-mx.com")
                    self.assertFalse(ok)
                    self.assertEqual(status, "Invalid")
                    mock_smtp.assert_not_called()

    def test_smtp_dns_rebinding_mixed_ips_rejected_and_public_ip_pinned(self):
        # Mixed public + private resolution must fail closed
        mixed_gai = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 25)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 25)),
        ]
        with patch("dns.resolver.resolve", return_value=self._mock_mx("mx.dual-rebind.com.")), \
             patch("services.security.socket.getaddrinfo", return_value=mixed_gai), \
             patch("smtplib.SMTP") as mock_smtp:
            ok, status = verify_email_smtp("user@dual-rebind.com")
            self.assertFalse(ok)
            self.assertEqual(status, "Invalid")
            mock_smtp.assert_not_called()

        # Public MX: verifies smtplib.SMTP connects directly to pinned IP literal (never raw mx_host)
        public_gai = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 25))]
        mock_server = MagicMock()
        mock_server.rcpt.side_effect = [(550, b"No user"), (250, b"OK")]
        with patch("dns.resolver.resolve", return_value=self._mock_mx("mx.public-corp.com.")), \
             patch("services.security.socket.getaddrinfo", return_value=public_gai), \
             patch("smtplib.SMTP", return_value=mock_server) as mock_smtp:
            ok, status = verify_email_smtp("owner@public-corp.com", timeout=4)
            self.assertTrue(ok)
            self.assertEqual(status, "Verified")
            mock_smtp.assert_called_once_with("93.184.216.34", 25, timeout=4)

    def test_ssl_private_loopback_metadata_and_rebinding_rejected(self):
        blocked_cases = [
            ("localhost", []),
            ("127.0.0.1", []),
            ("169.254.169.254", []),
            ("internal.example.com", [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.9", 443))]),
            ("rebind.example.com", [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443)),
            ]),
            ("ipv6local.example.com", [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 443, 0, 0))]),
        ]
        for host, gai_res in blocked_cases:
            with self.subTest(host=host):
                with patch("services.security.socket.getaddrinfo", return_value=gai_res), \
                     patch("services.security.socket.socket") as mock_sock_cls:
                    res = inspect_ssl_certificate(host)
                    self.assertEqual(res["status"], "Blocked")
                    mock_sock_cls.assert_not_called()

    def test_ssl_connects_directly_to_pinned_public_ip_and_preserves_tls_verification_and_sni(self):
        fake_cert = {
            "notAfter": "May 20 12:00:00 2029 GMT",
            "issuer": ((("organizationName", "DigiCert Inc"),),),
        }
        mock_raw_sock = MagicMock()
        mock_raw_sock.__enter__.return_value = mock_raw_sock

        mock_ssock = MagicMock()
        mock_ssock.__enter__.return_value = mock_ssock
        mock_ssock.getpeercert.return_value = fake_cert

        real_ctx = ssl.create_default_context()
        captured_ctx = {}

        def fake_create_default_context(cafile=None):
            captured_ctx["cafile"] = cafile
            captured_ctx["ctx"] = real_ctx
            return real_ctx

        with patch("services.security.socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]), \
             patch("services.security.socket.socket", return_value=mock_raw_sock), \
             patch("services.technical_audit.ssl.create_default_context", side_effect=fake_create_default_context), \
             patch.object(real_ctx, "wrap_socket", return_value=mock_ssock) as mock_wrap:
            res = inspect_ssl_certificate("secure.example.com", port=443, timeout=4)

        # Must connect directly to the validated public IP (zero secondary DNS lookup)
        mock_raw_sock.connect.assert_called_once_with(("93.184.216.34", 443))
        # Must preserve strict TLS verification & hostname checking
        self.assertIsNotNone(captured_ctx["cafile"])
        self.assertEqual(captured_ctx["ctx"].verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(captured_ctx["ctx"].check_hostname)
        # Must preserve original SNI hostname
        mock_wrap.assert_called_once_with(mock_raw_sock, server_hostname="secure.example.com")
        self.assertEqual(res["status"], "Valid")
        self.assertEqual(res["issuer"], "DigiCert Inc")


if __name__ == "__main__":
    unittest.main()
