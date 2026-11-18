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

    def test_data_url_navigations_blocked_in_main_and_child_frames_while_safe_data_subresources_allowed(self):
        mock_page = MagicMock()
        child_frame = MagicMock()  # Distinct from mock_page.main_frame
        interceptor = create_public_website_route_interceptor(mock_page)

        # 1. Main-frame data: navigation rejected (unit + route interceptor)
        for data_nav in [
            "data:text/html,<script>alert(1)</script>",
            "DATA:text/html;base64,PGh0bWw+PC9odG1sPg==",
            "data:image/svg+xml,<svg onload=alert(1)>",
        ]:
            with self.subTest(case="main_frame_data_nav", url=data_nav):
                safe, _ = is_safe_public_browser_url(data_nav, is_main_document=True, is_navigation=True)
                self.assertFalse(safe)

                mock_route = MagicMock()
                mock_route.request.url = data_nav
                mock_route.request.is_navigation_request.return_value = True
                mock_route.request.resource_type = "document"
                mock_route.request.frame = mock_page.main_frame
                interceptor(mock_route)
                mock_route.abort.assert_called_once_with("blockedbyclient")
                mock_route.continue_.assert_not_called()

        # 2. Child iframe data: navigation rejected (is_navigation_request=True, frame != main_frame)
        for iframe_data_nav in [
            "data:text/html,<h1>Injected Child Frame</h1>",
            "data:application/xhtml+xml,<html/>",
            "data:image/png;base64,iVBORw0KGgo=",
        ]:
            with self.subTest(case="child_iframe_data_nav", url=iframe_data_nav):
                safe, _ = is_safe_public_browser_url(iframe_data_nav, is_main_document=False, is_navigation=True)
                self.assertFalse(safe)

                mock_route = MagicMock()
                mock_route.request.url = iframe_data_nav
                mock_route.request.is_navigation_request.return_value = True
                mock_route.request.resource_type = "document"
                mock_route.request.frame = child_frame
                interceptor(mock_route)
                mock_route.abort.assert_called_once_with("blockedbyclient")
                mock_route.continue_.assert_not_called()

        # 3. Non-navigation safe inline data: image/font subresources allowed (and about:blank allowed)
        for safe_inline in [
            "data:image/png;base64,iVBORw0KGgo=",
            "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg'/>",
            "data:font/woff2;base64,d09GMgABAAAAAA==",
            "data:application/font-woff2;base64,d09GMgABAAAAAA==",
            "about:blank",
        ]:
            with self.subTest(case="safe_inline_subresource", url=safe_inline):
                safe, _ = is_safe_public_browser_url(safe_inline, is_main_document=False, is_navigation=False)
                self.assertTrue(safe)

                mock_route = MagicMock()
                mock_route.request.url = safe_inline
                mock_route.request.is_navigation_request.return_value = False
                mock_route.request.resource_type = "image"
                mock_route.request.frame = child_frame
                interceptor(mock_route)
                mock_route.continue_.assert_called_once()
                mock_route.abort.assert_not_called()

        # 4. Active data:text/html or data:text/javascript blocked even as non-navigation subresource
        for active_data in [
            "data:text/html,<script>alert(1)</script>",
            "data:text/javascript,alert(1)",
        ]:
            with self.subTest(case="active_data_subresource", url=active_data):
                safe, _ = is_safe_public_browser_url(active_data, is_main_document=False, is_navigation=False)
                self.assertFalse(safe)

    def test_child_iframe_http_private_metadata_blocked_and_public_resources_allowed(self):
        mock_page = MagicMock()
        child_frame = MagicMock()
        interceptor = create_public_website_route_interceptor(mock_page)

        # HTTP/HTTPS child iframe requests to private and metadata IPs rejected
        for blocked_iframe_url in [
            "http://10.0.0.5/internal-frame",
            "http://172.16.0.12/dashboard",
            "http://192.168.1.1/status",
            "http://127.0.0.1:8000/admin",
            "http://169.254.169.254/latest/meta-data/",
            "https://[::1]/secret",
        ]:
            with self.subTest(blocked_iframe_url=blocked_iframe_url):
                mock_route = MagicMock()
                mock_route.request.url = blocked_iframe_url
                mock_route.request.is_navigation_request.return_value = True
                mock_route.request.resource_type = "document"
                mock_route.request.frame = child_frame
                interceptor(mock_route)
                mock_route.abort.assert_called_once_with("blockedbyclient")
                mock_route.continue_.assert_not_called()

        # Legitimate public main navigation, child iframe navigation, and subresources remain functional
        public_gai = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        with patch("services.security.socket.getaddrinfo", return_value=public_gai):
            for url, is_nav, frame, rtype in [
                ("https://public-hvac.example.com/", True, mock_page.main_frame, "document"),
                ("https://booking.public-widget.example.com/embed", True, child_frame, "document"),
                ("https://cdn.public-hvac.example.com/styles.css", False, mock_page.main_frame, "stylesheet"),
            ]:
                with self.subTest(public_url=url, is_nav=is_nav):
                    mock_route = MagicMock()
                    mock_route.request.url = url
                    mock_route.request.is_navigation_request.return_value = is_nav
                    mock_route.request.resource_type = rtype
                    mock_route.request.frame = frame
                    interceptor(mock_route)
                    mock_route.continue_.assert_called_once()
                    mock_route.abort.assert_not_called()


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
        rate_limiter.set_redis_client(None)
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

    @patch("app.validate_google_maps_url", side_effect=lambda u: u)
    @patch("app.scrape_google_maps")
    def test_max_results_strict_json_integer_validation(self, mock_maps, _mock_validate):
        auth = {"X-API-Key": "super-secret-phase10-1a-key"}
        maps_url = "https://www.google.com/maps/search/HVAC+Dallas+TX"
        mock_maps.return_value = {
            "success": True,
            "is_search": True,
            "leads": [{"Business Name": "Dallas Air", "Website": "", "Phone Number": "214-555-0100"}],
        }

        # Valid genuine JSON integer 20 -> accepted
        r_valid = self.client.post(
            "/api/scrape",
            data=json.dumps({"url": maps_url, "type": "maps", "max_results": 20}),
            content_type="application/json",
            headers=auth,
        )
        self.assertEqual(r_valid.status_code, 200)
        self.assertEqual(mock_maps.call_args.kwargs["max_results"], 20)

        # Omitted max_results -> accepted with default value 20
        mock_maps.reset_mock()
        r_omitted = self.client.post(
            "/api/scrape",
            data=json.dumps({"url": maps_url, "type": "maps"}),
            content_type="application/json",
            headers=auth,
        )
        self.assertEqual(r_omitted.status_code, 200)
        self.assertEqual(mock_maps.call_args.kwargs["max_results"], 20)

        # Invalid types and out-of-range values MUST be rejected with 400
        rejected_raw_values = [
            ('"20"', "numeric string"),
            ('20.0', "float equal to integer"),
            ('true', "JSON boolean"),
            ('0', "below minimum"),
            ('-1', "negative integer"),
            ('51', "above maximum"),
        ]
        for raw_json_val, label in rejected_raw_values:
            with self.subTest(case=label, raw_value=raw_json_val):
                mock_maps.reset_mock()
                raw_body = f'{{"url": "{maps_url}", "type": "maps", "max_results": {raw_json_val}}}'
                resp = self.client.post(
                    "/api/scrape",
                    data=raw_body,
                    content_type="application/json",
                    headers=auth,
                )
                self.assertEqual(resp.status_code, 400, f"Expected 400 for {label} ({raw_json_val}), got {resp.status_code}")
                mock_maps.assert_not_called()

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


# =============================================================================
# 5. DUAL-MODE AUTHENTICATION (LOCAL SIGNED UI SESSION + CSRF & API KEY)
# =============================================================================


class TestDualModeUiSessionAuth(unittest.TestCase):
    def setUp(self):
        self._env_keys = (
            "LEADHUNTER_API_KEY",
            "LEADHUNTER_ENV",
            "FLASK_ENV",
            "RENDER",
            "HOST",
            "FLASK_RUN_HOST",
            "CONTAINER",
            "TRUSTED_PROXY_HOPS",
            "UI_AUTO_SESSION",
            "UI_AUTO_SESSION_BEHIND_TRUSTED_AUTH_PROXY",
            "TRUSTED_AUTH_PROXY_SECRET",
            "TRUSTED_AUTH_PROXY_HEADER",
            "UI_SESSION_TTL_SECONDS",
            "RATE_LIMIT_MAX_REQUESTS",
            "RATE_LIMIT_WINDOW_SECONDS",
        )
        self._env_backup = {k: os.environ.get(k) for k in self._env_keys}
        self.secret_key = "super-secret-dual-mode-auth-key-987654"
        os.environ["LEADHUNTER_API_KEY"] = self.secret_key
        for k in (
            "LEADHUNTER_ENV",
            "FLASK_ENV",
            "RENDER",
            "HOST",
            "FLASK_RUN_HOST",
            "CONTAINER",
            "TRUSTED_PROXY_HOPS",
            "UI_AUTO_SESSION",
            "UI_AUTO_SESSION_BEHIND_TRUSTED_AUTH_PROXY",
            "TRUSTED_AUTH_PROXY_SECRET",
            "TRUSTED_AUTH_PROXY_HEADER",
            "UI_SESSION_TTL_SECONDS",
        ):
            os.environ.pop(k, None)
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
        rate_limiter.set_redis_client(None)
        rate_limiter.reset()

    def _extract_csrf(self, html: str) -> str:
        match = re.search(r'<meta name="csrf-token" content="([0-9a-f]{64})">', html)
        return match.group(1) if match else ""

    def _same_origin_post_headers(self, csrf_token: str) -> dict:
        return {
            "X-CSRF-Token": csrf_token,
            "Origin": "http://localhost",
            "Referer": "http://localhost/",
            "Sec-Fetch-Site": "same-origin",
        }

    def test_local_ui_auto_session_authenticates_without_manual_key_and_never_exposes_secret(self):
        from app import UI_SESSION_COOKIE_NAME

        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode("utf-8")

        # Local loopback UI removes manual API key input and never exposes LEADHUNTER_API_KEY anywhere
        self.assertNotIn('id="apiKeyInput"', html)
        self.assertNotIn(self.secret_key, html)
        set_cookie_hdrs = resp.headers.getlist("Set-Cookie")
        self.assertTrue(any(h.startswith(f"{UI_SESSION_COOKIE_NAME}=") for h in set_cookie_hdrs))
        cookie_hdr = [h for h in set_cookie_hdrs if h.startswith(f"{UI_SESSION_COOKIE_NAME}=")][0]
        self.assertIn("HttpOnly", cookie_hdr)
        self.assertIn("SameSite=Strict", cookie_hdr)
        self.assertNotIn(self.secret_key, cookie_hdr)
        self.assertEqual(resp.headers.get("Cache-Control"), "no-store")

        csrf_token = self._extract_csrf(html)
        self.assertEqual(len(csrf_token), 64)

        # Authenticated UI POST works via HttpOnly session cookie + X-CSRF-Token + same-origin headers
        export_resp = self.client.post(
            "/api/export-csv",
            json={"leads": [{"Business Name": "Local HVAC Co"}]},
            headers=self._same_origin_post_headers(csrf_token),
        )
        self.assertEqual(export_resp.status_code, 200)

        # Authenticated UI GET works with Sec-Fetch-Site: same-origin + cookie + CSRF (404/503, NOT 401)
        import fakeredis
        with patch("services.job_queue.get_redis_connection", return_value=fakeredis.FakeRedis()):
            get_resp = self.client.get(
                "/api/jobs/nonexistent-local-ui-job",
                headers={"X-CSRF-Token": csrf_token, "Sec-Fetch-Site": "same-origin"},
            )
            self.assertEqual(get_resp.status_code, 404)

        # Explicit invalid X-API-Key header MUST still fail closed with 401 even with valid UI session
        bad_key_resp = self.client.post(
            "/api/export-csv",
            json={"leads": [{"Business Name": "Local HVAC Co"}]},
            headers={**self._same_origin_post_headers(csrf_token), "X-API-Key": "wrong-explicit-key"},
        )
        self.assertEqual(bad_key_resp.status_code, 401)

    def test_non_loopback_dev_configurations_do_not_silently_enable_auto_session(self):
        from app import UI_SESSION_COOKIE_NAME, _create_ui_session_tokens
        from services.runtime_config import is_loopback_only_local_deployment, is_ui_auto_session_enabled

        # 1. Non-loopback bind host / container / proxy configurations must disable default auto-session
        non_loopback_env_cases = [
            {"HOST": "0.0.0.0"},
            {"HOST": "::"},
            {"HOST": "192.168.1.50"},
            {"FLASK_RUN_HOST": "0.0.0.0"},
            {"CONTAINER": "true"},
            {"TRUSTED_PROXY_HOPS": "1"},
        ]
        for env_overrides in non_loopback_env_cases:
            for k in ("HOST", "FLASK_RUN_HOST", "CONTAINER", "TRUSTED_PROXY_HOPS", "UI_AUTO_SESSION"):
                os.environ.pop(k, None)
            os.environ.update(env_overrides)
            with self.subTest(env=env_overrides):
                self.assertFalse(is_loopback_only_local_deployment())
                self.assertFalse(is_ui_auto_session_enabled(remote_addr="127.0.0.1", host_header="127.0.0.1:5000"))

                c = app.test_client()
                r_home = c.get("/")
                html = r_home.data.decode("utf-8")
                self.assertIn('id="apiKeyInput"', html)
                self.assertEqual(self._extract_csrf(html), "")
                self.assertFalse(
                    any(h.startswith(f"{UI_SESSION_COOKIE_NAME}=") for h in r_home.headers.getlist("Set-Cookie"))
                )

                cookie_val, csrf_val = _create_ui_session_tokens(self.secret_key)
                c.set_cookie(UI_SESSION_COOKIE_NAME, cookie_val)
                r_api = c.post(
                    "/api/export-csv",
                    json={"leads": [{"Business Name": "Test"}]},
                    headers=self._same_origin_post_headers(csrf_val),
                )
                self.assertEqual(r_api.status_code, 401)

        # Reset env to default local dev and test LAN peer IP / LAN Host header rejection
        for k in ("HOST", "FLASK_RUN_HOST", "CONTAINER", "TRUSTED_PROXY_HOPS", "UI_AUTO_SESSION"):
            os.environ.pop(k, None)

        # 2. Non-loopback client peer IP (e.g. LAN visitor hitting `flask run --host=0.0.0.0`)
        c_lan_ip = app.test_client()
        r_lan_home = c_lan_ip.get("/", environ_base={"REMOTE_ADDR": "192.168.1.42"})
        self.assertIn('id="apiKeyInput"', r_lan_home.data.decode("utf-8"))
        self.assertEqual(self._extract_csrf(r_lan_home.data.decode("utf-8")), "")
        self.assertFalse(
            any(h.startswith(f"{UI_SESSION_COOKIE_NAME}=") for h in r_lan_home.headers.getlist("Set-Cookie"))
        )
        cookie_val, csrf_val = _create_ui_session_tokens(self.secret_key)
        c_lan_ip.set_cookie(UI_SESSION_COOKIE_NAME, cookie_val)
        r_lan_post = c_lan_ip.post(
            "/api/export-csv",
            json={"leads": [{"Business Name": "Test"}]},
            headers=self._same_origin_post_headers(csrf_val),
            environ_base={"REMOTE_ADDR": "192.168.1.42"},
        )
        self.assertEqual(r_lan_post.status_code, 401)

        # 3. Non-loopback Host header (e.g. LAN hostname or IP)
        c_lan_host = app.test_client()
        r_host_home = c_lan_host.get("/", headers={"Host": "192.168.1.10:5000"})
        self.assertIn('id="apiKeyInput"', r_host_home.data.decode("utf-8"))
        self.assertEqual(self._extract_csrf(r_host_home.data.decode("utf-8")), "")
        self.assertFalse(
            any(h.startswith(f"{UI_SESSION_COOKIE_NAME}=") for h in r_host_home.headers.getlist("Set-Cookie"))
        )

    def test_explicit_ui_auto_session_cannot_bypass_network_restrictions_and_requires_trusted_proxy_opt_in(self):
        from app import UI_SESSION_COOKIE_NAME, _create_ui_session_tokens

        # 1. Explicit UI_AUTO_SESSION=false on loopback disables auto-session
        os.environ["UI_AUTO_SESSION"] = "false"
        c_off = app.test_client()
        r_off = c_off.get("/")
        self.assertIn('id="apiKeyInput"', r_off.data.decode("utf-8"))
        self.assertEqual(self._extract_csrf(r_off.data.decode("utf-8")), "")
        self.assertFalse(
            any(h.startswith(f"{UI_SESSION_COOKIE_NAME}=") for h in r_off.headers.getlist("Set-Cookie"))
        )

        # 2. Explicit UI_AUTO_SESSION=true MUST NOT bypass wildcard, LAN, public, container,
        #    or incomplete proxy configurations (env flags alone NEVER prove proxy authentication)
        proxy_secret = "distinct-upstream-auth-proxy-secret-xyz789"
        rejected_explicit_cases = [
            {"HOST": "0.0.0.0", "UI_AUTO_SESSION": "true"},
            {"HOST": "::", "UI_AUTO_SESSION": "true"},
            {"HOST": "192.168.1.50", "UI_AUTO_SESSION": "true"},
            {"HOST": "203.0.113.10", "UI_AUTO_SESSION": "true"},
            {"CONTAINER": "true", "UI_AUTO_SESSION": "true"},
            # TRUSTED_PROXY_HOPS alone is NOT proof of an authenticated proxy
            {"HOST": "0.0.0.0", "UI_AUTO_SESSION": "true", "TRUSTED_PROXY_HOPS": "1"},
            # Trusted-proxy opt-in without TRUSTED_PROXY_HOPS > 0 is rejected
            {"HOST": "0.0.0.0", "UI_AUTO_SESSION": "true", "UI_AUTO_SESSION_BEHIND_TRUSTED_AUTH_PROXY": "true"},
            # Trusted-proxy flags WITHOUT TRUSTED_AUTH_PROXY_SECRET are rejected
            {
                "HOST": "0.0.0.0",
                "UI_AUTO_SESSION": "true",
                "TRUSTED_PROXY_HOPS": "1",
                "UI_AUTO_SESSION_BEHIND_TRUSTED_AUTH_PROXY": "true",
            },
            # Reusing LEADHUNTER_API_KEY as TRUSTED_AUTH_PROXY_SECRET is rejected
            {
                "HOST": "0.0.0.0",
                "UI_AUTO_SESSION": "true",
                "TRUSTED_PROXY_HOPS": "1",
                "UI_AUTO_SESSION_BEHIND_TRUSTED_AUTH_PROXY": "true",
                "TRUSTED_AUTH_PROXY_SECRET": self.secret_key,
            },
            # Trusted-proxy flags without explicit UI_AUTO_SESSION=true remain disabled by default
            {
                "HOST": "0.0.0.0",
                "TRUSTED_PROXY_HOPS": "1",
                "UI_AUTO_SESSION_BEHIND_TRUSTED_AUTH_PROXY": "true",
                "TRUSTED_AUTH_PROXY_SECRET": proxy_secret,
            },
        ]
        for env_overrides in rejected_explicit_cases:
            for k in (
                "HOST",
                "FLASK_RUN_HOST",
                "CONTAINER",
                "TRUSTED_PROXY_HOPS",
                "UI_AUTO_SESSION",
                "UI_AUTO_SESSION_BEHIND_TRUSTED_AUTH_PROXY",
                "TRUSTED_AUTH_PROXY_SECRET",
                "TRUSTED_AUTH_PROXY_HEADER",
            ):
                os.environ.pop(k, None)
            os.environ.update(env_overrides)
            with self.subTest(rejected_env=env_overrides):
                c = app.test_client()
                r_home = c.get("/", headers={"X-Trusted-Auth-Proxy-Secret": env_overrides.get("TRUSTED_AUTH_PROXY_SECRET", proxy_secret)})
                html = r_home.data.decode("utf-8")
                self.assertIn('id="apiKeyInput"', html)
                self.assertEqual(self._extract_csrf(html), "")
                self.assertFalse(
                    any(h.startswith(f"{UI_SESSION_COOKIE_NAME}=") for h in r_home.headers.getlist("Set-Cookie"))
                )
                cookie_val, csrf_val = _create_ui_session_tokens(self.secret_key)
                c.set_cookie(UI_SESSION_COOKIE_NAME, cookie_val)
                r_post = c.post(
                    "/api/export-csv",
                    json={"leads": [{"Business Name": "Unsafe Non-Loopback"}]},
                    headers={
                        **self._same_origin_post_headers(csrf_val),
                        "X-Trusted-Auth-Proxy-Secret": env_overrides.get("TRUSTED_AUTH_PROXY_SECRET", proxy_secret),
                    },
                )
                self.assertEqual(r_post.status_code, 401)

        # 3. Direct unauthenticated backend access vs authenticated proxy access
        os.environ["HOST"] = "0.0.0.0"
        os.environ["UI_AUTO_SESSION"] = "true"
        os.environ["UI_AUTO_SESSION_BEHIND_TRUSTED_AUTH_PROXY"] = "true"
        os.environ["TRUSTED_PROXY_HOPS"] = "1"
        os.environ["TRUSTED_AUTH_PROXY_SECRET"] = proxy_secret

        # 3a. Direct backend GET / (missing or wrong proxy secret, even with spoofed X-Forwarded-For: 127.0.0.1) -> REJECTED
        for direct_hdrs in [
            {},
            {"X-Forwarded-For": "127.0.0.1", "Host": "localhost"},
            {"X-Trusted-Auth-Proxy-Secret": "wrong-proxy-secret"},
        ]:
            with self.subTest(direct_get_headers=direct_hdrs):
                c_direct = app.test_client()
                r_direct_home = c_direct.get("/", headers=direct_hdrs)
                self.assertIn('id="apiKeyInput"', r_direct_home.data.decode("utf-8"))
                self.assertEqual(self._extract_csrf(r_direct_home.data.decode("utf-8")), "")
                self.assertFalse(
                    any(h.startswith(f"{UI_SESSION_COOKIE_NAME}=") for h in r_direct_home.headers.getlist("Set-Cookie"))
                )

        # 3b. Authenticated proxy GET / -> issues session cookie + CSRF token
        c_proxy = app.test_client()
        r_proxy_home = c_proxy.get("/", headers={"X-Trusted-Auth-Proxy-Secret": proxy_secret})
        csrf = self._extract_csrf(r_proxy_home.data.decode("utf-8"))
        self.assertEqual(len(csrf), 64)
        self.assertNotIn('id="apiKeyInput"', r_proxy_home.data.decode("utf-8"))

        # 3c. Direct backend POST /api/export-csv bypassing proxy (even with valid cookie + CSRF + same-origin) -> 401
        r_direct_post_missing = c_proxy.post(
            "/api/export-csv",
            json={"leads": [{"Business Name": "Direct Bypass Attempt"}]},
            headers=self._same_origin_post_headers(csrf),
        )
        self.assertEqual(r_direct_post_missing.status_code, 401)

        r_direct_post_wrong = c_proxy.post(
            "/api/export-csv",
            json={"leads": [{"Business Name": "Direct Bypass Attempt"}]},
            headers={**self._same_origin_post_headers(csrf), "X-Trusted-Auth-Proxy-Secret": "wrong-secret"},
        )
        self.assertEqual(r_direct_post_wrong.status_code, 401)

        # 3d. Authenticated proxy POST /api/export-csv -> 200
        r_ok = c_proxy.post(
            "/api/export-csv",
            json={"leads": [{"Business Name": "Trusted Proxy UI"}]},
            headers={**self._same_origin_post_headers(csrf), "X-Trusted-Auth-Proxy-Secret": proxy_secret},
        )
        self.assertEqual(r_ok.status_code, 200)

        # 3e. Missing same-origin evidence still rejected even through authenticated proxy
        r_no_origin = c_proxy.post(
            "/api/export-csv",
            json={"leads": [{"Business Name": "Trusted Proxy UI"}]},
            headers={"X-CSRF-Token": csrf, "X-Trusted-Auth-Proxy-Secret": proxy_secret},
        )
        self.assertEqual(r_no_origin.status_code, 401)

        # 3f. Custom TRUSTED_AUTH_PROXY_HEADER respected and default header rejected
        os.environ["TRUSTED_AUTH_PROXY_HEADER"] = "X-Internal-Proxy-Proof"
        r_wrong_hdr_name = c_proxy.post(
            "/api/export-csv",
            json={"leads": [{"Business Name": "Trusted Proxy UI"}]},
            headers={**self._same_origin_post_headers(csrf), "X-Trusted-Auth-Proxy-Secret": proxy_secret},
        )
        self.assertEqual(r_wrong_hdr_name.status_code, 401)
        r_custom_hdr_ok = c_proxy.post(
            "/api/export-csv",
            json={"leads": [{"Business Name": "Trusted Proxy UI"}]},
            headers={**self._same_origin_post_headers(csrf), "X-Internal-Proxy-Proof": proxy_secret},
        )
        self.assertEqual(r_custom_hdr_ok.status_code, 200)

    def test_anonymous_and_programmatic_api_key_clients_preserve_contract(self):
        # Anonymous client without cookie/CSRF/API key receives 401
        anon_resp = self.client.post("/api/export-csv", json={"leads": [{"Business Name": "Test"}]})
        self.assertEqual(anon_resp.status_code, 401)

        # Programmatic X-API-Key and Bearer clients still work without cookie, CSRF, or Origin headers
        r_key = self.client.post(
            "/api/export-csv",
            json={"leads": [{"Business Name": "Test"}]},
            headers={"X-API-Key": self.secret_key},
        )
        self.assertEqual(r_key.status_code, 200)

        r_bearer = self.client.post(
            "/api/export-csv",
            json={"leads": [{"Business Name": "Test"}]},
            headers={"Authorization": f"Bearer {self.secret_key}"},
        )
        self.assertEqual(r_bearer.status_code, 200)

    def test_missing_or_invalid_csrf_token_rejected(self):
        resp = self.client.get("/")
        csrf_token = self._extract_csrf(resp.data.decode("utf-8"))
        self.assertTrue(csrf_token)

        # Cookie + same-origin present, CSRF header missing -> 401
        r_missing = self.client.post(
            "/api/export-csv",
            json={"leads": [{"Business Name": "Test"}]},
            headers={"Origin": "http://localhost", "Sec-Fetch-Site": "same-origin"},
        )
        self.assertEqual(r_missing.status_code, 401)

        # Cookie + same-origin present, wrong CSRF token -> 401
        r_wrong = self.client.post(
            "/api/export-csv",
            json={"leads": [{"Business Name": "Test"}]},
            headers=self._same_origin_post_headers("0" * 64),
        )
        self.assertEqual(r_wrong.status_code, 401)

        # Cookie + same-origin present, single-bit flipped CSRF token -> 401
        flipped = ("1" if csrf_token[0] == "0" else "0") + csrf_token[1:]
        r_flipped = self.client.post(
            "/api/export-csv",
            json={"leads": [{"Business Name": "Test"}]},
            headers=self._same_origin_post_headers(flipped),
        )
        self.assertEqual(r_flipped.status_code, 401)

    def test_missing_malformed_and_cross_origin_evidence_rejected_even_with_valid_session_and_csrf(self):
        resp = self.client.get("/")
        csrf_token = self._extract_csrf(resp.data.decode("utf-8"))

        # 1. Missing ALL origin evidence (no Origin, no Referer, no Sec-Fetch-Site) rejected on POST & GET
        r_post_no_evidence = self.client.post(
            "/api/export-csv",
            json={"leads": [{"Business Name": "Test"}]},
            headers={"X-CSRF-Token": csrf_token},
        )
        self.assertEqual(r_post_no_evidence.status_code, 401)

        r_get_no_evidence = self.client.get(
            "/api/jobs/nonexistent-id",
            headers={"X-CSRF-Token": csrf_token},
        )
        self.assertEqual(r_get_no_evidence.status_code, 401)

        # 2. Every malformed, null, mismatched, Sec-Fetch-Site: none, or cross-origin case rejected on POST
        rejected_post_cases = [
            # Sec-Fetch-Site: none rejected (both alone and alongside valid Origin/Referer)
            {"X-CSRF-Token": csrf_token, "Sec-Fetch-Site": "none"},
            {
                "X-CSRF-Token": csrf_token,
                "Origin": "http://localhost",
                "Referer": "http://localhost/",
                "Sec-Fetch-Site": "none",
            },
            # Sec-Fetch-Site: same-origin alone without Origin or Referer rejected on state-changing POST
            {"X-CSRF-Token": csrf_token, "Sec-Fetch-Site": "same-origin"},
            # Other invalid Sec-Fetch-Site values
            {"X-CSRF-Token": csrf_token, "Origin": "http://localhost", "Sec-Fetch-Site": "cross-site"},
            {"X-CSRF-Token": csrf_token, "Origin": "http://localhost", "Sec-Fetch-Site": "same-site"},
            {"X-CSRF-Token": csrf_token, "Origin": "http://localhost", "Sec-Fetch-Site": ""},
            {"X-CSRF-Token": csrf_token, "Origin": "http://localhost", "Sec-Fetch-Site": "malformed"},
            # Cross-origin, null, empty, and malformed Origin headers
            {"X-CSRF-Token": csrf_token, "Origin": "https://evil.example"},
            {"X-CSRF-Token": csrf_token, "Origin": "null"},
            {"X-CSRF-Token": csrf_token, "Origin": ""},
            {"X-CSRF-Token": csrf_token, "Origin": "not-a-url"},
            {"X-CSRF-Token": csrf_token, "Origin": "http://localhost:9999"},
            {"X-CSRF-Token": csrf_token, "Origin": "https://localhost"},
            {"X-CSRF-Token": csrf_token, "Origin": "http://user@localhost"},
            {"X-CSRF-Token": csrf_token, "Origin": "http://localhost/unexpected-path"},
            {"X-CSRF-Token": csrf_token, "Origin": "http://localhost?foo=bar"},
            # Cross-origin, empty, and malformed Referer headers
            {"X-CSRF-Token": csrf_token, "Referer": "https://evil.example/attack.html"},
            {"X-CSRF-Token": csrf_token, "Referer": ""},
            {"X-CSRF-Token": csrf_token, "Referer": "not-a-url"},
            {"X-CSRF-Token": csrf_token, "Referer": "javascript:alert(1)"},
            {"X-CSRF-Token": csrf_token, "Referer": "http://user@localhost/"},
            # Conflicting Origin + Referer pair
            {"X-CSRF-Token": csrf_token, "Origin": "http://localhost", "Referer": "https://evil.example/"},
        ]
        for hdrs in rejected_post_cases:
            with self.subTest(headers=hdrs):
                r = self.client.post(
                    "/api/export-csv",
                    json={"leads": [{"Business Name": "Test"}]},
                    headers=hdrs,
                )
                self.assertEqual(r.status_code, 401)

        # 3. Sec-Fetch-Site: none also rejected on GET
        r_get_none = self.client.get(
            "/api/jobs/nonexistent-id",
            headers={"X-CSRF-Token": csrf_token, "Sec-Fetch-Site": "none"},
        )
        self.assertEqual(r_get_none.status_code, 401)

    def test_tampered_expired_and_missing_session_cookies_rejected(self):
        import time as _time
        from app import UI_SESSION_COOKIE_NAME, _create_ui_session_tokens

        # 1. Missing cookie with valid-looking CSRF + same-origin headers -> 401
        _, orphan_csrf = _create_ui_session_tokens(self.secret_key)
        r_missing_cookie = self.client.post(
            "/api/export-csv",
            json={"leads": [{"Business Name": "Test"}]},
            headers=self._same_origin_post_headers(orphan_csrf),
        )
        self.assertEqual(r_missing_cookie.status_code, 401)

        # 2. Tampered cookie signature / payload -> 401
        valid_cookie, valid_csrf = _create_ui_session_tokens(self.secret_key)
        nonce, ts, sig = valid_cookie.split(".")
        tampered_cookies = [
            f"{nonce}.{ts}.{'0' * 64}",
            f"{'f' * 32}.{ts}.{sig}",
            f"{nonce}.{int(ts) + 1}.{sig}",
            "not-a-valid-cookie",
        ]
        for bad_cookie in tampered_cookies:
            with self.subTest(bad_cookie=bad_cookie):
                c = app.test_client()
                c.set_cookie(UI_SESSION_COOKIE_NAME, bad_cookie)
                r = c.post(
                    "/api/export-csv",
                    json={"leads": [{"Business Name": "Test"}]},
                    headers=self._same_origin_post_headers(valid_csrf),
                )
                self.assertEqual(r.status_code, 401)

        # 3. Expired session cookie -> 401
        os.environ["UI_SESSION_TTL_SECONDS"] = "60"
        expired_cookie, expired_csrf = _create_ui_session_tokens(
            self.secret_key, now=int(_time.time()) - 120
        )
        c_exp = app.test_client()
        c_exp.set_cookie(UI_SESSION_COOKIE_NAME, expired_cookie)
        r_exp = c_exp.post(
            "/api/export-csv",
            json={"leads": [{"Business Name": "Test"}]},
            headers=self._same_origin_post_headers(expired_csrf),
        )
        self.assertEqual(r_exp.status_code, 401)

        # 4. Future-skewed session cookie -> 401
        future_cookie, future_csrf = _create_ui_session_tokens(
            self.secret_key, now=int(_time.time()) + 300
        )
        c_fut = app.test_client()
        c_fut.set_cookie(UI_SESSION_COOKIE_NAME, future_cookie)
        r_fut = c_fut.post(
            "/api/export-csv",
            json={"leads": [{"Business Name": "Test"}]},
            headers=self._same_origin_post_headers(future_csrf),
        )
        self.assertEqual(r_fut.status_code, 401)

    def test_production_defaults_disable_ui_auto_session_and_enforce_secure_cookie_when_opted_in(self):
        import fakeredis
        from app import UI_SESSION_COOKIE_NAME, _create_ui_session_tokens
        from services.runtime_config import is_ui_auto_session_enabled

        rate_limiter.set_redis_client(fakeredis.FakeRedis())
        for env_k, env_v in [("LEADHUNTER_ENV", "production"), ("FLASK_ENV", "production"), ("RENDER", "true")]:
            for k in ("LEADHUNTER_ENV", "FLASK_ENV", "RENDER", "UI_AUTO_SESSION"):
                os.environ.pop(k, None)
            os.environ[env_k] = env_v

            with self.subTest(prod_env=f"{env_k}={env_v}"):
                self.assertFalse(is_ui_auto_session_enabled())
                c = app.test_client()
                r_index = c.get("/")
                html = r_index.data.decode("utf-8")
                self.assertEqual(r_index.status_code, 200)
                self.assertIn('id="apiKeyInput"', html)
                self.assertEqual(self._extract_csrf(html), "")
                self.assertFalse(
                    any(h.startswith(f"{UI_SESSION_COOKIE_NAME}=") for h in r_index.headers.getlist("Set-Cookie"))
                )

                # Even a validly signed cookie+CSRF+same-origin MUST be rejected in production default mode
                cookie_val, csrf_val = _create_ui_session_tokens(self.secret_key)
                c.set_cookie(UI_SESSION_COOKIE_NAME, cookie_val)
                r_cookie = c.post(
                    "/api/export-csv",
                    json={"leads": [{"Business Name": "Test"}]},
                    headers=self._same_origin_post_headers(csrf_val),
                )
                self.assertEqual(r_cookie.status_code, 401)

                # Programmatic X-API-Key still succeeds in production
                r_api = c.post(
                    "/api/export-csv",
                    json={"leads": [{"Business Name": "Test"}]},
                    headers={"X-API-Key": self.secret_key},
                )
                self.assertEqual(r_api.status_code, 200)

        # Production with UI_AUTO_SESSION=true alone (or + TRUSTED_PROXY_HOPS alone) MUST stay rejected
        os.environ["LEADHUNTER_ENV"] = "production"
        os.environ["UI_AUTO_SESSION"] = "true"
        os.environ.pop("UI_AUTO_SESSION_BEHIND_TRUSTED_AUTH_PROXY", None)
        os.environ.pop("TRUSTED_PROXY_HOPS", None)
        r_prod_unsafe = app.test_client().get("/")
        self.assertEqual(self._extract_csrf(r_prod_unsafe.data.decode("utf-8")), "")
        self.assertFalse(
            any(h.startswith(f"{UI_SESSION_COOKIE_NAME}=") for h in r_prod_unsafe.headers.getlist("Set-Cookie"))
        )

        os.environ["TRUSTED_PROXY_HOPS"] = "1"
        r_prod_hops_only = app.test_client().get("/")
        self.assertEqual(self._extract_csrf(r_prod_hops_only.data.decode("utf-8")), "")
        self.assertFalse(
            any(h.startswith(f"{UI_SESSION_COOKIE_NAME}=") for h in r_prod_hops_only.headers.getlist("Set-Cookie"))
        )

        # Explicit trusted-auth-proxy opt-in + TRUSTED_PROXY_HOPS > 0 + UI_AUTO_SESSION=true +
        # distinct TRUSTED_AUTH_PROXY_SECRET verified per-request in production sets Secure + HttpOnly + SameSite=Strict
        prod_proxy_secret = "prod-authenticating-proxy-secret-abc123"
        os.environ["UI_AUTO_SESSION_BEHIND_TRUSTED_AUTH_PROXY"] = "true"
        os.environ["TRUSTED_AUTH_PROXY_SECRET"] = prod_proxy_secret

        # Direct request without proxy secret header MUST still be rejected in production
        r_prod_direct = app.test_client().get("/")
        self.assertEqual(self._extract_csrf(r_prod_direct.data.decode("utf-8")), "")
        self.assertFalse(
            any(h.startswith(f"{UI_SESSION_COOKIE_NAME}=") for h in r_prod_direct.headers.getlist("Set-Cookie"))
        )

        # Request with valid proxy secret header succeeds and enforces Secure + HttpOnly + SameSite=Strict
        c_opt = app.test_client()
        r_opt = c_opt.get("/", headers={"X-Trusted-Auth-Proxy-Secret": prod_proxy_secret})
        cookie_hdr = [
            h for h in r_opt.headers.getlist("Set-Cookie") if h.startswith(f"{UI_SESSION_COOKIE_NAME}=")
        ][0]
        self.assertIn("HttpOnly", cookie_hdr)
        self.assertIn("SameSite=Strict", cookie_hdr)
        self.assertIn("Secure", cookie_hdr)

    def test_missing_api_key_still_fails_closed_with_503_and_rate_limit_applies_to_ui_session(self):
        from app import UI_SESSION_COOKIE_NAME

        # Missing LEADHUNTER_API_KEY -> GET / issues no cookie/CSRF, API fails closed with 503
        os.environ.pop("LEADHUNTER_API_KEY", None)
        c_no_key = app.test_client()
        r_home = c_no_key.get("/")
        self.assertEqual(self._extract_csrf(r_home.data.decode("utf-8")), "")
        self.assertFalse(
            any(h.startswith(f"{UI_SESSION_COOKIE_NAME}=") for h in r_home.headers.getlist("Set-Cookie"))
        )
        r_503 = c_no_key.post("/api/jobs", json={"url": "https://example.com", "type": "website"})
        self.assertEqual(r_503.status_code, 503)

        # Rate limiting still applies to UI-session-authenticated requests
        os.environ["LEADHUNTER_API_KEY"] = self.secret_key
        os.environ["RATE_LIMIT_MAX_REQUESTS"] = "2"
        rate_limiter.reset()
        c_rl = app.test_client()
        csrf = self._extract_csrf(c_rl.get("/").data.decode("utf-8"))
        for _ in range(2):
            self.assertEqual(
                c_rl.post(
                    "/api/export-csv",
                    json={"leads": [{"Business Name": "RL Test"}]},
                    headers=self._same_origin_post_headers(csrf),
                ).status_code,
                200,
            )
        r_429 = c_rl.post(
            "/api/export-csv",
            json={"leads": [{"Business Name": "RL Test"}]},
            headers=self._same_origin_post_headers(csrf),
        )
        self.assertEqual(r_429.status_code, 429)


class TestExplicitUiSessionAndFrontendWorkflow(unittest.TestCase):
    """
    Verifies explicit interactive UI session authentication (`POST /api/ui-session`,
    `DELETE /api/ui-session`), domain-separated tokens, server-side logout revocation,
    multi-URL auth propagation, zero browser storage of API keys, and accurate partial/auth
    failure reporting in `templates/index.html`.
    """

    def setUp(self):
        self._orig_env = dict(os.environ)
        self.secret_key = "explicit-ui-session-secret-key-987654"
        os.environ["LEADHUNTER_API_KEY"] = self.secret_key
        os.environ["UI_AUTO_SESSION"] = "false"
        os.environ["CONTAINER"] = "true"
        os.environ["LEADHUNTER_ENV"] = "development"
        os.environ["RATE_LIMIT_MAX_REQUESTS"] = "200"
        os.environ["RATE_LIMIT_WINDOW_SECONDS"] = "60"
        for k in (
            "FLASK_ENV",
            "RENDER",
            "TRUSTED_PROXY_HOPS",
            "UI_AUTO_SESSION_BEHIND_TRUSTED_AUTH_PROXY",
            "TRUSTED_AUTH_PROXY_SECRET",
            "REDIS_URL",
        ):
            os.environ.pop(k, None)
        rate_limiter.reset()

    def tearDown(self):
        from services.job_queue import set_redis_connection
        set_redis_connection(None)
        rate_limiter.set_redis_client(None)
        os.environ.clear()
        os.environ.update(self._orig_env)
        rate_limiter.reset()

    @staticmethod
    def _same_origin_post_headers(csrf_token: str = "", extra: dict | None = None) -> dict:
        hdrs = {"Origin": "http://localhost", "Sec-Fetch-Site": "same-origin"}
        if csrf_token:
            hdrs["X-CSRF-Token"] = csrf_token
        if extra:
            hdrs.update(extra)
        return hdrs

    @staticmethod
    def _same_origin_get_headers(csrf_token: str = "") -> dict:
        hdrs = {"Sec-Fetch-Site": "same-origin", "Referer": "http://localhost/"}
        if csrf_token:
            hdrs["X-CSRF-Token"] = csrf_token
        return hdrs

    @staticmethod
    def _extract_csrf(html: str) -> str:
        m = re.search(r'<meta\s+name="csrf-token"\s+content="([^"]+)"', html)
        return m.group(1) if m else ""

    @staticmethod
    def _extract_cookie_value(resp, cookie_name: str) -> str:
        for hdr in resp.headers.getlist("Set-Cookie"):
            if hdr.startswith(f"{cookie_name}="):
                return hdr.split("=", 1)[1].split(";", 1)[0]
        return ""

    def test_explicit_ui_session_login_multi_url_propagation_reload_and_logout_revocation(self):
        import fakeredis
        from app import UI_SESSION_COOKIE_NAME
        from services.job_queue import set_redis_connection

        fake_redis = fakeredis.FakeRedis()
        set_redis_connection(fake_redis)

        client = app.test_client()

        # 1. Unauthenticated GET / with UI_AUTO_SESSION=false issues no cookie, no CSRF, no secret
        r_home = client.get("/")
        html_locked = r_home.data.decode("utf-8")
        self.assertEqual(r_home.status_code, 200)
        self.assertEqual(self._extract_csrf(html_locked), "")
        self.assertEqual(self._extract_cookie_value(r_home, UI_SESSION_COOKIE_NAME), "")
        self.assertNotIn(self.secret_key, html_locked)
        self.assertIn('id="apiKeyInput"', html_locked)
        self.assertIn('id="btnUnlockSession"', html_locked)

        # 2. Unauthenticated API request rejected with 401
        r_unauth = client.post("/api/jobs", json={"url": "https://example.com", "type": "website"})
        self.assertEqual(r_unauth.status_code, 401)

        # 3. POST /api/ui-session rejects cross-origin, missing key, and invalid key
        r_cross = client.post(
            "/api/ui-session",
            json={},
            headers={"Origin": "https://evil.example", "X-API-Key": self.secret_key},
        )
        self.assertEqual(r_cross.status_code, 403)
        r_missing_key = client.post("/api/ui-session", json={}, headers=self._same_origin_post_headers())
        self.assertEqual(r_missing_key.status_code, 401)
        r_wrong_key = client.post(
            "/api/ui-session",
            json={},
            headers=self._same_origin_post_headers(extra={"X-API-Key": "wrong-key"}),
        )
        self.assertEqual(r_wrong_key.status_code, 401)

        # 4. Valid login exchanges X-API-Key for HttpOnly SameSite=Strict cookie + paired CSRF token
        r_login = client.post(
            "/api/ui-session",
            json={},
            headers=self._same_origin_post_headers(extra={"X-API-Key": self.secret_key}),
        )
        self.assertEqual(r_login.status_code, 200)
        login_data = r_login.get_json()
        self.assertTrue(login_data["success"])
        self.assertTrue(login_data["authenticated"])
        csrf_token = login_data["csrf_token"]
        self.assertTrue(csrf_token)
        self.assertNotIn(self.secret_key, r_login.data.decode("utf-8"))
        self.assertEqual(r_login.headers.get("Cache-Control"), "no-store")
        set_cookie_hdr = [
            h for h in r_login.headers.getlist("Set-Cookie") if h.startswith(f"{UI_SESSION_COOKIE_NAME}=")
        ][0]
        self.assertIn("HttpOnly", set_cookie_hdr)
        self.assertIn("SameSite=Strict", set_cookie_hdr)
        captured_cookie = self._extract_cookie_value(r_login, UI_SESSION_COOKIE_NAME)
        self.assertTrue(captured_cookie)

        # 5. Page reload preserves unlocked session by re-deriving paired CSRF without leaking API key
        r_reload = client.get("/")
        html_unlocked = r_reload.data.decode("utf-8")
        self.assertEqual(self._extract_csrf(html_unlocked), csrf_token)
        self.assertEqual(r_reload.headers.get("Cache-Control"), "no-store")
        self.assertNotIn(self.secret_key, html_unlocked)

        # 6. Multi-URL per-URL job submission, polling, and result retrieval all succeed via cookie + CSRF
        urls = ["https://alpha.example.com", "https://beta.example.com", "https://gamma.example.com"]
        with patch("app.validate_and_sanitize_url", side_effect=lambda u: u), \
             patch(
                 "app.enqueue_scrape_job",
                 side_effect=lambda **kw: {
                     "job_id": f"job-{abs(hash(kw['url'])) % 100000}",
                     "status": "queued",
                     "deduplicated": False,
                     "workers_online": 1,
                 },
             ), \
             patch(
                 "app.get_job_status_payload",
                 side_effect=lambda jid: {"success": True, "job_id": jid, "status": "finished", "progress": {}},
             ), \
             patch(
                 "app.get_job_result_payload",
                 side_effect=lambda jid: (
                     {"success": True, "status": "finished", "count": 1, "data": {"Business Name": jid, "Website": "https://example.com"}},
                     200,
                 ),
             ):
            for u in urls:
                r_enq = client.post(
                    "/api/jobs",
                    json={"url": u, "type": "website"},
                    headers=self._same_origin_post_headers(csrf_token),
                )
                self.assertEqual(r_enq.status_code, 202, r_enq.data)
                jid = r_enq.get_json()["job_id"]

                r_st = client.get(f"/api/jobs/{jid}", headers=self._same_origin_get_headers(csrf_token))
                self.assertEqual(r_st.status_code, 200)
                self.assertEqual(r_st.get_json()["status"], "finished")

                r_res = client.get(f"/api/jobs/{jid}/result", headers=self._same_origin_get_headers(csrf_token))
                self.assertEqual(r_res.status_code, 200)
                self.assertTrue(r_res.get_json()["success"])

            # 7. Missing CSRF, cross-origin, and bad explicit X-API-Key alongside valid cookie MUST fail (401)
            self.assertEqual(
                client.post(
                    "/api/jobs",
                    json={"url": urls[0], "type": "website"},
                    headers=self._same_origin_post_headers(""),
                ).status_code,
                401,
            )
            self.assertEqual(
                client.post(
                    "/api/jobs",
                    json={"url": urls[0], "type": "website"},
                    headers={"Origin": "https://evil.example", "X-CSRF-Token": csrf_token},
                ).status_code,
                401,
            )
            self.assertEqual(
                client.post(
                    "/api/jobs",
                    json={"url": urls[0], "type": "website"},
                    headers=self._same_origin_post_headers(csrf_token, extra={"X-API-Key": "wrong-key"}),
                ).status_code,
                401,
            )

            # 8. DELETE /api/ui-session rejects missing CSRF (logout CSRF protection) & cross-origin
            self.assertEqual(
                client.delete("/api/ui-session", headers=self._same_origin_post_headers("")).status_code,
                401,
            )
            self.assertEqual(
                client.delete(
                    "/api/ui-session",
                    headers={"Origin": "https://evil.example", "X-CSRF-Token": csrf_token},
                ).status_code,
                403,
            )

            # 9. Valid logout revokes the explicit session server-side and clears cookie
            r_logout = client.delete("/api/ui-session", headers=self._same_origin_post_headers(csrf_token))
            self.assertEqual(r_logout.status_code, 200)
            self.assertFalse(r_logout.get_json()["authenticated"])

            # 10. Replaying the captured pre-logout cookie + CSRF MUST be rejected (401) even if resent manually
            replay_client = app.test_client()
            replay_client.set_cookie(UI_SESSION_COOKIE_NAME, captured_cookie)
            r_replay_api = replay_client.post(
                "/api/jobs",
                json={"url": urls[0], "type": "website"},
                headers=self._same_origin_post_headers(csrf_token),
            )
            self.assertEqual(r_replay_api.status_code, 401)
            r_replay_home = replay_client.get("/")
            self.assertEqual(self._extract_csrf(r_replay_home.data.decode("utf-8")), "")

    def test_explicit_and_auto_session_tokens_are_cryptographically_separated_and_expire(self):
        import time
        from app import (
            UI_SESSION_COOKIE_NAME,
            UI_SESSION_MODE_AUTO,
            UI_SESSION_MODE_EXPLICIT,
            _create_ui_session_tokens,
            _verify_ui_session_and_csrf,
        )

        now = int(time.time())
        auto_cookie, auto_csrf = _create_ui_session_tokens(self.secret_key, now=now, mode=UI_SESSION_MODE_AUTO)
        exp_cookie, exp_csrf = _create_ui_session_tokens(self.secret_key, now=now, mode=UI_SESSION_MODE_EXPLICIT)

        # Domain separation: auto != explicit
        self.assertTrue(_verify_ui_session_and_csrf(auto_cookie, auto_csrf, self.secret_key, now=now, mode=UI_SESSION_MODE_AUTO))
        self.assertFalse(_verify_ui_session_and_csrf(auto_cookie, auto_csrf, self.secret_key, now=now, mode=UI_SESSION_MODE_EXPLICIT))
        self.assertTrue(_verify_ui_session_and_csrf(exp_cookie, exp_csrf, self.secret_key, now=now, mode=UI_SESSION_MODE_EXPLICIT))
        self.assertFalse(_verify_ui_session_and_csrf(exp_cookie, exp_csrf, self.secret_key, now=now, mode=UI_SESSION_MODE_AUTO))

        # Auto-session cookie MUST NOT authenticate when UI_AUTO_SESSION=false
        c_auto = app.test_client()
        c_auto.set_cookie(UI_SESSION_COOKIE_NAME, auto_cookie)
        r_reject_auto = c_auto.post(
            "/api/export-csv",
            json={"leads": [{"Business Name": "Test"}]},
            headers=self._same_origin_post_headers(auto_csrf),
        )
        self.assertEqual(r_reject_auto.status_code, 401)

        # Expired explicit session MUST fail
        old_cookie, old_csrf = _create_ui_session_tokens(
            self.secret_key, now=now - 40000, mode=UI_SESSION_MODE_EXPLICIT
        )
        self.assertFalse(_verify_ui_session_and_csrf(old_cookie, old_csrf, self.secret_key, now=now, mode=UI_SESSION_MODE_EXPLICIT))
        c_old = app.test_client()
        c_old.set_cookie(UI_SESSION_COOKIE_NAME, old_cookie)
        r_expired = c_old.post(
            "/api/export-csv",
            json={"leads": [{"Business Name": "Test"}]},
            headers=self._same_origin_post_headers(old_csrf),
        )
        self.assertEqual(r_expired.status_code, 401)

        # Production login fails closed (429) if Redis rate limiter is unconfigured,
        # and sets Secure + HttpOnly + SameSite=Strict when Redis is available
        import fakeredis
        os.environ["LEADHUNTER_ENV"] = "production"
        r_prod_no_redis = app.test_client().post(
            "/api/ui-session",
            json={},
            headers=self._same_origin_post_headers(extra={"X-API-Key": self.secret_key}),
        )
        self.assertEqual(r_prod_no_redis.status_code, 429)

        rate_limiter.set_redis_client(fakeredis.FakeRedis())
        c_prod = app.test_client()
        r_prod_login = c_prod.post(
            "/api/ui-session",
            json={},
            headers=self._same_origin_post_headers(extra={"X-API-Key": self.secret_key}),
        )
        self.assertEqual(r_prod_login.status_code, 200)
        prod_cookie_hdr = [
            h for h in r_prod_login.headers.getlist("Set-Cookie") if h.startswith(f"{UI_SESSION_COOKIE_NAME}=")
        ][0]
        self.assertIn("Secure", prod_cookie_hdr)
        self.assertIn("HttpOnly", prod_cookie_hdr)
        self.assertIn("SameSite=Strict", prod_cookie_hdr)

        os.environ.pop("LEADHUNTER_API_KEY", None)
        r_503 = app.test_client().post("/api/ui-session", json={}, headers=self._same_origin_post_headers())
        self.assertEqual(r_503.status_code, 503)

    def test_frontend_zero_storage_auth_propagation_partial_failure_and_401_short_circuit_in_chromium(self):
        from pathlib import Path
        from playwright.sync_api import sync_playwright

        # 1. Static source audit: never write/read leadhunter_api_key in sessionStorage/localStorage
        tpl_path = Path(__file__).resolve().parent.parent / "templates" / "index.html"
        tpl_src = tpl_path.read_text(encoding="utf-8")
        self.assertNotIn("sessionStorage.setItem('leadhunter_api_key'", tpl_src)
        self.assertNotIn('sessionStorage.setItem("leadhunter_api_key"', tpl_src)
        self.assertNotIn("sessionStorage.getItem('leadhunter_api_key'", tpl_src)
        self.assertNotIn('sessionStorage.getItem("leadhunter_api_key"', tpl_src)
        self.assertNotIn("localStorage.setItem('leadhunter_api_key'", tpl_src)
        self.assertNotIn('localStorage.setItem("leadhunter_api_key"', tpl_src)
        self.assertNotIn("localStorage.getItem('leadhunter_api_key'", tpl_src)

        # Render the real template as served when UI_AUTO_SESSION=false
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
                # Serve rendered HTML at http://localhost/ so sessionStorage/localStorage are enabled
                page.route(
                    "http://localhost/",
                    lambda route: route.fulfill(status=200, body=rendered_html, content_type="text/html; charset=utf-8"),
                )
                # Seed legacy browser storage keys BEFORE page loads to confirm cleanup on DOMContentLoaded
                page.add_init_script("""
                    sessionStorage.setItem('leadhunter_api_key', 'legacy-leaked-secret');
                    localStorage.setItem('leadhunter_api_key', 'legacy-leaked-secret');
                """)
                page.goto("http://localhost/", wait_until="domcontentloaded")

                result = page.evaluate("""async () => {
                    // Speed up polling timers in runAsyncScrapeJob
                    const origSetTimeout = window.setTimeout;
                    window.setTimeout = (fn, ms) => origSetTimeout(fn, Math.min(ms || 0, 5));

                    const legacyCleared = (
                        sessionStorage.getItem('leadhunter_api_key') === null &&
                        localStorage.getItem('leadhunter_api_key') === null
                    );

                    const calls = [];
                    let mode = 'partial';
                    let jobSeq = 0;

                    window.fetch = async (url, opts = {}) => {
                        const headers = opts.headers || {};
                        calls.push({ url: String(url), method: opts.method || 'GET', headers: { ...headers }, credentials: opts.credentials });
                        const mkJson = (status, obj) => ({
                            ok: status >= 200 && status < 300,
                            status,
                            headers: { get: (k) => k.toLowerCase() === 'content-type' ? 'application/json' : null },
                            json: async () => obj
                        });

                        if (url === '/api/ui-session' && opts.method === 'POST') {
                            if (headers['X-API-Key'] === 'valid-operator-key') {
                                return mkJson(200, { success: true, authenticated: true, csrf_token: 'csrf-memory-token-abc' });
                            }
                            return mkJson(401, { success: false, error: 'Unauthorized: valid API key required.' });
                        }
                        if (url === '/api/ui-session' && opts.method === 'DELETE') {
                            return mkJson(200, { success: true, authenticated: false });
                        }
                        if (url === '/api/jobs' && opts.method === 'POST') {
                            jobSeq += 1;
                            if (mode === 'auth_abort' && jobSeq === 2) {
                                return mkJson(401, { success: false, error: 'Unauthorized: valid API key required.' });
                            }
                            if (mode === 'all_fail') {
                                return mkJson(422, { success: false, error: 'Target unreachable' });
                            }
                            if (mode === 'partial' && jobSeq === 2) {
                                return mkJson(422, { success: false, error: 'Target unreachable' });
                            }
                            return mkJson(202, { success: true, job_id: 'job-' + jobSeq, status: 'queued' });
                        }
                        if (String(url).startsWith('/api/jobs/') && !String(url).endsWith('/result')) {
                            const jid = String(url).split('/').pop();
                            return mkJson(200, { success: true, job_id: jid, status: 'finished', progress: { message: 'Done' } });
                        }
                        if (String(url).endsWith('/result')) {
                            return mkJson(200, {
                                success: true,
                                status: 'finished',
                                count: 1,
                                data: {
                                    'Business Name': 'Test Co',
                                    'Website': 'https://example.com',
                                    'Email': 'owner@example.com',
                                    'Email Verification': 'Verified',
                                    'intelligence': { technical: { status: 'OK' }, seo: { status: 'OK' }, opportunities: { detected_opportunities: [] } }
                                }
                            });
                        }
                        return mkJson(404, { success: false, error: 'Not found' });
                    };

                    // Scenario A: Pre-flight auth guard blocks unauthenticated start without calling /api/jobs
                    document.getElementById('manualUrls').value = 'https://a.example.com\\nhttps://b.example.com';
                    await startManualScraping();
                    const scenarioA = {
                        callsCount: calls.length,
                        statusText: document.getElementById('statusText').textContent
                    };

                    // Unlock session via UI input; verify input cleared and zero browser storage written
                    document.getElementById('apiKeyInput').value = 'valid-operator-key';
                    const unlockRes = await unlockUiSession();
                    const afterUnlock = {
                        ok: unlockRes.ok,
                        inputCleared: document.getElementById('apiKeyInput').value === '',
                        sessionStorageKey: sessionStorage.getItem('leadhunter_api_key'),
                        localStorageKey: localStorage.getItem('leadhunter_api_key'),
                        lockedHidden: document.getElementById('uiAuthLocked').classList.contains('hidden'),
                        unlockedVisible: !document.getElementById('uiAuthUnlocked').classList.contains('hidden')
                    };

                    // Scenario B: Partial failure (2 succeed, 1 fails) on 3-URL file enrichment batch
                    calls.length = 0;
                    jobSeq = 0;
                    mode = 'partial';
                    inputType = 'file';
                    scrapeMode = 'website';
                    uploadedData = [
                        { 'Business Name': 'Biz 1', 'Website': 'https://b1.example.com', intelligence: null },
                        { 'Business Name': 'Biz 2', 'Website': 'https://b2.example.com', intelligence: null },
                        { 'Business Name': 'Biz 3', 'Website': 'https://b3.example.com', intelligence: null },
                        { 'Business Name': 'Biz 4 No Web', 'Website': '', intelligence: null }
                    ];
                    targetQueue = [
                        { rowIndex: 0, url: 'https://b1.example.com', business_name: 'Biz 1', decision_maker: '' },
                        { rowIndex: 1, url: 'https://b2.example.com', business_name: 'Biz 2', decision_maker: '' },
                        { rowIndex: 2, url: 'https://b3.example.com', business_name: 'Biz 3', decision_maker: '' }
                    ];
                    showProgress(true);
                    await processQueue();
                    const apiCallsB = calls.filter(c => c.url.startsWith('/api/jobs'));
                    const scenarioB = {
                        allCarryCsrf: apiCallsB.every(c => c.headers['X-CSRF-Token'] === 'csrf-memory-token-abc'),
                        allSameOriginCreds: apiCallsB.every(c => c.credentials === 'same-origin'),
                        noneSendRawApiKey: apiCallsB.every(c => !('X-API-Key' in c.headers)),
                        scanned: document.getElementById('statWebsitesScanned').textContent,
                        succeeded: document.getElementById('statSuccessfulAudits').textContent,
                        failed: document.getElementById('statFailedAudits').textContent,
                        progressCount: document.getElementById('progressCount').textContent,
                        statusText: document.getElementById('statusText').textContent,
                        downloadVisible: !document.getElementById('downloadSection').classList.contains('hidden')
                    };

                    // Scenario C: Mid-queue 401 short-circuit on 5-URL batch (URL 1 ok, URL 2 -> 401, URLs 3-5 skipped)
                    calls.length = 0;
                    jobSeq = 0;
                    mode = 'auth_abort';
                    targetQueue = [0, 1, 2, 3, 4].map(i => ({ url: `https://s${i}.example.com` }));
                    inputType = 'manual';
                    showProgress(true);
                    await processQueue();
                    const submitCallsC = calls.filter(c => c.url === '/api/jobs' && c.method === 'POST');
                    const scenarioC = {
                        submitCallCount: submitCallsC.length,
                        scanned: document.getElementById('statWebsitesScanned').textContent,
                        succeeded: document.getElementById('statSuccessfulAudits').textContent,
                        failed: document.getElementById('statFailedAudits').textContent,
                        progressCount: document.getElementById('progressCount').textContent,
                        statusText: document.getElementById('statusText').textContent,
                        relocked: !document.getElementById('uiAuthLocked').classList.contains('hidden')
                    };

                    // Scenario D: Re-unlock, then 100% failure (0/2 audited) -> must NOT say Complete and must hide export
                    await unlockUiSession('valid-operator-key');
                    calls.length = 0;
                    jobSeq = 0;
                    mode = 'all_fail';
                    targetQueue = [{ url: 'https://f1.example.com' }, { url: 'https://f2.example.com' }];
                    inputType = 'manual';
                    showProgress(true);
                    await processQueue();
                    const scenarioD = {
                        scanned: document.getElementById('statWebsitesScanned').textContent,
                        succeeded: document.getElementById('statSuccessfulAudits').textContent,
                        failed: document.getElementById('statFailedAudits').textContent,
                        statusText: document.getElementById('statusText').textContent,
                        downloadHidden: document.getElementById('downloadSection').classList.contains('hidden')
                    };

                    // Lock session cleans up UI state
                    await lockUiSession();
                    const afterLock = {
                        lockedVisible: !document.getElementById('uiAuthLocked').classList.contains('hidden'),
                        unlockedHidden: document.getElementById('uiAuthUnlocked').classList.contains('hidden')
                    };

                    return { legacyCleared, scenarioA, afterUnlock, scenarioB, scenarioC, scenarioD, afterLock };
                }""")

                self.assertTrue(result["legacyCleared"])
                self.assertEqual(result["scenarioA"]["callsCount"], 0)
                self.assertIn("Authentication Required", result["scenarioA"]["statusText"])

                self.assertTrue(result["afterUnlock"]["ok"])
                self.assertTrue(result["afterUnlock"]["inputCleared"])
                self.assertIsNone(result["afterUnlock"]["sessionStorageKey"])
                self.assertIsNone(result["afterUnlock"]["localStorageKey"])
                self.assertTrue(result["afterUnlock"]["lockedHidden"])
                self.assertTrue(result["afterUnlock"]["unlockedVisible"])

                self.assertTrue(result["scenarioB"]["allCarryCsrf"])
                self.assertTrue(result["scenarioB"]["allSameOriginCreds"])
                self.assertTrue(result["scenarioB"]["noneSendRawApiKey"])
                self.assertEqual(result["scenarioB"]["scanned"], "3")
                self.assertEqual(result["scenarioB"]["succeeded"], "2")
                self.assertEqual(result["scenarioB"]["failed"], "1")
                self.assertIn("3 / 3 URLs processed (2 audited, 1 failed)", result["scenarioB"]["progressCount"])
                self.assertIn("Completed with Failures", result["scenarioB"]["statusText"])
                self.assertTrue(result["scenarioB"]["downloadVisible"])

                self.assertEqual(result["scenarioC"]["submitCallCount"], 2)
                self.assertEqual(result["scenarioC"]["scanned"], "2")
                self.assertEqual(result["scenarioC"]["succeeded"], "1")
                self.assertEqual(result["scenarioC"]["failed"], "1")
                self.assertIn("2 / 5 URLs processed (1 audited, 1 failed)", result["scenarioC"]["progressCount"])
                self.assertIn("Stopped — Authentication Required", result["scenarioC"]["statusText"])
                self.assertTrue(result["scenarioC"]["relocked"])

                self.assertEqual(result["scenarioD"]["scanned"], "2")
                self.assertEqual(result["scenarioD"]["succeeded"], "0")
                self.assertEqual(result["scenarioD"]["failed"], "2")
                self.assertIn("Audit Failed (0 / 2 URLs audited)", result["scenarioD"]["statusText"])
                self.assertTrue(result["scenarioD"]["downloadHidden"])

                self.assertTrue(result["afterLock"]["lockedVisible"])
                self.assertTrue(result["afterLock"]["unlockedHidden"])
            finally:
                browser.close()

    def test_independent_read_and_write_rate_limit_buckets_recovery_and_api_key_compatibility(self):
        import time
        import fakeredis
        from services.job_queue import set_redis_connection

        fake_redis = fakeredis.FakeRedis()
        set_redis_connection(fake_redis)
        rate_limiter.set_redis_client(fake_redis)
        os.environ["RATE_LIMIT_MAX_REQUESTS"] = "2"
        os.environ["RATE_LIMIT_WINDOW_SECONDS"] = "60"
        os.environ["RATE_LIMIT_READ_MAX_REQUESTS"] = "3"
        os.environ["RATE_LIMIT_READ_WINDOW_SECONDS"] = "1"
        os.environ["RATE_LIMIT_FAIL_CLOSED"] = "true"
        rate_limiter.reset()

        client = app.test_client()
        x_headers = {"X-API-Key": self.secret_key}
        bearer_headers = {"Authorization": f"Bearer {self.secret_key}"}

        with patch("app.validate_and_sanitize_url", side_effect=lambda u: u), \
             patch(
                 "app.enqueue_scrape_job",
                 return_value={"job_id": "job-rl-1", "status": "queued", "deduplicated": False, "workers_online": 1},
             ), \
             patch(
                 "app.get_job_status_payload",
                 return_value={"success": True, "job_id": "job-rl-1", "status": "finished", "progress": {}},
             ), \
             patch(
                 "app.get_job_result_payload",
                 return_value=({"success": True, "status": "finished", "count": 1, "data": {"Business Name": "A"}}, 200),
             ):
            # 1. Exhaust write bucket (2 allowed, 3rd -> 429) using X-API-Key & Bearer
            self.assertEqual(client.post("/api/jobs", json={"url": "https://a.example.com", "type": "website"}, headers=x_headers).status_code, 202)
            self.assertEqual(client.post("/api/jobs", json={"url": "https://b.example.com", "type": "website"}, headers=bearer_headers).status_code, 202)
            r_write_429 = client.post("/api/jobs", json={"url": "https://c.example.com", "type": "website"}, headers=x_headers)
            self.assertEqual(r_write_429.status_code, 429)
            self.assertTrue(int(r_write_429.headers.get("Retry-After", "0")) >= 1)

            # 2. Read bucket is INDEPENDENT: GET /api/jobs/<id> & /result still succeed up to 3 reads!
            self.assertEqual(client.get("/api/jobs/job-rl-1", headers=x_headers).status_code, 200)
            self.assertEqual(client.get("/api/jobs/job-rl-1", headers=bearer_headers).status_code, 200)
            self.assertEqual(client.get("/api/jobs/job-rl-1/result", headers=x_headers).status_code, 200)

            # 3. 4th read exhausts the read bucket -> 429 with Retry-After (not exempted!)
            r_read_429 = client.get("/api/jobs/job-rl-1", headers=x_headers)
            self.assertEqual(r_read_429.status_code, 429)
            self.assertTrue(int(r_read_429.headers.get("Retry-After", "0")) >= 1)

            # Verify separate Redis keys for write vs read buckets
            self.assertEqual(fake_redis.zcard("leadhunter:ratelimit:127.0.0.1"), 2)
            self.assertEqual(fake_redis.zcard("leadhunter:ratelimit:read:127.0.0.1"), 3)

            # 4. Read bucket recovers after its 1-second sliding window expires while write stays exhausted
            time.sleep(1.15)
            self.assertEqual(client.get("/api/jobs/job-rl-1", headers=bearer_headers).status_code, 200)
            self.assertEqual(client.post("/api/jobs", json={"url": "https://d.example.com", "type": "website"}, headers=x_headers).status_code, 429)

            # 5. Read bucket fails closed (429) if Redis errors when RATE_LIMIT_FAIL_CLOSED=true
            broken_redis = MagicMock()
            broken_redis.eval.side_effect = ConnectionError("redis down")
            rate_limiter.set_redis_client(broken_redis)
            r_fail_closed = client.get("/api/jobs/job-rl-1", headers=x_headers)
            self.assertEqual(r_fail_closed.status_code, 429)

    def test_explicit_session_revocation_cross_worker_and_redis_failure_fail_closed(self):
        import time
        import fakeredis
        from app import (
            UI_SESSION_COOKIE_NAME,
            _is_ui_session_revoked,
            _revoke_ui_session_nonce,
            _revoked_ui_sessions,
            _revoked_ui_sessions_lock,
        )
        from services.job_queue import QueueUnavailableError, set_redis_connection

        # Local Docker staging mode: LEADHUNTER_ENV=development + REDIS_URL explicitly configured
        os.environ["LEADHUNTER_ENV"] = "development"
        os.environ["UI_AUTO_SESSION"] = "false"
        os.environ["CONTAINER"] = "true"
        os.environ["REDIS_URL"] = "redis://redis:6379/0"
        fake_redis = fakeredis.FakeRedis()
        set_redis_connection(fake_redis)
        rate_limiter.set_redis_client(fake_redis)

        client = app.test_client()
        r_login = client.post(
            "/api/ui-session",
            json={},
            headers=self._same_origin_post_headers(extra={"X-API-Key": self.secret_key}),
        )
        self.assertEqual(r_login.status_code, 200)
        csrf_token = r_login.get_json()["csrf_token"]
        cookie_val = self._extract_cookie_value(r_login, UI_SESSION_COOKIE_NAME)
        nonce_hex = cookie_val.split(".")[0]

        # 1A. REDIS_URL configured + get_redis_connection() raises QueueUnavailableError -> MUST fail closed
        #     even in non-production local Docker staging (never infer unconfigured from exception type!)
        with patch("app.get_redis_connection", side_effect=QueueUnavailableError("Failed to create Redis connection")):
            self.assertTrue(_is_ui_session_revoked(nonce_hex))
            self.assertFalse(_revoke_ui_session_nonce(nonce_hex, int(time.time()) + 300))

            # Clear local cache so we prove fail-closed came from Redis-unavailable check, not local cache
            with _revoked_ui_sessions_lock:
                _revoked_ui_sessions.clear()

            r_api_queue_err = client.post(
                "/api/export-csv",
                json={"leads": [{"Business Name": "Test"}]},
                headers=self._same_origin_post_headers(csrf_token),
            )
            self.assertEqual(r_api_queue_err.status_code, 401)

            r_logout_queue_err = client.delete(
                "/api/ui-session",
                headers=self._same_origin_post_headers(csrf_token),
            )
            self.assertEqual(r_logout_queue_err.status_code, 503)
            self.assertTrue(
                any("Max-Age=0" in h for h in r_logout_queue_err.headers.getlist("Set-Cookie"))
            )

        # 1B. Redis exists()/set() runtime ConnectionError -> MUST also fail closed & return 503 on logout
        with _revoked_ui_sessions_lock:
            _revoked_ui_sessions.clear()
        client.set_cookie(UI_SESSION_COOKIE_NAME, cookie_val)
        broken_redis = MagicMock()
        broken_redis.exists.side_effect = ConnectionError("redis timeout")
        broken_redis.set.side_effect = ConnectionError("redis timeout")
        set_redis_connection(broken_redis)

        self.assertTrue(_is_ui_session_revoked(nonce_hex))
        self.assertEqual(
            client.post(
                "/api/export-csv",
                json={"leads": [{"Business Name": "Test"}]},
                headers=self._same_origin_post_headers(csrf_token),
            ).status_code,
            401,
        )
        r_logout_conn_err = client.delete(
            "/api/ui-session",
            headers=self._same_origin_post_headers(csrf_token),
        )
        self.assertEqual(r_logout_conn_err.status_code, 503)
        self.assertTrue(
            any("Max-Age=0" in h for h in r_logout_conn_err.headers.getlist("Set-Cookie"))
        )

        # 2. Cross-worker logout revocation: Worker A revokes in Redis -> clear process-local cache
        #    (simulating Worker B) -> Worker B MUST reject replayed pre-logout cookie!
        set_redis_connection(fake_redis)
        with _revoked_ui_sessions_lock:
            _revoked_ui_sessions.clear()

        r_login2 = client.post(
            "/api/ui-session",
            json={},
            headers=self._same_origin_post_headers(extra={"X-API-Key": self.secret_key}),
        )
        self.assertEqual(r_login2.status_code, 200)
        csrf2 = r_login2.get_json()["csrf_token"]
        cookie2 = self._extract_cookie_value(r_login2, UI_SESSION_COOKIE_NAME)

        r_logout2 = client.delete("/api/ui-session", headers=self._same_origin_post_headers(csrf2))
        self.assertEqual(r_logout2.status_code, 200)

        with _revoked_ui_sessions_lock:
            _revoked_ui_sessions.clear()

        worker_b_client = app.test_client()
        worker_b_client.set_cookie(UI_SESSION_COOKIE_NAME, cookie2)
        self.assertEqual(
            worker_b_client.post(
                "/api/export-csv",
                json={"leads": [{"Business Name": "Test"}]},
                headers=self._same_origin_post_headers(csrf2),
            ).status_code,
            401,
        )
        self.assertEqual(self._extract_csrf(worker_b_client.get("/").data.decode("utf-8")), "")

        # 3. Redis genuinely unconfigured in non-production single-process local dev -> local fallback works
        set_redis_connection(None)
        rate_limiter.set_redis_client(None)
        os.environ["LEADHUNTER_ENV"] = "development"
        os.environ.pop("REDIS_URL", None)
        with _revoked_ui_sessions_lock:
            _revoked_ui_sessions.clear()

        c_local = app.test_client()
        r_local_login = c_local.post(
            "/api/ui-session",
            json={},
            headers=self._same_origin_post_headers(extra={"X-API-Key": self.secret_key}),
        )
        self.assertEqual(r_local_login.status_code, 200)
        local_csrf = r_local_login.get_json()["csrf_token"]
        local_cookie = self._extract_cookie_value(r_local_login, UI_SESSION_COOKIE_NAME)
        local_nonce = local_cookie.split(".")[0]

        self.assertFalse(_is_ui_session_revoked(local_nonce))
        self.assertEqual(
            c_local.post(
                "/api/export-csv",
                json={"leads": [{"Business Name": "Local"}]},
                headers=self._same_origin_post_headers(local_csrf),
            ).status_code,
            200,
        )
        self.assertEqual(
            c_local.delete("/api/ui-session", headers=self._same_origin_post_headers(local_csrf)).status_code,
            200,
        )
        self.assertTrue(_is_ui_session_revoked(local_nonce))
        c_local_replay = app.test_client()
        c_local_replay.set_cookie(UI_SESSION_COOKIE_NAME, local_cookie)
        self.assertEqual(
            c_local_replay.post(
                "/api/export-csv",
                json={"leads": [{"Business Name": "Local"}]},
                headers=self._same_origin_post_headers(local_csrf),
            ).status_code,
            401,
        )

        # 4. Production with Redis unavailable (unconfigured OR QueueUnavailableError) MUST fail closed
        os.environ["LEADHUNTER_ENV"] = "production"
        os.environ.pop("REDIS_URL", None)
        with _revoked_ui_sessions_lock:
            _revoked_ui_sessions.clear()
        self.assertTrue(_is_ui_session_revoked("a" * 32))
        self.assertFalse(_revoke_ui_session_nonce("a" * 32, int(time.time()) + 300))

        os.environ["REDIS_URL"] = "redis://redis:6379/0"
        with patch("app.get_redis_connection", side_effect=QueueUnavailableError("prod redis down")):
            with _revoked_ui_sessions_lock:
                _revoked_ui_sessions.clear()
            self.assertTrue(_is_ui_session_revoked("b" * 32))
            self.assertFalse(_revoke_ui_session_nonce("b" * 32, int(time.time()) + 300))

    def test_frontend_retry_after_and_bounded_polling_backoff_in_chromium(self):
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
                    const backoffSchedule = [0, 1, 2, 3, 4, 5, 10].map(a => getPollDelayMs(a));
                    const parsedValid = parseRetryAfterMs({ headers: { get: () => '7' } });
                    const parsedClamped = parseRetryAfterMs({ headers: { get: () => '999' } });
                    const parsedFallback = parseRetryAfterMs({ headers: { get: () => 'not-a-number' } }, 3, 60);

                    const recordedDelays = [];
                    const origSetTimeout = window.setTimeout;
                    window.setTimeout = (fn, ms) => {
                        recordedDelays.push(ms);
                        return origSetTimeout(fn, 1);
                    };

                    uiCsrfToken = 'csrf-retry-test';
                    uiSessionActive = true;

                    let statusCalls = 0;
                    let resultCalls = 0;
                    window.fetch = async (url, opts = {}) => {
                        const mkResp = (status, obj, retryAfter = null) => ({
                            ok: status >= 200 && status < 300,
                            status,
                            headers: {
                                get: (k) => {
                                    const kl = k.toLowerCase();
                                    if (kl === 'content-type') return 'application/json';
                                    if (kl === 'retry-after') return retryAfter;
                                    return null;
                                }
                            },
                            json: async () => obj
                        });
                        if (url === '/api/jobs' && opts.method === 'POST') {
                            return mkResp(202, { success: true, job_id: 'job-backoff-1', status: 'queued' });
                        }
                        if (url === '/api/jobs/job-backoff-1') {
                            statusCalls += 1;
                            if (statusCalls === 1) return mkResp(429, { success: false, error: 'Rate limit exceeded.' }, '3');
                            if (statusCalls === 2) return mkResp(200, { success: true, job_id: 'job-backoff-1', status: 'queued', progress: {} });
                            if (statusCalls === 3) return mkResp(200, { success: true, job_id: 'job-backoff-1', status: 'started', progress: {} });
                            return mkResp(200, { success: true, job_id: 'job-backoff-1', status: 'finished', progress: {} });
                        }
                        if (url === '/api/jobs/job-backoff-1/result') {
                            resultCalls += 1;
                            if (resultCalls === 1) return mkResp(429, { success: false, error: 'Rate limit exceeded.' }, '2');
                            return mkResp(200, { success: true, status: 'finished', count: 1, data: { 'Business Name': 'Backoff Co', 'Website': 'https://example.com' } });
                        }
                        return mkResp(404, { success: false, error: 'Not found' });
                    };

                    const jobOut = await runAsyncScrapeJob({ url: 'https://example.com', type: 'website' });
                    const jobDelays = recordedDelays.slice();
                    recordedDelays.length = 0;

                    // Verify bounded 429 retries stop cleanly after MAX_RATE_LIMIT_RETRIES (3)
                    let always429Calls = 0;
                    window.fetch = async (url) => {
                        always429Calls += 1;
                        return {
                            ok: false,
                            status: 429,
                            headers: { get: (k) => k.toLowerCase() === 'retry-after' ? '1' : 'application/json' },
                            json: async () => ({ success: false, error: 'Rate limit exceeded.' })
                        };
                    };
                    const exhaustedOut = await runAsyncScrapeJob({ url: 'https://example.com', type: 'website' });
                    const exhaustedDelays = recordedDelays.slice();

                    return {
                        backoffSchedule,
                        parsedValid,
                        parsedClamped,
                        parsedFallback,
                        jobDelays,
                        exhaustedDelays,
                        statusCalls,
                        resultCalls,
                        jobOut,
                        always429Calls,
                        exhaustedOut
                    };
                }""")

                self.assertEqual(res["backoffSchedule"], [2000, 2500, 3000, 4000, 5000, 5000, 5000])
                self.assertEqual(res["parsedValid"], 7000)
                self.assertEqual(res["parsedClamped"], 60000)
                self.assertEqual(res["parsedFallback"], 3000)
                self.assertTrue(res["jobOut"]["success"])
                self.assertEqual(res["statusCalls"], 4)
                self.assertEqual(res["resultCalls"], 2)
                # Delays: poll0(2000) -> 429 Retry-After(3000) -> poll1(2500) -> poll2(3000) -> result 429 Retry-After(2000)
                self.assertEqual(res["jobDelays"], [2000, 3000, 2500, 3000, 2000])
                # Bounded retries: 1 initial + 3 retries (1000ms each) = 4 total calls, returns clean non-auth 429 failure
                self.assertEqual(res["always429Calls"], 4)
                self.assertEqual(res["exhaustedDelays"], [1000, 1000, 1000])
                self.assertFalse(res["exhaustedOut"]["success"])
                self.assertEqual(res["exhaustedOut"]["status"], 429)
                self.assertFalse(res["exhaustedOut"]["authError"])
            finally:
                browser.close()


if __name__ == "__main__":
    unittest.main()
