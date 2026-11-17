import unittest
from unittest.mock import patch, MagicMock
import socket
import requests
import urllib3
import urllib3.connection
import urllib3.util.connection as urllib3_connection
from services.security import (
    validate_and_sanitize_url,
    is_ip_allowed,
    _safe_create_connection,
    safe_http_get,
    SafeHTTPAdapter,
    SecurityError,
    validate_google_maps_url,
    is_safe_browser_url,
    is_google_maps_domain,
    is_authorized_maps_subresource_host,
    resolve_and_validate_hostname,
    SafeBrowserProxy
)
from services.maps_scraper import create_playwright_route_interceptor, scrape_google_maps

class TestSecurity(unittest.TestCase):
    # -------------------------------------------------------------
    # Static URL & IP Sanitization Tests
    # -------------------------------------------------------------
    def test_blocks_localhost_and_loopback(self):
        with self.assertRaises(SecurityError):
            validate_and_sanitize_url("http://localhost:5000")
        with self.assertRaises(SecurityError):
            validate_and_sanitize_url("http://127.0.0.1:8080")
        with self.assertRaises(SecurityError):
            validate_and_sanitize_url("http://[::1]")

    def test_blocks_cloud_metadata(self):
        with self.assertRaises(SecurityError):
            validate_and_sanitize_url("http://169.254.169.254/latest/meta-data")

    def test_blocks_private_ip_ranges(self):
        with self.assertRaises(SecurityError):
            validate_and_sanitize_url("http://10.0.0.1/admin")
        with self.assertRaises(SecurityError):
            validate_and_sanitize_url("http://192.168.1.1")
        with self.assertRaises(SecurityError):
            validate_and_sanitize_url("http://172.16.0.5")

    def test_blocks_disallowed_schemes(self):
        with self.assertRaises(SecurityError):
            validate_and_sanitize_url("file:///etc/passwd")
        with self.assertRaises(SecurityError):
            validate_and_sanitize_url("ftp://example.com/test")

    def test_allows_valid_public_domains(self):
        url = validate_and_sanitize_url("https://google.com")
        self.assertTrue(url.startswith("https://google.com"))

    def test_ip_allowed_checks(self):
        self.assertFalse(is_ip_allowed("127.0.0.1"))
        self.assertFalse(is_ip_allowed("10.10.10.10"))
        self.assertFalse(is_ip_allowed("169.254.169.254"))
        self.assertFalse(is_ip_allowed("::1"))
        self.assertFalse(is_ip_allowed("fe80::1"))
        self.assertFalse(is_ip_allowed("fc00::1"))
        self.assertFalse(is_ip_allowed("::ffff:127.0.0.1"))
        self.assertFalse(is_ip_allowed("::ffff:169.254.169.254"))
        self.assertTrue(is_ip_allowed("8.8.8.8"))
        self.assertTrue(is_ip_allowed("1.1.1.1"))
        self.assertTrue(is_ip_allowed("2607:f8b0:4004:800::200e"))

    # -------------------------------------------------------------
    # Actual Connection Path Reference Tests
    # -------------------------------------------------------------
    def test_urllib3_connection_reference_is_patched(self):
        """Verify the exact function reference used by urllib3 HTTPConnection points to _safe_create_connection."""
        self.assertIs(urllib3_connection.create_connection, _safe_create_connection)
        self.assertIs(urllib3.connection.connection.create_connection, _safe_create_connection)

    # -------------------------------------------------------------
    # Live requests.Session.get() Execution Path Integration Tests
    # -------------------------------------------------------------
    def test_requests_session_get_blocks_dns_rebinding_localhost(self):
        """Invoke requests.Session.get() and verify DNS rebinding to 127.0.0.1 is blocked before socket connect."""
        session = requests.Session()
        with patch('socket.getaddrinfo') as mock_gai, patch('socket.socket') as mock_sock_cls:
            mock_gai.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 80))]
            with self.assertRaises(SecurityError) as ctx:
                session.get('http://rebind-localhost-test.com', timeout=1)
            self.assertIn("restricted IP: 127.0.0.1", str(ctx.exception))
            # Verify socket.socket was never connected
            mock_sock_cls.return_value.connect.assert_not_called()

    def test_requests_session_get_blocks_dns_rebinding_metadata(self):
        """Invoke requests.Session.get() and verify DNS rebinding to 169.254.169.254 is blocked."""
        session = requests.Session()
        with patch('socket.getaddrinfo') as mock_gai, patch('socket.socket') as mock_sock_cls:
            mock_gai.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('169.254.169.254', 80))]
            with self.assertRaises(SecurityError) as ctx:
                session.get('http://rebind-metadata-test.com', timeout=1)
            self.assertIn("restricted IP: 169.254.169.254", str(ctx.exception))
            mock_sock_cls.return_value.connect.assert_not_called()

    def test_requests_session_get_blocks_private_ipv4(self):
        """Invoke requests.Session.get() and verify DNS rebinding to 10.0.0.1 is blocked."""
        session = requests.Session()
        with patch('socket.getaddrinfo') as mock_gai, patch('socket.socket') as mock_sock_cls:
            mock_gai.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.1', 80))]
            with self.assertRaises(SecurityError) as ctx:
                session.get('http://rebind-private-test.com', timeout=1)
            self.assertIn("restricted IP: 10.0.0.1", str(ctx.exception))
            mock_sock_cls.return_value.connect.assert_not_called()

    def test_requests_session_get_blocks_ipv6_link_local(self):
        """Invoke requests.Session.get() and verify DNS rebinding to fe80::1 is blocked."""
        session = requests.Session()
        with patch('socket.getaddrinfo') as mock_gai, patch('socket.socket') as mock_sock_cls:
            mock_gai.return_value = [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('fe80::1', 80, 0, 0))]
            with self.assertRaises(SecurityError) as ctx:
                session.get('http://rebind-ipv6-test.com', timeout=1)
            self.assertIn("restricted IP: fe80::1", str(ctx.exception))
            mock_sock_cls.return_value.connect.assert_not_called()

    def test_requests_session_get_connects_public_ip_with_pinning(self):
        """Invoke requests.Session.get() and verify connection connects to validated pinned IP."""
        session = requests.Session()
        with patch('socket.getaddrinfo') as mock_gai, patch('socket.socket') as mock_sock_cls:
            mock_gai.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 80))]
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            # Simulate socket connection success then stop before HTTP response parsing
            mock_sock.connect.side_effect = OSError("Simulated connection verified")

            with self.assertRaises(OSError):
                session.get('http://safe-public-example.com', timeout=1)

            # Ensure socket.connect was called directly with the verified pinned address tuple
            mock_sock.connect.assert_called_once_with(('93.184.216.34', 80))

    # -------------------------------------------------------------
    # HTTP Redirect & Safe GET Tests
    # -------------------------------------------------------------
    def test_redirect_to_private_ip_blocked(self):
        """Verify that redirect hops pointing to private IPs are intercepted and blocked."""
        mock_redirect = MagicMock()
        mock_redirect.is_redirect = True
        mock_redirect.headers = {'location': 'http://192.168.1.1/admin'}

        with patch('requests.Session.get') as mock_get, \
             patch('services.security.validate_and_sanitize_url') as mock_val:
            mock_val.side_effect = [
                'https://publicsite.com',
                SecurityError("Access to private destination '192.168.1.1' is forbidden.")
            ]
            mock_get.return_value = mock_redirect

            with self.assertRaises(SecurityError) as ctx:
                safe_http_get('https://publicsite.com')
            self.assertIn("192.168.1.1", str(ctx.exception))

    def test_redirect_to_public_domain_allowed(self):
        """Verify safe redirect to another public domain proceeds normally."""
        mock_redirect = MagicMock()
        mock_redirect.is_redirect = True
        mock_redirect.headers = {'location': 'https://example.com/welcome'}

        mock_final = MagicMock()
        mock_final.is_redirect = False
        mock_final.iter_content.return_value = [b"Welcome Content"]

        with patch('requests.Session.get') as mock_get, \
             patch('services.security.validate_and_sanitize_url') as mock_val:
            mock_val.side_effect = ['https://example.com', 'https://example.com/welcome']
            mock_get.side_effect = [mock_redirect, mock_final]

            resp = safe_http_get('https://example.com')
            self.assertEqual(resp._content, b"Welcome Content")
            self.assertTrue(resp.ssl_verified)

    def test_tls_verification_failure(self):
        """Verify that TLS verification failures are raised and never downgraded to verify=False."""
        with patch('services.security.validate_and_sanitize_url') as mock_val, \
             patch('requests.Session.get') as mock_get:
            mock_val.return_value = 'https://self-signed.badssl.com'
            mock_get.side_effect = requests.exceptions.SSLError("CERTIFICATE_VERIFY_FAILED")

            with self.assertRaises(requests.exceptions.SSLError):
                safe_http_get('https://self-signed.badssl.com')

    def test_response_size_limit_enforced(self):
        """Verify responses exceeding MAX_RESPONSE_BYTES (5 MB) are terminated."""
        mock_resp = MagicMock()
        mock_resp.is_redirect = False
        mock_resp.iter_content.return_value = [b'X' * (1024 * 1024)] * 6

        with patch('services.security.validate_and_sanitize_url') as mock_val, \
             patch('requests.Session.get') as mock_get:
            mock_val.return_value = 'https://large-file.com'
            mock_get.return_value = mock_resp

            with self.assertRaises(SecurityError) as ctx:
                safe_http_get('https://large-file.com')
            self.assertIn("Response size exceeded safety limit", str(ctx.exception))
            mock_resp.close.assert_called_once()

    def test_safe_http_adapter_preflight_blocks_invalid_url(self):
        """Verify SafeHTTPAdapter blocks restricted URLs at the adapter layer."""
        adapter = SafeHTTPAdapter()
        req = requests.PreparedRequest()
        req.url = 'http://127.0.0.1:8000/api'
        with self.assertRaises(SecurityError):
            adapter.send(req)

    # -------------------------------------------------------------
    # Environment Proxy Bypass Prevention & Resource Cleanup Tests
    # -------------------------------------------------------------
    def test_proxy_env_cannot_bypass_localhost(self):
        """Verify that HTTP_PROXY / HTTPS_PROXY in environment cannot route requests to localhost."""
        with patch.dict('os.environ', {'HTTP_PROXY': 'http://127.0.0.1:8888', 'HTTPS_PROXY': 'http://127.0.0.1:8888'}):
            with self.assertRaises(SecurityError):
                safe_http_get('http://127.0.0.1:8000')

    def test_proxy_env_cannot_bypass_cloud_metadata(self):
        """Verify that HTTP_PROXY / HTTPS_PROXY in environment cannot reach cloud metadata (169.254.169.254)."""
        with patch.dict('os.environ', {'HTTP_PROXY': 'http://corporate-proxy:8080', 'HTTPS_PROXY': 'http://corporate-proxy:8080'}):
            with self.assertRaises(SecurityError):
                safe_http_get('http://169.254.169.254/latest/meta-data')

    def test_proxy_env_cannot_bypass_private_ipv4(self):
        """Verify that HTTP_PROXY in environment cannot reach private class A or class C networks."""
        with patch.dict('os.environ', {'HTTP_PROXY': 'http://corporate-proxy:8080'}):
            with self.assertRaises(SecurityError):
                safe_http_get('http://10.0.0.1/admin')
            with self.assertRaises(SecurityError):
                safe_http_get('http://192.168.1.1')

    def test_proxy_env_cannot_bypass_ipv6_link_local(self):
        """Verify that HTTPS_PROXY in environment cannot reach IPv6 link-local addresses."""
        with patch.dict('os.environ', {'HTTPS_PROXY': 'http://corporate-proxy:8080'}):
            with self.assertRaises(SecurityError):
                safe_http_get('http://[fe80::1]')

    def test_proxy_env_ignored_and_not_inherited(self):
        """Verify safe_http_get explicitly sets trust_env=False so proxies in os.environ are ignored."""
        with patch.dict('os.environ', {'HTTP_PROXY': 'http://127.0.0.1:8888', 'HTTPS_PROXY': 'http://127.0.0.1:8888'}):
            with patch('services.security.validate_and_sanitize_url') as mock_val, \
                 patch('requests.Session.get') as mock_get:
                mock_val.return_value = 'https://example.com'
                mock_resp = MagicMock()
                mock_resp.is_redirect = False
                mock_resp.iter_content.return_value = [b"Safe content"]
                mock_get.return_value = mock_resp

                with patch('requests.Session') as mock_sess_cls:
                    real_session = requests.Session()
                    mock_sess_cls.return_value = real_session
                    real_session.get = mock_get

                    resp = safe_http_get('https://example.com')
                    self.assertFalse(real_session.trust_env)
                    self.assertEqual(resp._content, b"Safe content")

    def test_redirect_and_session_closed_during_lifecycle(self):
        """Verify redirect responses, final stream, and session are properly closed."""
        mock_redirect = MagicMock()
        mock_redirect.is_redirect = True
        mock_redirect.headers = {'location': 'https://example.com/dest'}

        mock_final = MagicMock()
        mock_final.is_redirect = False
        mock_final.iter_content.return_value = [b"OK"]

        with patch('services.security.validate_and_sanitize_url') as mock_val, \
             patch('requests.Session.get') as mock_get, \
             patch('requests.Session.close') as mock_session_close:
            mock_val.side_effect = ['https://example.com', 'https://example.com/dest']
            mock_get.side_effect = [mock_redirect, mock_final]

            safe_http_get('https://example.com')
            # Verify redirect response was closed before following next hop
            mock_redirect.close.assert_called_once()
            # Verify final response stream was closed
            mock_final.close.assert_called_once()
            # Verify session was closed at end of lifecycle
            mock_session_close.assert_called_once()

    def test_public_destination_with_proxy_env_does_not_contact_proxy(self):
        """
        Verify that when HTTP_PROXY and HTTPS_PROXY are configured in the environment,
        a request to a public destination connects directly to the target host and
        never contacts or resolves the configured proxy host because session.trust_env is False.
        """
        proxy_host = "unreachable-proxy-server.invalid"
        resolved_hosts = []

        def tracking_getaddrinfo(host, port, *args, **kwargs):
            resolved_hosts.append(host)
            if "example.com" in host:
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', port))]
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', port))]

        with patch.dict('os.environ', {
            'HTTP_PROXY': f'http://{proxy_host}:8080',
            'HTTPS_PROXY': f'http://{proxy_host}:8080'
        }):
            with patch('socket.getaddrinfo', side_effect=tracking_getaddrinfo), \
                 patch('socket.socket') as mock_sock_cls:
                mock_sock = MagicMock()
                mock_sock_cls.return_value = mock_sock
                mock_sock.connect.side_effect = OSError("Simulated connection verified directly to public host")

                with self.assertRaises(OSError) as ctx:
                    safe_http_get('https://example.com')
                self.assertIn("Simulated connection verified", str(ctx.exception))

                # Verify proxy host was never resolved via DNS
                self.assertNotIn(proxy_host, resolved_hosts)
                # Verify DNS lookup was performed for the target public host
                self.assertIn("example.com", resolved_hosts)
                # Verify socket connected directly to the pinned public IP address
                mock_sock.connect.assert_called_once_with(('93.184.216.34', 443))

class TestGoogleMapsPlaywrightSecurity(unittest.TestCase):
    """
    Automated security regression tests for Google Maps Playwright navigation,
    SSRF defense, domain whitelist validation, and browser route/redirect/subresource filtering.
    """

    def test_valid_google_maps_search_url_accepted(self):
        url = "https://www.google.com/maps/search/HVAC+contractors+in+Dallas,+TX"
        sanitized = validate_google_maps_url(url)
        self.assertEqual(sanitized, url)

        # Query format
        q_url = "https://maps.google.com/?q=HVAC+Dallas"
        self.assertEqual(validate_google_maps_url(q_url), q_url)

    def test_valid_google_maps_place_url_accepted(self):
        url = "https://www.google.com/maps/place/Dallas+HVAC/@32.7767,-96.7970,14z"
        sanitized = validate_google_maps_url(url)
        self.assertEqual(sanitized, url)

        # Shortlink
        short = "https://maps.app.goo.gl/abcdef123"
        self.assertEqual(validate_google_maps_url(short), short)

    def test_arbitrary_external_host_rejected(self):
        invalid_hosts = [
            "https://example.com/maps/search/HVAC",
            "https://bing.com/maps",
            "https://evil-google.com/maps",
            "https://google.com.attacker.com/maps",
            "https://yahoo.com/maps",
            "https://www.google.com/finance",  # Legitimate Google host, but unauthorized non-maps pattern
        ]
        for url in invalid_hosts:
            with self.subTest(url=url):
                with self.assertRaises(SecurityError):
                    validate_google_maps_url(url)

    def test_localhost_and_private_ip_urls_rejected(self):
        private_urls = [
            "http://127.0.0.1:8000/maps",
            "http://localhost:5000/maps",
            "http://10.0.0.1/maps",
            "http://192.168.1.1/maps",
            "http://172.16.0.1/maps",
            "http://0.0.0.0:8000/maps",
        ]
        for url in private_urls:
            with self.subTest(url=url):
                with self.assertRaises(SecurityError):
                    validate_google_maps_url(url)

    def test_cloud_metadata_and_ipv6_link_local_rejected(self):
        metadata_urls = [
            "http://169.254.169.254/latest/meta-data",
            "http://[fe80::1]/maps",
            "http://[::1]:8080/maps",
            "file:///etc/passwd",
            "gopher://127.0.0.1:8000/",
        ]
        for url in metadata_urls:
            with self.subTest(url=url):
                with self.assertRaises(SecurityError):
                    validate_google_maps_url(url)

    def test_redirects_to_unauthorized_destinations_blocked(self):
        mock_page = MagicMock()
        mock_page.main_frame = MagicMock()

        interceptor = create_playwright_route_interceptor(mock_page)

        # Case A: Redirect to localhost
        route_localhost = MagicMock()
        req_localhost = MagicMock()
        req_localhost.url = "http://127.0.0.1:8000/internal-admin"
        req_localhost.is_navigation_request.return_value = True
        req_localhost.frame = mock_page.main_frame
        route_localhost.request = req_localhost

        interceptor(route_localhost)
        route_localhost.abort.assert_called_once_with("blockedbyclient")
        route_localhost.continue_.assert_not_called()

        # Case B: Redirect to arbitrary external destination
        route_external = MagicMock()
        req_external = MagicMock()
        req_external.url = "https://evil.com/phishing"
        req_external.is_navigation_request.return_value = True
        req_external.frame = mock_page.main_frame
        route_external.request = req_external

        interceptor(route_external)
        route_external.abort.assert_called_once_with("blockedbyclient")
        route_external.continue_.assert_not_called()

        # Case C: Valid navigation to Google Maps
        route_valid = MagicMock()
        req_valid = MagicMock()
        req_valid.url = "https://www.google.com/maps/place/Dallas+Pro+HVAC"
        req_valid.is_navigation_request.return_value = True
        req_valid.frame = mock_page.main_frame
        route_valid.request = req_valid

        interceptor(route_valid)
        route_valid.continue_.assert_called_once()
        route_valid.abort.assert_not_called()

    def test_browser_subresource_requests_to_unauthorized_destinations_blocked(self):
        mock_page = MagicMock()
        mock_page.main_frame = MagicMock()

        interceptor = create_playwright_route_interceptor(mock_page)

        # Case A: Subresource requesting cloud metadata IP
        route_meta = MagicMock()
        req_meta = MagicMock()
        req_meta.url = "http://169.254.169.254/latest/meta-data"
        req_meta.is_navigation_request.return_value = False
        route_meta.request = req_meta

        interceptor(route_meta)
        route_meta.abort.assert_called_once_with("blockedbyclient")
        route_meta.continue_.assert_not_called()

        # Case B: Subresource requesting local network
        route_local = MagicMock()
        req_local = MagicMock()
        req_local.url = "http://127.0.0.1:8000/leak.png"
        req_local.is_navigation_request.return_value = False
        route_local.request = req_local

        interceptor(route_local)
        route_local.abort.assert_called_once_with("blockedbyclient")
        route_local.continue_.assert_not_called()

        # Case C: Subresource requesting untrusted third-party host
        route_evil = MagicMock()
        req_evil = MagicMock()
        req_evil.url = "https://evil.com/tracker.js"
        req_evil.is_navigation_request.return_value = False
        route_evil.request = req_evil

        interceptor(route_evil)
        route_evil.abort.assert_called_once_with("blockedbyclient")
        route_evil.continue_.assert_not_called()

        # Case D: Authorized Google subresource (gstatic)
        route_static = MagicMock()
        req_static = MagicMock()
        req_static.url = "https://maps.gstatic.com/tactile/omnibox/compass-2x.png"
        req_static.is_navigation_request.return_value = False
        route_static.request = req_static

        interceptor(route_static)
        route_static.continue_.assert_called_once()
        route_static.abort.assert_not_called()

        # Case E: Inline base64 data URL
        route_data = MagicMock()
        req_data = MagicMock()
        req_data.url = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
        req_data.is_navigation_request.return_value = False
        route_data.request = req_data

        interceptor(route_data)
        route_data.continue_.assert_called_once()
        route_data.abort.assert_not_called()

    def test_scrape_google_maps_preflight_blocks_invalid_url(self):
        # Localhost rejected before Playwright launches
        with self.assertRaises(SecurityError):
            scrape_google_maps("http://127.0.0.1:8000/maps")

        # Arbitrary external host rejected before Playwright launches
        with self.assertRaises(SecurityError):
            scrape_google_maps("https://example.com/search?q=hvac")

        # Cloud metadata rejected before Playwright launches
        with self.assertRaises(SecurityError):
            scrape_google_maps("http://169.254.169.254/latest")

    def test_public_to_private_dns_rebinding_rejected(self):
        """
        Verify that a domain that resolves to a public IP on initial check and later flips
        to a private IP (127.0.0.1) is NOT protected by stale cache and is rejected on the second check.
        """
        call_count = 0
        def rebinding_getaddrinfo(host, port, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First lookup: public IP
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('142.250.190.46', port))]
            else:
                # Second lookup: rebound to localhost!
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', port))]

        with patch('socket.getaddrinfo', side_effect=rebinding_getaddrinfo):
            # Check 1: Resolves to public IP -> Safe
            is_safe_1, reason_1 = is_safe_browser_url("https://www.google.com/maps/search/hvac", is_main_document=True)
            self.assertTrue(is_safe_1)
            self.assertEqual(reason_1, "OK")

            # Check 2: Rebound to 127.0.0.1 -> Must NOT use stale cache, must be rejected!
            is_safe_2, reason_2 = is_safe_browser_url("https://www.google.com/maps/search/hvac", is_main_document=True)
            self.assertFalse(is_safe_2)
            self.assertIn("127.0.0.1", reason_2)

    def test_dns_result_changing_between_validation_and_connection_blocked_by_proxy(self):
        """
        Verify that when a client requests a Google Maps connection through SafeBrowserProxy,
        if DNS resolves to a private IP (DNS rebinding between validation and connect),
        the proxy intercepts the CONNECT request, responds with 403 Forbidden, and never
        establishes a connection to the private IP.
        """
        def private_getaddrinfo(host, port, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', port))]

        mock_client = MagicMock()
        mock_client.recv.side_effect = [b"CONNECT maps.google.com:443 HTTP/1.1\r\nHost: maps.google.com:443\r\n\r\n", b""]

        proxy = SafeBrowserProxy()
        try:
            with patch('socket.getaddrinfo', side_effect=private_getaddrinfo), \
                 patch('services.security.socket.socket') as mock_sock_cls:
                proxy._handle_client(mock_client)

                # Upstream socket was never connected
                mock_sock_cls.return_value.connect.assert_not_called()
        finally:
            proxy.stop()

        # Client was sent 403 Forbidden
        sent_bytes = b"".join(call.args[0] for call in mock_client.sendall.call_args_list)
        self.assertIn(b"403 Forbidden", sent_bytes)
        self.assertIn(b"127.0.0.1", sent_bytes)

    def test_redirect_to_hostname_resolving_to_private_ip_blocked(self):
        """
        Verify that a browser navigation redirect to a hostname whose DNS resolves to a private IP
        is intercepted and aborted at the route handler level.
        """
        mock_page = MagicMock()
        mock_page.main_frame = MagicMock()

        interceptor = create_playwright_route_interceptor(mock_page)

        def private_redirect_getaddrinfo(host, port, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.5', port))]

        route_redirect = MagicMock()
        req_redirect = MagicMock()
        req_redirect.url = "https://maps.google.com/redirect-to-private"
        req_redirect.is_navigation_request.return_value = True
        req_redirect.frame = mock_page.main_frame
        route_redirect.request = req_redirect

        with patch('socket.getaddrinfo', side_effect=private_redirect_getaddrinfo):
            interceptor(route_redirect)
            route_redirect.abort.assert_called_once_with("blockedbyclient")
            route_redirect.continue_.assert_not_called()

    def test_browser_subresource_dns_rebinding_blocked(self):
        """
        Verify that a browser subresource request to an authorized hostname whose DNS resolves
        to cloud metadata (169.254.169.254) is aborted.
        """
        mock_page = MagicMock()
        mock_page.main_frame = MagicMock()

        interceptor = create_playwright_route_interceptor(mock_page)

        def metadata_subresource_getaddrinfo(host, port, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('169.254.169.254', port))]

        route_sub = MagicMock()
        req_sub = MagicMock()
        req_sub.url = "https://fonts.googleapis.com/css2?family=Roboto"
        req_sub.is_navigation_request.return_value = False
        route_sub.request = req_sub

        with patch('socket.getaddrinfo', side_effect=metadata_subresource_getaddrinfo):
            interceptor(route_sub)
            route_sub.abort.assert_called_once_with("blockedbyclient")
            route_sub.continue_.assert_not_called()

    def test_safe_browser_proxy_pins_socket_destination(self):
        """
        Verify that SafeBrowserProxy resolves the destination host, checks is_ip_allowed(),
        and pins the upstream socket connection directly to the validated public IP address.
        """
        pinned_ip = '142.250.190.46'

        def public_getaddrinfo(host, port, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (pinned_ip, port))]

        connected_destinations = []

        mock_upstream = MagicMock()
        mock_upstream.connect.side_effect = lambda addr: connected_destinations.append(addr)

        mock_client = MagicMock()
        mock_client.recv.side_effect = [b"CONNECT maps.google.com:443 HTTP/1.1\r\nHost: maps.google.com:443\r\n\r\n", b""]

        proxy = SafeBrowserProxy()
        try:
            with patch('socket.getaddrinfo', side_effect=public_getaddrinfo), \
                 patch('services.security.socket.socket', return_value=mock_upstream):
                proxy._handle_client(mock_client)
        finally:
            proxy.stop()

        self.assertIn((pinned_ip, 443), connected_destinations)
        mock_client.sendall.assert_called_with(b"HTTP/1.1 200 Connection Established\r\n\r\n")

if __name__ == '__main__':
    unittest.main()
