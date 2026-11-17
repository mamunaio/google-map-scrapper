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
    SecurityError
)

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

if __name__ == '__main__':
    unittest.main()
