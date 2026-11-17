import unittest
from unittest.mock import patch, MagicMock
import requests
from services.security import (
    validate_and_sanitize_url,
    is_ip_allowed,
    _safe_create_connection,
    safe_http_get,
    SecurityError
)

class TestSecurity(unittest.TestCase):
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
        self.assertTrue(is_ip_allowed("8.8.8.8"))

    # -------------------------------------------------------------
    # DNS Rebinding & Socket Connection Tests
    # -------------------------------------------------------------
    def test_public_dns_resolution_and_connection(self):
        with patch('socket.getaddrinfo') as mock_gai, patch('socket.socket') as mock_sock_cls:
            mock_gai.return_value = [(2, 1, 0, '', ('93.184.216.34', 443))]
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock

            sock = _safe_create_connection(('example.com', 443))
            self.assertIsNotNone(sock)
            mock_sock.connect.assert_called_once_with(('93.184.216.34', 443))

    def test_dns_rebinding_to_localhost(self):
        """Simulate DNS rebinding where domain resolves to 127.0.0.1 at socket connect."""
        with patch('socket.getaddrinfo') as mock_gai:
            mock_gai.return_value = [(2, 1, 0, '', ('127.0.0.1', 80))]
            with self.assertRaises(SecurityError) as ctx:
                _safe_create_connection(('rebind-local.com', 80))
            self.assertIn("restricted IP: 127.0.0.1", str(ctx.exception))

    def test_dns_rebinding_to_private_ipv4(self):
        """Simulate DNS rebinding where domain resolves to internal 10.0.0.1 at socket connect."""
        with patch('socket.getaddrinfo') as mock_gai:
            mock_gai.return_value = [(2, 1, 0, '', ('10.0.0.1', 80))]
            with self.assertRaises(SecurityError) as ctx:
                _safe_create_connection(('rebind-internal.com', 80))
            self.assertIn("restricted IP: 10.0.0.1", str(ctx.exception))

    def test_ipv6_private_and_link_local_destinations(self):
        """Verify IPv6 loopback, link-local and private addresses are rejected."""
        self.assertFalse(is_ip_allowed("::1"))
        self.assertFalse(is_ip_allowed("fe80::1"))
        self.assertFalse(is_ip_allowed("fc00::1"))
        self.assertFalse(is_ip_allowed("[fe80::1]"))

        with patch('socket.getaddrinfo') as mock_gai:
            mock_gai.return_value = [(23, 1, 0, '', ('fe80::1', 80, 0, 0))]
            with self.assertRaises(SecurityError):
                _safe_create_connection(('[fe80::1]', 80))

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
            # First URL validates, second URL (redirect) raises SecurityError
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
        # Return 6 chunks of 1 MB = 6 MB
        mock_resp.iter_content.return_value = [b'X' * (1024 * 1024)] * 6

        with patch('services.security.validate_and_sanitize_url') as mock_val, \
             patch('requests.Session.get') as mock_get:
            mock_val.return_value = 'https://large-file.com'
            mock_get.return_value = mock_resp

            with self.assertRaises(SecurityError) as ctx:
                safe_http_get('https://large-file.com')
            self.assertIn("Response size exceeded safety limit", str(ctx.exception))
            mock_resp.close.assert_called_once()

if __name__ == '__main__':
    unittest.main()
