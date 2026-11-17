import unittest
from services.security import validate_and_sanitize_url, is_ip_allowed, SecurityError

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

if __name__ == '__main__':
    unittest.main()
