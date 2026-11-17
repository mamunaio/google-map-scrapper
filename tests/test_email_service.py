import unittest
from unittest.mock import patch, MagicMock
from services.email_service import (
    decode_cloudflare_email,
    clean_and_validate_emails,
    extract_name_from_email_prefix,
    generate_email_permutations,
    extract_emails_and_socials,
    find_decision_maker_from_html,
    verify_email_smtp
)

class TestEmailService(unittest.TestCase):
    def test_cloudflare_email_decode(self):
        # Sample Cloudflare XOR hash for test@example.com (key 0x12)
        # 't' ^ 0x12 = 0x66, 'e' ^ 0x12 = 0x77, 's' ^ 0x12 = 0x61, 't' ^ 0x12 = 0x66
        # Let's verify standard roundtrip
        key = 0x25
        email = "test@example.com"
        cf_hex = f"{key:02x}" + "".join(f"{ord(c) ^ key:02x}" for c in email)
        decoded = decode_cloudflare_email(cf_hex)
        self.assertEqual(decoded, "test@example.com")

    def test_clean_and_validate_emails(self):
        raw = [
            "valid.owner@acmeair.com",
            "test@acmeair.com.png",  # File extension in domain
            "sentry@acmeair.com",   # Blacklist
            "info@acmeair.com",
            "valid.owner@acmeair.com" # Duplicate
        ]
        res = clean_and_validate_emails(raw, base_url="https://acmeair.com")
        self.assertIn("valid.owner@acmeair.com", res)
        self.assertIn("info@acmeair.com", res)
        self.assertNotIn("sentry@acmeair.com", res)
        self.assertNotIn("test@acmeair.com.png", res)
        # Named email on company domain must be prioritized over info@
        self.assertEqual(res[0], "valid.owner@acmeair.com")

    def test_name_from_email_prefix(self):
        self.assertEqual(extract_name_from_email_prefix("james.richmond@acme.com"), "James Richmond")
        self.assertEqual(extract_name_from_email_prefix("steve@acme.com"), "Steve")
        self.assertEqual(extract_name_from_email_prefix("info@acme.com"), "")
        self.assertEqual(extract_name_from_email_prefix("support@acme.com"), "")

    def test_permutations_generation(self):
        perms = generate_email_permutations("Steve Smith", "acmeair.com")
        self.assertIn("steve@acmeair.com", perms)
        self.assertIn("steve.smith@acmeair.com", perms)
        self.assertIn("ssmith@acmeair.com", perms)
        self.assertIn("steves@acmeair.com", perms)

    def test_decision_maker_from_schema(self):
        html = """
        <html>
        <head>
            <script type="application/ld+json">
            {
                "@context": "https://schema.org",
                "@type": "LocalBusiness",
                "name": "Acme Cooling",
                "founder": {
                    "@type": "Person",
                    "name": "David Miller"
                }
            }
            </script>
        </head>
        <body><h1>Welcome</h1></body>
        </html>
        """
        name, role = find_decision_maker_from_html(html)
        self.assertEqual(name, "David Miller")
        self.assertEqual(role, "Founder")

    def test_decision_maker_distinct_from_business_name(self):
        # When candidate matches business name, it must be rejected
        html_matching = """
        <html><body>
        <p>Founder: Dallas HVAC Pros</p>
        </body></html>
        """
        name, role = find_decision_maker_from_html(html_matching, business_name="Dallas HVAC Pros")
        self.assertIsNone(name)

        # Blacklisted business words
        html_blacklist = """
        <html><body>
        <p>CEO: Commercial Heating Solutions</p>
        </body></html>
        """
        name2, role2 = find_decision_maker_from_html(html_blacklist, business_name="Acme Air")
        self.assertIsNone(name2)

        # Genuine human name distinct from business name
        html_valid = """
        <html><body>
        <p>Owner: Robert Johnson</p>
        </body></html>
        """
        name3, role3 = find_decision_maker_from_html(html_valid, business_name="Apex Cooling Co")
        self.assertEqual(name3, "Robert Johnson")

    @patch('dns.resolver.resolve')
    @patch('smtplib.SMTP')
    def test_verify_email_smtp_statuses(self, mock_smtp_class, mock_dns_resolve):
        # Setup DNS MX mock
        mx_mock = MagicMock()
        mx_mock.preference = 10
        mx_mock.exchange = 'mail.example.com.'
        mock_dns_resolve.return_value = [mx_mock]

        mock_smtp = MagicMock()
        mock_smtp_class.return_value = mock_smtp

        # 1. Non-catch-all, 250 confirmed -> Verified
        mock_smtp.rcpt.side_effect = [
            (550, b'User unknown'), # Probe random email rejected (NOT catch-all)
            (250, b'OK recipient valid') # Target email accepted
        ]
        is_valid, status = verify_email_smtp("john@example.com")
        self.assertTrue(is_valid)
        self.assertEqual(status, "Verified")

        # 2. Catch-all domain (probe returns 250) -> MX Only
        mock_smtp.rcpt.side_effect = [
            (250, b'OK catch-all'), # Probe accepted
            (250, b'OK')
        ]
        is_valid, status = verify_email_smtp("random@example.com")
        self.assertTrue(is_valid)
        self.assertEqual(status, "MX Only")

        # 3. Mailbox rejected (550) -> Invalid
        mock_smtp.rcpt.side_effect = [
            (550, b'User unknown'),
            (550, b'No such user')
        ]
        is_valid, status = verify_email_smtp("nonexistent@example.com")
        self.assertFalse(is_valid)
        self.assertEqual(status, "Invalid")

        # 4. Empty or malformed -> Not Found
        is_valid, status = verify_email_smtp("")
        self.assertFalse(is_valid)
        self.assertEqual(status, "Not Found")

if __name__ == '__main__':
    unittest.main()
