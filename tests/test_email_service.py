import unittest
from services.email_service import (
    decode_cloudflare_email,
    clean_and_validate_emails,
    extract_name_from_email_prefix,
    generate_email_permutations,
    extract_emails_and_socials,
    find_decision_maker_from_html
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

if __name__ == '__main__':
    unittest.main()
