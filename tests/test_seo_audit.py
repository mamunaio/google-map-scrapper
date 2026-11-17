import unittest
from services.seo_audit import audit_page_seo

class TestSEOAudit(unittest.TestCase):
    def test_missing_elements_flagged(self):
        html = "<html><body><p>Bare minimal page</p></body></html>"
        res = audit_page_seo(html, "https://example.com")
        findings = [f["name"] for f in res["findings"]]
        self.assertIn("Missing Page Title", findings)
        self.assertIn("Missing Meta Description", findings)
        self.assertIn("Missing H1 Heading", findings)
        self.assertLess(res["seo_score"], 60)

    def test_complete_seo_elements_pass(self):
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Acme Air Conditioning & Heating Repair in Houston, TX</title>
            <meta name="description" content="Houston's trusted HVAC experts offering 24/7 air conditioning repair, heating maintenance, and commercial installation. Call today for a free quote!">
            <link rel="canonical" href="https://acmeair.com">
            <meta property="og:title" content="Acme Air Conditioning">
            <meta property="og:image" content="https://acmeair.com/og.jpg">
            <script type="application/ld+json">
            {
                "@context": "https://schema.org",
                "@type": "LocalBusiness",
                "name": "Acme Air Conditioning"
            }
            </script>
        </head>
        <body>
            <h1>Houston Air Conditioning & Heating Services</h1>
            <h2>Emergency Repairs</h2>
            <img src="/logo.png" alt="Acme Air Logo">
        </body>
        </html>
        """
        res = audit_page_seo(html, "https://acmeair.com")
        findings = [f["name"] for f in res["findings"]]
        self.assertNotIn("Missing Page Title", findings)
        self.assertNotIn("Missing Meta Description", findings)
        self.assertNotIn("Missing H1 Heading", findings)
        self.assertGreaterEqual(res["seo_score"], 85)

if __name__ == '__main__':
    unittest.main()
