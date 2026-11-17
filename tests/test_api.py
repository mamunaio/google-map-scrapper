import unittest
import json
from unittest.mock import patch
from app import app

class TestAppAPI(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_homepage_loads(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

    def test_scrape_api_missing_url(self):
        response = self.client.post('/api/scrape', json={})
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertFalse(data["success"])

    def test_scrape_api_ssrf_blocked(self):
        response = self.client.post('/api/scrape', json={"url": "http://127.0.0.1:8000", "type": "website"})
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertFalse(data["success"])
        self.assertIn("Security restriction", data["error"])

    def test_scrape_api_maps_ssrf_blocked_localhost(self):
        response = self.client.post('/api/scrape', json={"url": "http://127.0.0.1:8000/maps", "type": "maps"})
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertFalse(data["success"])
        self.assertIn("Security restriction", data["error"])

    def test_scrape_api_maps_ssrf_blocked_external_domain(self):
        response = self.client.post('/api/scrape', json={"url": "https://example.com/maps/search/hvac", "type": "maps"})
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertFalse(data["success"])
        self.assertIn("Security restriction", data["error"])

    def test_scrape_api_maps_ssrf_blocked_metadata(self):
        response = self.client.post('/api/scrape', json={"url": "http://169.254.169.254/latest", "type": "maps"})
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertFalse(data["success"])
        self.assertIn("Security restriction", data["error"])

    @patch('app.scrape_google_maps')
    @patch('app.crawl_and_audit_website')
    def test_scrape_api_maps_search_url_multi_lead(self, mock_crawl, mock_maps):
        mock_maps.return_value = {
            "success": True,
            "is_search": True,
            "leads": [
                {"Business Name": "Dallas Pro HVAC", "Website": "https://dallasprohvac.com", "Phone Number": "(214) 555-0101"},
                {"Business Name": "Lone Star Air", "Website": "https://lonestarair.com", "Phone Number": "(214) 555-0102"},
                {"Business Name": "Texas Cooling", "Website": "", "Phone Number": "(214) 555-0103"}
            ],
            "count": 3,
            "data": {"Business Name": "Dallas Pro HVAC", "Website": "https://dallasprohvac.com"}
        }

        mock_crawl.side_effect = lambda url, **kwargs: {
            "Website": url,
            "Email": f"contact@{url.replace('https://', '')}",
            "Decision Maker": "John Doe",
            "Email Verification": "SMTP Valid",
            "Facebook": "",
            "Instagram": "",
            "LinkedIn": "",
            "About Page Link": "",
            "intelligence": {"lead_score": 80, "priority_tier": "High Priority Prospect"}
        }

        response = self.client.post('/api/scrape', json={
            "url": "https://www.google.com/maps/search/HVAC+contractors+in+Dallas,+TX",
            "type": "maps"
        })

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data["success"])
        self.assertTrue(data["is_search"])
        self.assertEqual(data["count"], 3)
        self.assertEqual(len(data["leads"]), 3)
        self.assertEqual(data["leads"][0]["Business Name"], "Dallas Pro HVAC")
        self.assertEqual(data["leads"][0]["Email"], "contact@dallasprohvac.com")
        self.assertEqual(data["leads"][0]["Email Verification"], "SMTP Valid")
        self.assertEqual(data["data"]["Business Name"], "Dallas Pro HVAC")

    @patch('app.scrape_google_maps')
    @patch('app.crawl_and_audit_website')
    def test_scrape_api_maps_failed_website_enrichment_preserves_maps_lead(self, mock_crawl, mock_maps):
        mock_maps.return_value = {
            "success": True,
            "is_search": True,
            "leads": [
                {"Business Name": "Dallas Online HVAC", "Website": "https://dallasonline.com", "Phone Number": "(214) 555-1111", "City": "Dallas", "State": "TX"},
                {"Business Name": "Dallas Timeout HVAC", "Website": "https://dallastimeout.com", "Phone Number": "(214) 555-2222", "City": "Dallas", "State": "TX"}
            ],
            "count": 2,
            "data": {"Business Name": "Dallas Online HVAC", "Website": "https://dallasonline.com"}
        }

        def crawl_side_effect(url, **kwargs):
            if "dallastimeout" in url:
                raise Exception("Connection timed out after 12s")
            return {
                "Website": url,
                "Email": "info@dallasonline.com",
                "Decision Maker": "Alice Smith",
                "Email Verification": "SMTP Valid",
                "intelligence": {"opportunities": {"priority": "High"}}
            }

        mock_crawl.side_effect = crawl_side_effect

        response = self.client.post('/api/scrape', json={
            "url": "https://www.google.com/maps/search/HVAC+contractors+in+Dallas,+TX",
            "type": "maps"
        })

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data["success"])
        self.assertEqual(len(data["leads"]), 2)

        # Lead 1 is enriched
        self.assertEqual(data["leads"][0]["Business Name"], "Dallas Online HVAC")
        self.assertEqual(data["leads"][0]["Email"], "info@dallasonline.com")

        # Lead 2 failed website enrichment but is preserved with original Maps lead data
        self.assertEqual(data["leads"][1]["Business Name"], "Dallas Timeout HVAC")
        self.assertEqual(data["leads"][1]["Phone Number"], "(214) 555-2222")
        self.assertEqual(data["leads"][1]["City"], "Dallas")
        self.assertEqual(data["leads"][1]["State"], "TX")
        self.assertEqual(data["leads"][1]["Website"], "https://dallastimeout.com")

    @patch('app.scrape_google_maps')
    @patch('app.crawl_and_audit_website')
    def test_scrape_api_maps_aclk_without_adurl_sanitized_and_not_crawled(self, mock_crawl, mock_maps):
        mock_maps.return_value = {
            "success": True,
            "is_search": True,
            "leads": [
                {
                    "Business Name": "Dallas Ad HVAC",
                    "Website": "/aclk?sa=l&ai=internal_tracking_only",
                    "Phone Number": "(214) 555-3333"
                }
            ],
            "count": 1,
            "data": {"Business Name": "Dallas Ad HVAC"}
        }

        response = self.client.post('/api/scrape', json={
            "url": "https://www.google.com/maps/search/HVAC+contractors+in+Dallas,+TX",
            "type": "maps"
        })

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data["success"])
        self.assertEqual(len(data["leads"]), 1)
        # Website must be sanitized to empty string, and crawl must NOT be called for /aclk
        self.assertEqual(data["leads"][0]["Website"], "")
        mock_crawl.assert_not_called()

    @patch('app.scrape_google_maps')
    def test_scrape_api_maps_empty_failure_honest_422(self, mock_maps):
        mock_maps.return_value = {
            "success": False,
            "error": "No business listings found at the provided Google Maps search URL.",
            "leads": [],
            "count": 0,
            "is_search": True,
            "data": None
        }

        response = self.client.post('/api/scrape', json={
            "url": "https://www.google.com/maps/search/HVAC+contractors+in+Dallas,+TX",
            "type": "maps"
        })

        self.assertEqual(response.status_code, 422)
        data = json.loads(response.data)
        self.assertFalse(data["success"])
        self.assertEqual(data["count"], 0)
        self.assertEqual(data["leads"], [])
        self.assertIsNone(data["data"])
        self.assertIn("No business listings found", data["error"])

    @patch('app.scrape_google_maps')
    def test_scrape_api_maps_place_url_single_lead(self, mock_maps):
        mock_maps.return_value = {
            "success": True,
            "is_search": False,
            "leads": [{
                "Business Name": "Dallas Master Heating",
                "Website": "",
                "Phone Number": "(214) 555-9988",
                "Rating": "4.8",
                "Review Count": "320"
            }],
            "count": 1,
            "data": {
                "Business Name": "Dallas Master Heating",
                "Website": "",
                "Phone Number": "(214) 555-9988"
            }
        }

        response = self.client.post('/api/scrape', json={
            "url": "https://www.google.com/maps/place/Dallas+Master+Heating",
            "type": "maps"
        })

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data["success"])
        self.assertFalse(data["is_search"])
        self.assertEqual(data["count"], 1)
        self.assertEqual(len(data["leads"]), 1)
        self.assertEqual(data["leads"][0]["Business Name"], "Dallas Master Heating")

    @patch('app.crawl_and_audit_website')
    def test_scrape_api_website_type_preserves_contract(self, mock_crawl):
        mock_crawl.return_value = {
            "Website": "https://acmeair.com",
            "Email": "info@acmeair.com",
            "Decision Maker": "Steve Smith",
            "Email Verification": "SMTP Valid",
            "Facebook": "https://facebook.com/acmeair",
            "Instagram": "",
            "LinkedIn": "https://linkedin.com/company/acmeair",
            "About Page Link": "",
            "intelligence": {"lead_score": 75}
        }

        response = self.client.post('/api/scrape', json={
            "url": "https://acmeair.com",
            "type": "website",
            "business_name": "Acme Air"
        })

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data["success"])
        self.assertEqual(data["count"], 1)
        self.assertEqual(len(data["leads"]), 1)
        self.assertEqual(data["leads"][0]["Business Name"], "Acme Air")
        self.assertEqual(data["leads"][0]["Email"], "info@acmeair.com")
        self.assertEqual(data["data"]["Email"], "info@acmeair.com")

    def test_export_excel_api_validation(self):
        response = self.client.post('/api/export-excel', json={"leads": []})
        self.assertEqual(response.status_code, 400)

        sample_leads = [{
            "Business Name": "Acme Air",
            "Website": "https://acmeair.com",
            "Email": "info@acmeair.com",
            "Decision Maker": "Steve Smith (Owner)",
            "intelligence": {
                "lead_score": 85,
                "priority_tier": "High Priority Prospect",
                "seo": {"seo_score": 90},
                "opportunities": {
                    "lead_score": 85,
                    "priority_tier": "High Priority Prospect",
                    "detected_opportunities": [{"service": "AI Chatbot"}]
                }
            }
        }]
        resp_export = self.client.post('/api/export-excel', json={"leads": sample_leads})
        self.assertEqual(resp_export.status_code, 200)
        self.assertEqual(resp_export.mimetype, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

if __name__ == '__main__':
    unittest.main()
