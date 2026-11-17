import unittest
import json
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
