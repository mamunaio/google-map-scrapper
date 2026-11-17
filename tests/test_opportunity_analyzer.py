import unittest
from services.opportunity_analyzer import analyze_business_opportunities

class TestOpportunityAnalyzer(unittest.TestCase):
    def test_nine_field_opportunity_schema(self):
        features = {
            "booking": {"status": "Not Detected"},
            "chatbot": {"status": "Not Detected"},
            "voice_agent": {"status": "Not Detected"},
            "lead_capture": {"status": "Not Detected", "details": {}},
            "crm": {"status": "Unknown"},
            "review_management": {"status": "Unknown"}
        }
        seo = {
            "seo_score": 50,
            "findings": ["Missing meta description"]
        }
        tech = {
            "ssl_certificate": {"status": "Expired"},
            "mobile_usability": {"status": "Poor"}
        }

        result = analyze_business_opportunities(
            features_result=features,
            seo_result=seo,
            technical_result=tech,
            decision_maker="Jane Doe (CEO)",
            email="jane@acme.com",
            business_name="Acme Corporation",
            target_url="https://acme.com"
        )

        opportunities = result["detected_opportunities"]
        self.assertGreater(len(opportunities), 0)

        required_fields = {
            "Business Name", "Opportunity Category", "Related Finding",
            "Evidence URL", "Evidence Description", "Potential Business Impact",
            "Recommended Service", "Confidence Level", "Research Status"
        }

        for opp in opportunities:
            # Check all 9 fields exist
            self.assertEqual(set(opp.keys()), required_fields)
            self.assertEqual(opp["Business Name"], "Acme Corporation")
            self.assertEqual(opp["Evidence URL"], "https://acme.com")
            # Verify no fabricated claims
            impact = opp["Potential Business Impact"].lower()
            hook = opp["Recommended Service"].lower()
            self.assertNotIn("25-30%", impact)
            self.assertNotIn("guaranteed top 3", impact)
            self.assertNotIn("guaranteed", hook)

if __name__ == '__main__':
    unittest.main()
