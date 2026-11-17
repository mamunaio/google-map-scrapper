import unittest
from services.opportunity_analyzer import analyze_business_opportunities

class TestOpportunityAnalyzer(unittest.TestCase):
    def test_essential_seven_opportunity_fields_schema(self):
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

        essential_fields = {
            "Business Name", "Opportunity Category", "Finding",
            "Evidence", "Confidence", "Research Status", "Recommended Service"
        }

        for opp in opportunities:
            # Check all 7 essential fields exist
            self.assertTrue(essential_fields.issubset(set(opp.keys())))
            self.assertEqual(opp["Business Name"], "Acme Corporation")
            self.assertIn(opp["Confidence"], ["High", "Medium", "Low"])
            self.assertIn(opp["Research Status"], ["Detected", "Not Detected", "Unknown", "Needs Review"])

            # Verify no fabricated claims
            impact = opp.get("Potential Business Impact", "").lower()
            hook = opp["Recommended Service"].lower()
            self.assertNotIn("25-30%", impact)
            self.assertNotIn("guaranteed top 3", impact)
            self.assertNotIn("guaranteed", hook)

    def test_missing_public_elements_marked_needs_review(self):
        # Absence of public code does NOT prove internal absence; must be Needs Review
        features = {
            "booking": {"status": "Not Detected"},
            "chatbot": {"status": "Not Detected"},
            "crm": {"status": "Not Detected"},
            "voice_agent": {"status": "Not Detected"},
            "review_management": {"status": "Not Detected"}
        }
        result = analyze_business_opportunities(
            features_result=features,
            seo_result={"findings": [], "seo_score": 100},
            technical_result={"ssl_certificate": {"status": "Valid"}, "mobile_usability": {"has_viewport": True}},
            decision_maker="John Owner",
            email="john@example.com",
            business_name="Example HVAC",
            target_url="https://example.com"
        )
        opps = result["detected_opportunities"]
        # Public-element absences must have Research Status 'Needs Review'
        for opp in opps:
            if opp["Opportunity Category"] in ["Workflow Automation", "AI Automation", "CRM Integration", "AI Voice Automation", "Reputation Automation"]:
                self.assertEqual(opp["Research Status"], "Needs Review")
                self.assertEqual(opp["Confidence"], "Medium")
                self.assertIn("no public", opp["Finding"].lower())

    def test_confirmed_technical_issues_marked_detected(self):
        # Confirmed on-page issues should have Research Status 'Detected' and Confidence 'High'
        features = {}
        tech = {
            "ssl_certificate": {"status": "Expired", "evidence": "Certificate expired on 2026-01-01"},
            "mobile_usability": {"has_viewport": False, "overflow_risk": True}
        }
        result = analyze_business_opportunities(
            features_result=features,
            seo_result={"findings": [{"name": "Missing Meta Description", "severity": "High", "evidence": "No meta tag"}], "seo_score": 50},
            technical_result=tech,
            decision_maker="",
            email="",
            business_name="Example HVAC",
            target_url="https://example.com"
        )
        opps = result["detected_opportunities"]
        for opp in opps:
            if opp["Opportunity Category"] in ["Technical SEO", "Website Development", "Website Security"]:
                self.assertEqual(opp["Research Status"], "Detected")
                self.assertEqual(opp["Confidence"], "High")

if __name__ == '__main__':
    unittest.main()
