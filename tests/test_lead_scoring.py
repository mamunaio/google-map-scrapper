import unittest
from services.lead_scoring import calculate_lead_score, DEFAULT_SCORING_WEIGHTS

class TestLeadScoring(unittest.TestCase):
    def test_default_weights_sum_to_100(self):
        total = sum(DEFAULT_SCORING_WEIGHTS.values())
        self.assertEqual(total, 100)
        self.assertEqual(len(DEFAULT_SCORING_WEIGHTS), 9)

    def test_weight_normalization(self):
        custom_weights = {k: 10 for k in DEFAULT_SCORING_WEIGHTS}
        # 9 * 10 = 90 (not 100) -> should be normalized to 100
        result = calculate_lead_score({}, weights=custom_weights)
        total_normalized = sum(result["weights_applied"].values())
        self.assertAlmostEqual(total_normalized, 100.0, places=2)

    def test_failed_audit_yields_manual_review(self):
        audit_empty = {"Website": ""}
        result = calculate_lead_score(audit_empty)
        self.assertEqual(result["research_priority"], "Manual Review")
        self.assertIn("Manual Review", result["research_priority"])

    def test_high_priority_lead(self):
        lead_data = {
            "Website": "https://examplehvac.com",
            "Email": "john@examplehvac.com",
            "Phone Number": "+1-555-1234",
            "Decision Maker": "John Doe (Owner)",
            "intelligence": {
                "performance": {"mobile_score": 35},
                "seo": {"seo_score": 45},
                "features": {
                    "lead_capture": {"status": "Not Detected"},
                    "booking": {"status": "Not Detected"},
                    "chatbot": {"status": "Not Detected"},
                    "voice_agent": {"status": "Not Detected"}
                },
                "technical": {
                    "ssl_certificate": {"status": "Valid"},
                    "mobile_usability": {"status": "Good"}
                }
            }
        }
        res = calculate_lead_score(lead_data)
        self.assertGreaterEqual(res["research_score"], 68)
        self.assertEqual(res["research_priority"], "High Priority")
        self.assertTrue(len(res["dimension_scores"]) == 9)
        self.assertIn("mobile performance", res["main_identified_gap"].lower())

    def test_low_priority_fully_optimized_lead(self):
        lead_data = {
            "Website": "https://modernplumbing.com",
            "Email": "",
            "Phone Number": "",
            "Decision Maker": "",
            "intelligence": {
                "performance": {"mobile_score": 95},
                "seo": {"seo_score": 95},
                "features": {
                    "lead_capture": {"status": "Detected", "details": {"has_quote_form": True}},
                    "booking": {"status": "Detected"},
                    "chatbot": {"status": "Detected"},
                    "voice_agent": {"status": "Detected"}
                },
                "technical": {
                    "ssl_certificate": {"status": "Valid"},
                    "mobile_usability": {"status": "Good"}
                }
            }
        }
        res = calculate_lead_score(lead_data)
        self.assertLess(res["research_score"], 45)
        self.assertEqual(res["research_priority"], "Low Priority")

if __name__ == '__main__':
    unittest.main()
