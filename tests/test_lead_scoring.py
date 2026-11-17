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

    def test_missing_audit_data_yields_manual_review(self):
        lead_no_intel = {"Website": "https://example.com"}
        result = calculate_lead_score(lead_no_intel)
        self.assertEqual(result["research_priority"], "Manual Review")

    def test_scan_failed_yields_manual_review(self):
        lead_scan_failed = {
            "Website": "https://example.com",
            "intelligence": {
                "performance": {"audit_status": "Scan Failed"},
                "seo": {"status": "Scan Failed"},
                "features": {
                    "lead_capture": {"status": "Scan Failed"},
                    "booking": {"status": "Scan Failed"}
                }
            }
        }
        result = calculate_lead_score(lead_scan_failed)
        self.assertEqual(result["research_priority"], "Manual Review")
        self.assertIn("crawler data is incomplete", result["suggested_next_action"])

    def test_unknown_lead_capture_neutral_scoring(self):
        lead_data = {
            "Website": "https://example.com",
            "Phone": "+1-555-1234",
            "intelligence": {
                "performance": {"mobile_score": 80},
                "seo": {"seo_score": 85},
                "features": {
                    "lead_capture": {"status": "Unknown"},
                    "booking": {"status": "Detected"},
                    "chatbot": {"status": "Detected"},
                    "voice_agent": {"status": "Detected"}
                },
                "technical": {"ssl_certificate": {"status": "Valid"}, "mobile_usability": {"status": "Good"}}
            }
        }
        res = calculate_lead_score(lead_data)
        # Lead capture should be neutral (5/10 * 15 = 7.5) and NOT treated as confirmed missing
        self.assertEqual(res["dimension_scores"]["lead_capture"], 7.5)
        self.assertIn("inconclusive", res["dimension_explanations"]["lead_capture"])
        # Crucially: no false gap should be logged for unknown lead capture
        gap_categories = [g[0] for g in res.get("gaps_identified", [])]
        self.assertNotIn("Lead Capture", gap_categories)

    def test_unknown_booking_neutral_scoring(self):
        lead_data = {
            "Website": "https://example.com",
            "Phone": "+1-555-1234",
            "intelligence": {
                "performance": {"mobile_score": 80},
                "seo": {"seo_score": 85},
                "features": {
                    "lead_capture": {"status": "Detected"},
                    "booking": {"status": "Unknown"},
                    "chatbot": {"status": "Detected"},
                    "voice_agent": {"status": "Detected"}
                },
                "technical": {"ssl_certificate": {"status": "Valid"}, "mobile_usability": {"status": "Good"}}
            }
        }
        res = calculate_lead_score(lead_data)
        self.assertEqual(res["dimension_scores"]["booking_automation"], 7.5)
        self.assertIn("inconclusive", res["dimension_explanations"]["booking_automation"])

    def test_unknown_chatbot_and_voice_neutral_scoring(self):
        lead_data = {
            "Website": "https://example.com",
            "Phone": "+1-555-1234",
            "intelligence": {
                "performance": {"mobile_score": 80},
                "seo": {"seo_score": 85},
                "features": {
                    "lead_capture": {"status": "Detected"},
                    "booking": {"status": "Detected"},
                    "chatbot": {"status": "Unknown"},
                    "voice_agent": {"status": "Unknown"}
                },
                "technical": {"ssl_certificate": {"status": "Valid"}, "mobile_usability": {"status": "Good"}}
            }
        }
        res = calculate_lead_score(lead_data)
        self.assertEqual(res["dimension_scores"]["chatbot_voice"], 5.0)
        self.assertIn("inconclusive", res["dimension_explanations"]["chatbot_voice"])

    def test_confirmed_not_detected_high_priority(self):
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
        self.assertEqual(len(res["dimension_scores"]), 9)
        self.assertEqual(len(res["dimension_explanations"]), 9)
        self.assertIn("mobile performance", res["main_identified_gap"].lower())

    def test_fully_detected_features_low_priority(self):
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
        self.assertIn("well-optimized", res["dimension_explanations"]["technical_seo"])

    def test_configurable_priority_thresholds(self):
        lead_data = {
            "Website": "https://midpriorityhvac.com",
            "Phone": "+1-214-555-9000",
            "intelligence": {
                "performance": {"mobile_score": 60},
                "seo": {"seo_score": 70},
                "features": {
                    "lead_capture": {"status": "Detected"},
                    "booking": {"status": "Not Detected"}, # Gap
                    "chatbot": {"status": "Detected"},
                    "voice_agent": {"status": "Detected"}
                },
                "technical": {"ssl_certificate": {"status": "Valid"}, "mobile_usability": {"status": "Good"}}
            }
        }
        # With default thresholds (high: 68, medium: 40)
        res_default = calculate_lead_score(lead_data)
        score = res_default["research_score"]

        # Custom aggressive thresholds where high threshold is lower than score
        custom_thresholds = {"high": score - 5, "medium": score - 15}
        res_custom = calculate_lead_score(lead_data, priority_thresholds=custom_thresholds)

        self.assertEqual(res_custom["research_priority"], "High Priority")
        self.assertEqual(res_custom["priority"], "High")
        self.assertIn("priority_reason", res_custom)
        self.assertTrue(len(res_custom["priority_reason"]) > 10)

if __name__ == '__main__':
    unittest.main()
