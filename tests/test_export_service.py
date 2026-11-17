import unittest
import openpyxl
from services.export_service import (
    generate_styled_excel,
    generate_standard_intelligence_workbook,
    generate_lead_tracker_csv,
    deduplicate_leads,
    normalize_priority,
    normalize_email_status,
    LEAD_TRACKER_COLUMNS,
    WEBSITE_AUDIT_COLUMNS,
    BUSINESS_OPPORTUNITIES_COLUMNS
)

class TestExportService(unittest.TestCase):
    def setUp(self):
        self.sample_leads = [
            {
                "Business Name": "Acme Air HVAC",
                "Category": "HVAC Contractor",
                "City": "Dallas",
                "State": "TX",
                "Rating": 4.8,
                "Reviews": 120,
                "Phone": "+1-214-555-0100",
                "Website": "https://acmeairhvac.com",
                "Google Maps URL": "https://maps.google.com/?cid=123",
                "Contact Person": "John Doe",
                "Email": "john@acmeairhvac.com",
                "Email Status": "Verified",
                "Priority": "High",
                "Lead Score": 78,
                "Main Opportunity": "No online booking",
                "Notes": "High opportunity score with booking gap",
                "intelligence": {
                    "lead_score": 78,
                    "priority_tier": "High Priority",
                    "performance": {"mobile_score": 42, "desktop_score": 85},
                    "seo": {"seo_score": 65, "findings": [{"name": "Missing meta description", "severity": "High"}]},
                    "technical": {
                        "ssl_certificate": {"status": "Valid"},
                        "mobile_usability": {"has_viewport": True, "overflow_risk": False},
                        "findings": []
                    },
                    "features": {
                        "lead_capture": {"status": "Not Detected"},
                        "booking": {"status": "Not Detected"},
                        "chatbot": {"status": "Not Detected"},
                        "voice_agent": {"status": "Not Detected"},
                        "crm": {"status": "Unknown"},
                        "review_management": {"status": "Unknown"}
                    },
                    "opportunities": {
                        "lead_score": 78,
                        "priority": "High",
                        "main_gap": "No online booking",
                        "next_action": "Reach out about online booking",
                        "detected_opportunities": [
                            {
                                "Business Name": "Acme Air HVAC",
                                "Opportunity Category": "Workflow Automation",
                                "Finding": "No Public Booking Widget Detected",
                                "Evidence": "No self-service scheduling scripts found in DOM",
                                "Confidence": "Medium",
                                "Research Status": "Needs Review",
                                "Recommended Service": "Online Booking & Appointment Scheduling Integration"
                            }
                        ]
                    }
                }
            },
            # Duplicate record of Acme Air HVAC to test deduplication
            {
                "Business Name": "Acme Air HVAC",
                "Website": "https://acmeairhvac.com",
                "Phone": "+1-214-555-0100"
            }
        ]

    def test_format_b_standard_3_sheet_workbook(self):
        excel_stream = generate_standard_intelligence_workbook(self.sample_leads)
        self.assertIsNotNone(excel_stream)

        wb = openpyxl.load_workbook(excel_stream)
        # Verify exactly 3 sheets
        self.assertEqual(wb.sheetnames, ["Lead Tracker", "Website Audit", "Business Opportunities"])

        # Sheet 1: exactly 16 essential columns
        ws1 = wb["Lead Tracker"]
        header1 = [cell.value for cell in ws1[1]]
        self.assertEqual(len(header1), 16)
        self.assertEqual(header1, LEAD_TRACKER_COLUMNS)
        self.assertEqual(ws1.freeze_panes, "A2")

        # Sheet 2: exactly 15 essential columns
        ws2 = wb["Website Audit"]
        header2 = [cell.value for cell in ws2[1]]
        self.assertEqual(len(header2), 15)
        self.assertEqual(header2, WEBSITE_AUDIT_COLUMNS)
        self.assertEqual(ws2.freeze_panes, "A2")

        # Sheet 3: exactly 7 essential columns
        ws3 = wb["Business Opportunities"]
        header3 = [cell.value for cell in ws3[1]]
        self.assertEqual(len(header3), 7)
        self.assertEqual(header3, BUSINESS_OPPORTUNITIES_COLUMNS)
        self.assertEqual(ws3.freeze_panes, "A2")

    def test_lead_deduplication_in_sheets_01_and_02(self):
        excel_stream = generate_standard_intelligence_workbook(self.sample_leads)
        wb = openpyxl.load_workbook(excel_stream)

        # Duplicate lead was provided in setUp; Sheet 01 and Sheet 02 should contain only 1 data row!
        ws1 = wb["Lead Tracker"]
        self.assertEqual(ws1.max_row, 2) # 1 header row + 1 data row

        ws2 = wb["Website Audit"]
        self.assertEqual(ws2.max_row, 2) # 1 header row + 1 data row

    def test_excel_numeric_formats(self):
        excel_stream = generate_standard_intelligence_workbook(self.sample_leads)
        wb = openpyxl.load_workbook(excel_stream)
        ws1 = wb["Lead Tracker"]

        # Rating cell (col 8): float with 0.0 format
        rating_cell = ws1.cell(row=2, column=8)
        self.assertIsInstance(rating_cell.value, float)
        self.assertEqual(rating_cell.value, 4.8)
        self.assertEqual(rating_cell.number_format, '0.0')

        # Reviews cell (col 9): int with #,##0 format
        rev_cell = ws1.cell(row=2, column=9)
        self.assertIsInstance(rev_cell.value, int)
        self.assertEqual(rev_cell.value, 120)
        self.assertEqual(rev_cell.number_format, '#,##0')

        # Lead Score cell (col 14): int with 0 format
        score_cell = ws1.cell(row=2, column=14)
        self.assertIsInstance(score_cell.value, int)
        self.assertEqual(score_cell.value, 78)
        self.assertEqual(score_cell.number_format, '0')

    def test_phantom_records_prevented_in_sheet_03(self):
        # Lead with 0 opportunities
        lead_no_opps = {
            "Business Name": "Zero Opps Co",
            "Website": "https://zeroopps.com",
            "intelligence": {
                "opportunities": {
                    "detected_opportunities": []
                }
            }
        }
        excel_stream = generate_standard_intelligence_workbook([lead_no_opps])
        wb = openpyxl.load_workbook(excel_stream)
        ws3 = wb["Business Opportunities"]

        # Crucial test: exactly 1 row (the header row). ZERO phantom records emitted!
        self.assertEqual(ws3.max_row, 1)

    def test_multiple_and_single_opportunities_emitted(self):
        lead = {
            "Business Name": "Multi Opps Co",
            "Website": "https://multiopps.com",
            "intelligence": {
                "opportunities": {
                    "detected_opportunities": [
                        {
                            "Opportunity Category": "Workflow Automation",
                            "Finding": "No Public Booking Widget Detected",
                            "Evidence": "Missing scheduling scripts",
                            "Confidence": "Medium",
                            "Research Status": "Needs Review",
                            "Recommended Service": "Online Booking Calendar Integration"
                        },
                        {
                            "Opportunity Category": "AI Automation",
                            "Finding": "No Public Chatbot Detected",
                            "Evidence": "No chat widget in DOM",
                            "Confidence": "Medium",
                            "Research Status": "Needs Review",
                            "Recommended Service": "24/7 AI Chatbot"
                        }
                    ]
                }
            }
        }
        excel_stream = generate_standard_intelligence_workbook([lead])
        wb = openpyxl.load_workbook(excel_stream)
        ws3 = wb["Business Opportunities"]

        # 1 header + 2 opportunity rows = 3 rows
        self.assertEqual(ws3.max_row, 3)
        self.assertEqual(ws3.cell(row=2, column=1).value, "Multi Opps Co")
        self.assertEqual(ws3.cell(row=2, column=2).value, "Workflow Automation")
        self.assertEqual(ws3.cell(row=3, column=2).value, "AI Automation")

    def test_lead_tracker_csv_export(self):
        csv_str = generate_lead_tracker_csv(self.sample_leads)
        self.assertIsNotNone(csv_str)
        lines = csv_str.strip().split("\n")

        # 1 header line + 1 deduplicated data line = 2 lines
        self.assertEqual(len(lines), 2)
        header_cols = lines[0].strip().split(",")
        self.assertEqual(header_cols, LEAD_TRACKER_COLUMNS)
        self.assertIn("Acme Air HVAC", lines[1])
        self.assertIn("Dallas", lines[1])
        self.assertIn("TX", lines[1])

    def test_normalize_priority_handling(self):
        # High stays High
        self.assertEqual(normalize_priority("High"), "High")
        self.assertEqual(normalize_priority("High Priority"), "High")

        # Medium stays Medium
        self.assertEqual(normalize_priority("Medium"), "Medium")
        self.assertEqual(normalize_priority("Medium Priority"), "Medium")

        # Low stays Low
        self.assertEqual(normalize_priority("Low"), "Low")
        self.assertEqual(normalize_priority("Low Priority"), "Low")

        # Explicit Manual Review stays Manual Review
        self.assertEqual(normalize_priority("Manual Review"), "Manual Review")
        self.assertEqual(normalize_priority("Manual"), "Manual Review")

        # Missing, empty, or unrecognized values default to Manual Review (NEVER silently classified as Low)
        self.assertEqual(normalize_priority(""), "Manual Review")
        self.assertEqual(normalize_priority(None), "Manual Review")
        self.assertEqual(normalize_priority("Unknown"), "Manual Review")
        self.assertEqual(normalize_priority("Unrecognized_Value"), "Manual Review")
        self.assertEqual(normalize_priority("Pending"), "Manual Review")

    def test_incomplete_record_priority_defaults_to_manual_review_in_exports(self):
        # Lead with completely missing priority
        lead_missing_priority = {
            "Business Name": "Incomplete Data LLC",
            "Website": "https://incompletedata.com",
            "Phone": "+1-555-0001"
            # No Priority, no intelligence
        }

        # 1. Test Excel export Sheet 01 priority column (column 13)
        stream = generate_standard_intelligence_workbook([lead_missing_priority])
        wb = openpyxl.load_workbook(stream)
        ws1 = wb["Lead Tracker"]
        priority_val = ws1.cell(row=2, column=13).value
        self.assertEqual(priority_val, "Manual Review")
        self.assertNotEqual(priority_val, "Low")

        # 2. Test CSV export priority column
        csv_str = generate_lead_tracker_csv([lead_missing_priority])
        lines = csv_str.strip().split("\n")
        self.assertEqual(len(lines), 2)
        row_fields = lines[1].split(",")
        priority_idx = LEAD_TRACKER_COLUMNS.index("Priority")
        self.assertEqual(row_fields[priority_idx], "Manual Review")
        self.assertNotEqual(row_fields[priority_idx], "Low")

    def test_audit_status_consistency_no_contradictions(self):
        # A high-quality lead with 100/100 score and complete metadata (e.g. Harlen Johnson HVAC)
        flawless_lead = {
            "Business Name": "Harlen Johnson HVAC",
            "Category": "HVAC contractor",
            "City": "Dallas",
            "State": "TX",
            "Phone": "(972) 241-7771",
            "Website": "https://harlenjohnson.com",
            "Google Maps URL": "https://www.google.com/maps/place/Harlen+Johnson",
            "intelligence": {
                "seo": {
                    "seo_score": 100,
                    "findings": [],
                    "metrics": {
                        "title": "Harlen Johnson Heating and Air Conditioning",
                        "meta_description": "Premier HVAC service and repair in Dallas, TX.",
                        "canonical_url": "https://harlenjohnson.com/",
                        "h1_tags": ["Reliable Heating and Air in Dallas"],
                        "images_total": 8,
                        "images_missing_alt": 0,
                        "is_noindex": False
                    },
                    "robots_sitemap": {
                        "has_robots_txt": True,
                        "has_sitemap_xml": True
                    }
                },
                "technical": {
                    "ssl_certificate": {"status": "Valid", "has_ssl": True},
                    "mobile_usability": {"status": "Mobile-Friendly", "has_viewport": True, "overflow_risk": False},
                    "findings": []
                },
                "performance": {
                    "mobile_score": 92,
                    "performance_status": "Optimal"
                }
            }
        }

        stream = generate_standard_intelligence_workbook([flawless_lead])
        wb = openpyxl.load_workbook(stream)
        ws_audit = wb["Website Audit"]

        # Header:
        # Col 1: Business Name, Col 2: Website, Col 3: Website Status, Col 4: Page Title,
        # Col 5: Meta Description Status, Col 6: Canonical Status, Col 7: Indexability / Robots Status,
        # Col 8: H1 Status, Col 9: Image Alt Status, Col 10: Mobile / Viewport Status,
        # Col 11: HTTPS Status, Col 12: Performance Status, Col 13: Key SEO Issues,
        # Col 14: Technical Issues, Col 15: Audit Summary
        self.assertEqual(ws_audit.cell(row=2, column=1).value, "Harlen Johnson HVAC")
        self.assertEqual(ws_audit.cell(row=2, column=2).value, "https://harlenjohnson.com")
        self.assertEqual(ws_audit.cell(row=2, column=3).value, "Online")
        self.assertEqual(ws_audit.cell(row=2, column=4).value, "Harlen Johnson Heating and Air Conditioning")
        self.assertEqual(ws_audit.cell(row=2, column=5).value, "Passed")
        self.assertEqual(ws_audit.cell(row=2, column=6).value, "Passed")
        self.assertEqual(ws_audit.cell(row=2, column=7).value, "Passed")
        self.assertEqual(ws_audit.cell(row=2, column=8).value, "Passed")
        self.assertEqual(ws_audit.cell(row=2, column=9).value, "Passed")
        self.assertEqual(ws_audit.cell(row=2, column=10).value, "Passed")
        self.assertEqual(ws_audit.cell(row=2, column=11).value, "Passed")
        self.assertEqual(ws_audit.cell(row=2, column=12).value, "Passed")
        self.assertEqual(ws_audit.cell(row=2, column=13).value, "None detected")
        self.assertEqual(ws_audit.cell(row=2, column=14).value, "None detected")
        self.assertIn("SEO Score: 100/100", ws_audit.cell(row=2, column=15).value)

    def test_invalid_website_audit_prevention(self):
        # Business with Google Ads tracking link in Website (e.g. Skylinq Home / Tempo Air)
        lead_aclk = {
            "Business Name": "Skylinq Home",
            "Category": "Air conditioning contractor",
            "City": "Dallas",
            "State": "TX",
            "Website": "/aclk?sa=l&ai=DChcSEwj_tracking_only",
            "Google Maps URL": "https://www.google.com/maps/place/Skylinq+Home"
        }
        lead_relative = {
            "Business Name": "Tempo Air",
            "Category": "Air conditioning contractor",
            "City": "Irving",
            "State": "TX",
            "Website": "/maps/place/Tempo+Air",
            "Google Maps URL": "https://www.google.com/maps/place/Tempo+Air"
        }

        stream = generate_standard_intelligence_workbook([lead_aclk, lead_relative])
        wb = openpyxl.load_workbook(stream)

        # Sheet 01 (Lead Tracker)
        ws_leads = wb["Lead Tracker"]
        # Website must be sanitized to empty/None (col 6)
        self.assertIn(ws_leads.cell(row=2, column=6).value, [None, ""])
        self.assertIn(ws_leads.cell(row=3, column=6).value, [None, ""])
        # Google Maps URL is preserved independently (col 7)
        self.assertEqual(ws_leads.cell(row=2, column=7).value, "https://www.google.com/maps/place/Skylinq+Home")
        self.assertEqual(ws_leads.cell(row=3, column=7).value, "https://www.google.com/maps/place/Tempo+Air")

        # Sheet 02 (Website Audit)
        ws_audit = wb["Website Audit"]
        # Must NOT be marked Online
        self.assertIn(ws_audit.cell(row=2, column=2).value, [None, ""])
        self.assertEqual(ws_audit.cell(row=2, column=3).value, "Not checked")
        self.assertEqual(ws_audit.cell(row=2, column=13).value, "No website provided")
        self.assertEqual(ws_audit.cell(row=2, column=15).value, "Audit skipped: domain unavailable.")

        self.assertIn(ws_audit.cell(row=3, column=2).value, [None, ""])
        self.assertEqual(ws_audit.cell(row=3, column=3).value, "Not checked")
        self.assertEqual(ws_audit.cell(row=3, column=13).value, "No website provided")
        self.assertEqual(ws_audit.cell(row=3, column=15).value, "Audit skipped: domain unavailable.")

        # Test CSV export as well
        csv_str = generate_lead_tracker_csv([lead_aclk])
        lines = csv_str.strip().split("\n")
        web_idx = LEAD_TRACKER_COLUMNS.index("Website")
        self.assertEqual(lines[1].split(",")[web_idx], "")

    def test_email_mx_only_status_preserved_and_distinct_from_verified(self):
        # MX Only must remain MX Only, never claimed as Verified
        self.assertEqual(normalize_email_status("MX Only", "info@example.com"), "MX Only")
        self.assertEqual(normalize_email_status("Valid (MX Only)", "info@example.com"), "MX Only")
        self.assertEqual(normalize_email_status("Catch-All", "info@example.com"), "MX Only")
        self.assertNotEqual(normalize_email_status("MX Only", "info@example.com"), "Verified")

        lead_mx = {
            "Business Name": "Dallas MX Cooling",
            "Email": "contact@dallasmxcooling.com",
            "Email Status": "MX Only"
        }
        stream = generate_standard_intelligence_workbook([lead_mx])
        wb = openpyxl.load_workbook(stream)
        ws_leads = wb["Lead Tracker"]
        # Col 12 is Email Status
        status_val = ws_leads.cell(row=2, column=12).value
        self.assertEqual(status_val, "MX Only")
        self.assertNotEqual(status_val, "Verified")

if __name__ == '__main__':
    unittest.main()
