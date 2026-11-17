import unittest
import openpyxl
from services.export_service import (
    generate_styled_excel,
    generate_standard_intelligence_workbook,
    generate_source_compatible_excel,
    SHEET_01_COLUMNS,
    SHEET_02_COLUMNS,
    SHEET_03_COLUMNS
)

class TestExportService(unittest.TestCase):
    def setUp(self):
        self.sample_leads = [
            {
                "Business Name": "Acme Air HVAC",
                "Google Category": "HVAC Contractor",
                "City": "Dallas",
                "State": "TX",
                "Google Rating": 4.8,
                "Review Count": 120,
                "Phone": "+1-214-555-0100",
                "Website": "https://acmeairhvac.com",
                "Google Maps Profile": "https://maps.google.com/?cid=123",
                "Decision Maker": "John Doe (Owner)",
                "Email": "john@acmeairhvac.com",
                "Email Verification": "Valid",
                "Custom Column 1": "Custom Value 1",
                "Custom Column 2": "Custom Value 2",
                "intelligence": {
                    "lead_score": 78,
                    "priority_tier": "High Priority",
                    "performance": {"mobile_score": 42, "desktop_score": 85},
                    "seo": {"seo_score": 65, "findings": ["Missing meta description"]},
                    "technical": {
                        "ssl_certificate": {"status": "Valid"},
                        "mobile_usability": {"status": "Needs Improvement"},
                        "findings": ["No viewport tag"]
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
                        "priority_tier": "High Priority",
                        "main_gap": "No online booking",
                        "next_action": "Reach out about online booking",
                        "detected_opportunities": [
                            {
                                "Business Name": "Acme Air HVAC",
                                "Opportunity Category": "Booking Automation",
                                "Related Finding": "No scheduling software detected",
                                "Evidence URL": "https://acmeairhvac.com",
                                "Evidence Description": "No booking widget found in DOM",
                                "Potential Business Impact": "Potential loss of after-hours appointments",
                                "Recommended Service": "Online Booking Calendar Integration",
                                "Confidence Level": "Medium",
                                "Research Status": "Uncontacted"
                            }
                        ]
                    }
                }
            },
            # Duplicate record to test duplicate preservation
            {
                "Business Name": "Acme Air HVAC",
                "Website": "https://acmeairhvac.com",
                "Custom Column 1": "Duplicate Row"
            }
        ]

    def test_format_b_standard_3_sheet_workbook(self):
        excel_stream = generate_standard_intelligence_workbook(self.sample_leads)
        self.assertIsNotNone(excel_stream)

        wb = openpyxl.load_workbook(excel_stream)
        # Verify exactly 3 sheets
        self.assertEqual(wb.sheetnames, ["Lead Tracker", "Website Audit", "Business Opportunities"])

        # Sheet 1: exactly 15 columns
        ws1 = wb["Lead Tracker"]
        header1 = [cell.value for cell in ws1[1]]
        self.assertEqual(len(header1), 15)
        self.assertEqual(header1, SHEET_01_COLUMNS)
        self.assertEqual(ws1.freeze_panes, "A2")

        # Sheet 2: exactly 18 columns
        ws2 = wb["Website Audit"]
        header2 = [cell.value for cell in ws2[1]]
        self.assertEqual(len(header2), 18)
        self.assertEqual(header2, SHEET_02_COLUMNS)
        self.assertEqual(ws2.freeze_panes, "A2")

        # Sheet 3: exactly 10 columns
        ws3 = wb["Business Opportunities"]
        header3 = [cell.value for cell in ws3[1]]
        self.assertEqual(len(header3), 10)
        self.assertEqual(header3, SHEET_03_COLUMNS)
        self.assertEqual(ws3.freeze_panes, "A2")

        # Check opportunity row populated
        self.assertGreaterEqual(ws3.max_row, 2)
        row2_cat = ws3.cell(row=2, column=2).value
        self.assertEqual(row2_cat, "Booking Automation")

    def test_format_a_source_compatible(self):
        excel_stream = generate_source_compatible_excel(self.sample_leads)
        self.assertIsNotNone(excel_stream)

        wb = openpyxl.load_workbook(excel_stream)
        ws = wb.active
        headers = [cell.value for cell in ws[1]]

        # Original custom columns must be preserved
        self.assertIn("Custom Column 1", headers)
        self.assertIn("Custom Column 2", headers)

        # Total rows must preserve duplicates (header + 2 rows = 3 rows)
        self.assertEqual(ws.max_row, 3)

        # Enrichment columns appended
        self.assertIn("Research Priority", headers)
        self.assertIn("Research Score", headers)

    def test_router_selects_format(self):
        stream_a = generate_styled_excel(self.sample_leads, format_type="source_compatible")
        wb_a = openpyxl.load_workbook(stream_a)
        self.assertEqual(len(wb_a.sheetnames), 1)

        stream_b = generate_styled_excel(self.sample_leads, format_type="standard_3_sheet")
        wb_b = openpyxl.load_workbook(stream_b)
        self.assertEqual(len(wb_b.sheetnames), 3)

if __name__ == '__main__':
    unittest.main()
