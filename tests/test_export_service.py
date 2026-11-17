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

    def test_multiple_verified_opportunities(self):
        lead = {
            "Business Name": "Multi Opps Co",
            "Website": "https://multiopps.com",
            "intelligence": {
                "opportunities": {
                    "detected_opportunities": [
                        {
                            "Opportunity Category": "Booking Automation",
                            "Related Finding": "No booking widget",
                            "Evidence Description": "Missing scheduling scripts",
                            "Evidence URL": "https://multiopps.com",
                            "Potential Business Impact": "Manual callback friction",
                            "Recommended Service": "Online Booking Calendar",
                            "Confidence Level": "High",
                            "Research Status": "Identified"
                        },
                        {
                            "Opportunity Category": "AI Automation",
                            "Related Finding": "No live chat",
                            "Evidence Description": "No chat widget in DOM",
                            "Evidence URL": "https://multiopps.com",
                            "Potential Business Impact": "Missed after-hours inquiries",
                            "Recommended Service": "24/7 AI Chatbot",
                            "Confidence Level": "High",
                            "Research Status": "Identified"
                        }
                    ]
                }
            }
        }
        stream = generate_standard_intelligence_workbook([lead])
        wb = openpyxl.load_workbook(stream)
        ws = wb["Business Opportunities"]
        # Header + 2 opportunity rows = 3 rows
        self.assertEqual(ws.max_row, 3)
        self.assertEqual(ws.cell(row=2, column=2).value, "Booking Automation")
        self.assertEqual(ws.cell(row=3, column=2).value, "AI Automation")

    def test_one_verified_opportunity(self):
        lead = {
            "Business Name": "Single Opp Co",
            "Website": "https://singleopp.com",
            "intelligence": {
                "opportunities": {
                    "detected_opportunities": [
                        {
                            "Opportunity Category": "Technical SEO",
                            "Related Finding": "Missing title and meta description",
                            "Evidence Description": "Title tag is blank",
                            "Evidence URL": "https://singleopp.com",
                            "Potential Business Impact": "Poor search engine visibility",
                            "Recommended Service": "On-Page Technical SEO Optimization",
                            "Confidence Level": "High",
                            "Research Status": "Verified"
                        }
                    ]
                }
            }
        }
        stream = generate_standard_intelligence_workbook([lead])
        wb = openpyxl.load_workbook(stream)
        ws = wb["Business Opportunities"]
        self.assertEqual(ws.max_row, 2)
        self.assertEqual(ws.cell(row=2, column=2).value, "Technical SEO")

    def test_no_opportunities_neutral_row(self):
        lead = {
            "Business Name": "Fully Modern Co",
            "Website": "https://fullymodern.com",
            "intelligence": {
                "opportunities": {
                    "detected_opportunities": []
                }
            }
        }
        stream = generate_standard_intelligence_workbook([lead])
        wb = openpyxl.load_workbook(stream)
        ws = wb["Business Opportunities"]
        self.assertEqual(ws.max_row, 2)
        # Category must be neutral and not fabricated
        self.assertEqual(ws.cell(row=2, column=2).value, "No Verified Opportunity Identified")
        self.assertEqual(ws.cell(row=2, column=3).value, "None Detected")
        # Impact, service, and confidence must be N/A
        self.assertEqual(ws.cell(row=2, column=6).value, "N/A")
        self.assertEqual(ws.cell(row=2, column=7).value, "N/A")
        self.assertEqual(ws.cell(row=2, column=8).value, "N/A")

    def test_unknown_opportunity_status_neutral_row(self):
        lead = {
            "Business Name": "Unknown Co",
            "Website": "https://unknownco.com",
            "intelligence": {
                "features": {
                    "lead_capture": {"status": "Unknown"},
                    "booking": {"status": "Unknown"}
                },
                "opportunities": {}
            }
        }
        stream = generate_standard_intelligence_workbook([lead])
        wb = openpyxl.load_workbook(stream)
        ws = wb["Business Opportunities"]
        self.assertEqual(ws.max_row, 2)
        self.assertEqual(ws.cell(row=2, column=2).value, "No Verified Opportunity Identified")
        self.assertEqual(ws.cell(row=2, column=7).value, "N/A")

    def test_representative_22_columns_source_csv_preservation(self):
        # 22 representative columns typical of original Google Maps scraping export
        raw_lead = {
            "place_id": "ChIJ123",
            "name": "Original Dallas HVAC",
            "category": "HVAC contractor",
            "sub_categories": "Heating, AC",
            "street": "123 Main St",
            "city": "Dallas",
            "state": "TX",
            "postal_code": "75201",
            "country": "US",
            "latitude": "32.7767",
            "longitude": "-96.7970",
            "phone": "+1-214-555-9999",
            "website": "https://dallashvac.com",
            "rating": "4.9",
            "reviews_count": "150",
            "reviews_link": "https://maps.google.com/reviews",
            "working_hours": "Mon-Fri 8am-5pm",
            "verified": "True",
            "owner_title": "Owner",
            "cid": "9876543210",
            "query": "HVAC Dallas",
            "timezone": "America/Chicago"
        }
        stream = generate_source_compatible_excel([raw_lead])
        wb = openpyxl.load_workbook(stream)
        ws = wb.active
        headers = [cell.value for cell in ws[1]]

        # Verify all 22 columns are present in exact order
        for col_name in raw_lead.keys():
            self.assertIn(col_name, headers)
        self.assertEqual(headers[:22], list(raw_lead.keys()))

if __name__ == '__main__':
    unittest.main()
