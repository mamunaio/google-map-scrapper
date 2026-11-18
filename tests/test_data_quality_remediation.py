"""
LeadHunter Phase 08.2 Data Quality Remediation Test Suite
Validates all 14 required data quality, error handling, email filtering,
priority synchronization, and export integrity test cases.
"""

import io
import json
import pytest
from unittest.mock import patch, MagicMock
import openpyxl

from services.website_crawler import (
    crawl_and_audit_website,
    is_challenge_or_blocked,
    find_decision_maker_from_html
)
from services.email_service import (
    clean_and_validate_emails,
    extract_emails_and_socials
)
from services.export_service import (
    normalize_priority,
    normalize_email_status,
    clean_contact_person,
    generate_standard_intelligence_workbook,
    generate_lead_tracker_csv,
    LEAD_TRACKER_COLUMNS,
    WEBSITE_AUDIT_COLUMNS,
    BUSINESS_OPPORTUNITIES_COLUMNS
)
from services.lead_scoring import calculate_lead_score
from services.performance_audit import audit_website_performance


# -----------------------------------------------------------------------------
# 1. HTTP 403 Response Handling
# -----------------------------------------------------------------------------
def test_case_01_http_403_response_handling():
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.text = "<html><head><title>403 Forbidden</title></head><body>Access Denied</body></html>"
    mock_resp.url = "https://example-blocked.com"
    mock_resp.ssl_verified = True

    with patch("services.website_crawler.validate_and_sanitize_url", side_effect=lambda u: u), \
         patch("services.website_crawler.safe_http_get", return_value=mock_resp):
        res = crawl_and_audit_website("https://example-blocked.com")

    assert res["Website Status"] == "Blocked / Inconclusive"
    assert res["Priority"] == "Manual Review"
    assert res["Lead Score"] == 50

    intel = res["intelligence"]
    assert intel["seo"]["status"] == "Blocked / Inconclusive"
    assert intel["seo"]["seo_score"] is None
    assert intel["technical"]["mobile_usability"]["status"] == "Not Audited"
    assert intel["opportunities"]["opportunities_count"] == 0
    assert len(intel["opportunities"]["detected_opportunities"]) == 0


# -----------------------------------------------------------------------------
# 2. Cloudflare Challenge Detection
# -----------------------------------------------------------------------------
def test_case_02_cloudflare_challenge_detection():
    cf_html = """
    <!DOCTYPE html>
    <html>
    <head><title>Just a moment...</title></head>
    <body>
        <div id="cf-chl-widget">Please stand by, while we verify your browser...</div>
        <p>Ray ID: 7abc123456</p>
    </body>
    </html>
    """
    is_blocked, reason = is_challenge_or_blocked(status_code=403, html_text=cf_html)
    assert is_blocked is True
    assert "Cloudflare" in reason

    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.text = cf_html
    mock_resp.url = "https://cloudflare-site.com"
    mock_resp.ssl_verified = True

    with patch("services.website_crawler.validate_and_sanitize_url", side_effect=lambda u: u), \
         patch("services.website_crawler.safe_http_get", return_value=mock_resp):
        res = crawl_and_audit_website("https://cloudflare-site.com")

    assert res["Website Status"] == "Blocked / Inconclusive"
    assert res["intelligence"]["seo"]["seo_score"] is None
    # Ensure no false positive SEO defect findings were generated
    findings = res["intelligence"]["seo"]["findings"]
    assert not any("Missing Meta Description" in f for f in findings)
    assert not any("Missing H1" in f for f in findings)


# -----------------------------------------------------------------------------
# 3. CAPTCHA Response Detection
# -----------------------------------------------------------------------------
def test_case_03_captcha_response_detection():
    captcha_html = """
    <html>
    <head><title>Verify Access</title></head>
    <body>
        <p>Please verify you are human to proceed.</p>
        <div class="cf-turnstile" data-sitekey="xyz"></div>
    </body>
    </html>
    """
    is_blocked, reason = is_challenge_or_blocked(status_code=200, html_text=captcha_html)
    assert is_blocked is True
    assert "challenge" in reason.lower() or "captcha" in reason.lower()


# -----------------------------------------------------------------------------
# 4. Website Timeout Handling
# -----------------------------------------------------------------------------
def test_case_04_website_timeout_handling():
    with patch("services.website_crawler.validate_and_sanitize_url", side_effect=lambda u: u), \
         patch("services.website_crawler.safe_http_get", side_effect=Exception("HTTPSConnectionPool: Read timed out.")):
        res = crawl_and_audit_website("https://timeout-site.com")

    assert res["Website Status"] == "Timeout / Error"
    assert res["Priority"] == "Manual Review"
    assert res["intelligence"]["seo"]["seo_score"] is None
    assert res["intelligence"]["opportunities"]["opportunities_count"] == 0
    assert len(res["intelligence"]["opportunities"]["detected_opportunities"]) == 0


# -----------------------------------------------------------------------------
# 5. Invalid or Blocked Website Response
# -----------------------------------------------------------------------------
def test_case_05_invalid_or_blocked_website_response():
    mock_resp = MagicMock()
    mock_resp.status_code = 503
    mock_resp.text = "<html><title>Service Unavailable</title><body>Under maintenance</body></html>"
    mock_resp.url = "https://unavailable.com"
    mock_resp.ssl_verified = True

    with patch("services.website_crawler.validate_and_sanitize_url", side_effect=lambda u: u), \
         patch("services.website_crawler.safe_http_get", return_value=mock_resp):
        res = crawl_and_audit_website("https://unavailable.com")

    assert res["Priority"] == "Manual Review"
    assert res["intelligence"]["opportunities"]["opportunities_count"] == 0
    assert res["Main Opportunity"] != ""


# -----------------------------------------------------------------------------
# 6. MX-Only Email Verification Status Preserved
# -----------------------------------------------------------------------------
def test_case_06_mx_only_email_verification_status_preserved():
    assert normalize_email_status("MX Only", "test@company.com") == "MX Only"
    assert normalize_email_status("MX Valid", "test@company.com") == "MX Only"
    assert normalize_email_status("Catch-All", "test@company.com") == "MX Only"
    assert normalize_email_status("SMTP Verified", "test@company.com") == "Verified"
    assert normalize_email_status("Verified", "test@company.com") == "Verified"
    assert normalize_email_status("Invalid Syntax", "test@company.com") == "Invalid"
    assert normalize_email_status("", "test@company.com") == "Unverified"
    assert normalize_email_status("Verified", "") == "Not Found"


# -----------------------------------------------------------------------------
# 7. Email Domain Mismatch Rejection
# -----------------------------------------------------------------------------
def test_case_07_email_domain_mismatch_rejection():
    # When base_domain is texasairzone.com:
    # 1. Unrelated private domains should be rejected
    # 2. Matching domain should be kept
    # 3. Legitimate public provider (e.g. gmail.com) should be kept
    raw_emails = [
        "jane@residence.com",          # Unrelated private domain -> reject
        "owner@texasairzone.com",      # Matching domain -> keep
        "texasairzone@gmail.com",       # Legitimate public provider -> keep
        "contact@unrelateddomain.org"  # Unrelated private domain -> reject
    ]
    cleaned = clean_and_validate_emails(raw_emails, base_domain="texasairzone.com")
    assert "owner@texasairzone.com" in cleaned
    assert "texasairzone@gmail.com" in cleaned
    assert "jane@residence.com" not in cleaned
    assert "contact@unrelateddomain.org" not in cleaned


# -----------------------------------------------------------------------------
# 8. Placeholder Email Rejection
# -----------------------------------------------------------------------------
def test_case_08_placeholder_email_rejection():
    placeholders = [
        "filler@godaddy.com",
        "user@domain.com",
        "test@example.com",
        "sample@website.com",
        "yourname@company.com",
        "demo@template.net",
        "placeholder@test.org",
        "your_email_here@alphahvac.site"
    ]
    cleaned = clean_and_validate_emails(placeholders, base_domain="domain.com")
    assert len(cleaned) == 0


# -----------------------------------------------------------------------------
# 9. Unsupported Decision-Maker Identification
# -----------------------------------------------------------------------------
def test_case_09_unsupported_decision_maker_identification():
    # Plain page without Schema.org person or owner markers
    html = """
    <html>
    <body>
        <h1>Welcome to Serveway Heating & Air</h1>
        <p>Contact us at dispatch@servewayhvac.com or call 214-555-0199.</p>
    </body>
    </html>
    """
    dm_name, dm_role = find_decision_maker_from_html(html, business_name="Serveway Heating & Air")
    # Must NOT infer "Dispatch" as decision maker!
    assert dm_name is None

    # clean_contact_person should also reject placeholder/department names
    assert clean_contact_person("Dispatch") == ""
    assert clean_contact_person("Estimates") == ""
    assert clean_contact_person("Filler") == ""
    assert clean_contact_person("Serveway Heating & Air", "Serveway Heating & Air") == ""
    assert clean_contact_person("John Doe (Owner)", "Serveway") == "John Doe"


# -----------------------------------------------------------------------------
# 10. Priority Synchronization
# -----------------------------------------------------------------------------
def test_case_10_priority_synchronization():
    # Normalization mappings
    assert normalize_priority("High Priority") == "High"
    assert normalize_priority("High") == "High"
    assert normalize_priority("Medium Priority") == "Medium"
    assert normalize_priority("Medium") == "Medium"
    assert normalize_priority("Low Priority") == "Low"
    assert normalize_priority("Low") == "Low"
    assert normalize_priority("Manual Review") == "Manual Review"
    assert normalize_priority("") == "Manual Review"
    assert normalize_priority(None) == "Manual Review"
    assert normalize_priority("Unrecognized String") == "Manual Review"

    # Excel export preservation
    lead = {
        "Business Name": "Texas AirZone",
        "Website": "https://texasairzone.com",
        "Priority": "Medium",
        "Lead Score": 65,
        "Notes": "Moderate score; several digital infrastructure gaps identified.",
        "intelligence": {
            "opportunities": {
                "priority": "Medium",
                "lead_score": 65,
                "scoring_details": {"priority_reason": "Moderate score; several digital infrastructure gaps identified."}
            }
        }
    }
    wb_bytes = generate_standard_intelligence_workbook([lead])
    wb = openpyxl.load_workbook(io.BytesIO(wb_bytes.getvalue()))
    ws_leads = wb["Lead Tracker"]
    row_val = ws_leads.cell(row=2, column=13).value  # Priority column
    assert row_val == "Medium"


# -----------------------------------------------------------------------------
# 11. Lead Scoring Evidence Consistency
# -----------------------------------------------------------------------------
def test_case_11_lead_scoring_evidence_consistency():
    # 1. Quote form detected
    audit_quote = {
        "Website": "https://test-hvac.com",
        "intelligence": {
            "features": {
                "lead_capture": {
                    "status": "Detected",
                    "details": {"has_quote_form": True, "has_contact_form": True}
                }
            }
        }
    }
    score_q = calculate_lead_score(audit_quote)
    expl_q = score_q["dimension_explanations"]["lead_capture"]
    assert "quote/estimate" in expl_q.lower() or "estimate" in expl_q.lower()

    # 2. General contact form only
    audit_contact = {
        "Website": "https://test-hvac.com",
        "intelligence": {
            "features": {
                "lead_capture": {
                    "status": "Detected",
                    "details": {"has_quote_form": False, "has_contact_form": True}
                }
            }
        }
    }
    score_c = calculate_lead_score(audit_contact)
    expl_c = score_c["dimension_explanations"]["lead_capture"]
    assert "general contact form present" in expl_c.lower()

    # 3. Click-to-call link only
    audit_phone = {
        "Website": "https://test-hvac.com",
        "intelligence": {
            "features": {
                "lead_capture": {
                    "status": "Detected",
                    "details": {"has_quote_form": False, "has_contact_form": False, "has_phone_link": True}
                }
            }
        }
    }
    score_p = calculate_lead_score(audit_phone)
    expl_p = score_p["dimension_explanations"]["lead_capture"]
    assert "click-to-call" in expl_p.lower()


# -----------------------------------------------------------------------------
# 12. Missing PageSpeed API Key
# -----------------------------------------------------------------------------
def test_case_12_missing_pagespeed_api_key():
    perf_data = audit_website_performance("https://example.com", html_text="<html><body>Hello</body></html>", api_key="")
    assert perf_data["audit_status"] == "API Key Not Configured"
    assert perf_data["mobile_score"] is None
    assert perf_data["desktop_score"] is None
    assert perf_data["core_web_vitals"] == {}

    # Verify Sheet 02 handles this without fake "Passed"
    lead = {
        "Business Name": "Test HVAC",
        "Website": "https://test-hvac.com",
        "intelligence": {
            "seo": {"status": "Online", "seo_score": 85},
            "technical": {"ssl_certificate": {"status": "Valid"}, "mobile_usability": {"status": "Responsive"}},
            "performance": perf_data
        }
    }
    wb_bytes = generate_standard_intelligence_workbook([lead])
    wb = openpyxl.load_workbook(io.BytesIO(wb_bytes.getvalue()))
    ws_audit = wb["Website Audit"]
    perf_status = ws_audit.cell(row=2, column=12).value  # Performance Status column
    assert perf_status == "Unknown"


# -----------------------------------------------------------------------------
# 13. JSON and Excel Consistency
# -----------------------------------------------------------------------------
def test_case_13_json_and_excel_consistency():
    leads = [
        {
            "Business Name": "Dallas Heating Pro",
            "Category": "HVAC contractor",
            "City": "Dallas",
            "State": "TX",
            "Phone": "214-555-0100",
            "Website": "https://dallasheatingpro.com",
            "Google Maps URL": "https://maps.google.com/?cid=123",
            "Rating": 4.9,
            "Reviews": 120,
            "Contact Person": "Mark Smith",
            "Email": "info@dallasheatingpro.com",
            "Email Status": "Verified",
            "Priority": "High",
            "Lead Score": 82,
            "Main Opportunity": "No online booking",
            "Notes": "High opportunity score with key gaps in Booking.",
            "intelligence": {
                "seo": {"status": "Online", "seo_score": 75},
                "opportunities": {
                    "priority": "High",
                    "lead_score": 82,
                    "main_gap": "No online booking",
                    "detected_opportunities": [
                        {
                            "Opportunity Category": "Booking",
                            "Finding": "No online booking",
                            "Evidence": "Scanned pages lack scheduling widget",
                            "Confidence": "High",
                            "Research Status": "Detected",
                            "Recommended Service": "Online Booking Integration"
                        }
                    ]
                }
            }
        }
    ]

    # Generate JSON string
    json_str = json.dumps(leads)
    parsed_leads = json.loads(json_str)

    # Generate Excel
    wb_bytes = generate_standard_intelligence_workbook(parsed_leads)
    wb = openpyxl.load_workbook(io.BytesIO(wb_bytes.getvalue()))
    ws_leads = wb["Lead Tracker"]

    # Compare values
    assert len(parsed_leads) == ws_leads.max_row - 1
    assert ws_leads.cell(row=2, column=1).value == parsed_leads[0]["Business Name"]
    assert ws_leads.cell(row=2, column=8).value == parsed_leads[0]["Rating"]
    assert ws_leads.cell(row=2, column=9).value == parsed_leads[0]["Reviews"]
    assert ws_leads.cell(row=2, column=13).value == parsed_leads[0]["Priority"]
    assert ws_leads.cell(row=2, column=14).value == parsed_leads[0]["Lead Score"]


# -----------------------------------------------------------------------------
# 14. Exact Export Schema Validation
# -----------------------------------------------------------------------------
def test_case_14_exact_export_schema_validation():
    lead = {
        "Business Name": "Sample HVAC",
        "Website": "https://samplehvac.com",
        "Priority": "Medium",
        "Lead Score": 60,
        "intelligence": {
            "seo": {"status": "Online", "seo_score": 80},
            "technical": {"ssl_certificate": {"status": "Valid"}, "mobile_usability": {"status": "Responsive"}},
            "performance": {"audit_status": "API Key Not Configured", "mobile_score": None},
            "opportunities": {
                "priority": "Medium",
                "lead_score": 60,
                "detected_opportunities": [
                    {
                        "Opportunity Category": "SEO",
                        "Finding": "Missing H1",
                        "Evidence": "No H1 tags found",
                        "Confidence": "High",
                        "Research Status": "Detected",
                        "Recommended Service": "H1 Heading Optimization"
                    }
                ]
            }
        }
    }

    # Excel validation
    wb_bytes = generate_standard_intelligence_workbook([lead])
    wb = openpyxl.load_workbook(io.BytesIO(wb_bytes.getvalue()))

    sheet_names = wb.sheetnames
    assert sheet_names == ["Lead Tracker", "Website Audit", "Business Opportunities"]

    # Sheet 01: 16 columns
    s1_cols = [cell.value for cell in wb["Lead Tracker"][1]]
    assert len(s1_cols) == 16
    assert s1_cols == LEAD_TRACKER_COLUMNS

    # Sheet 02: 15 columns
    s2_cols = [cell.value for cell in wb["Website Audit"][1]]
    assert len(s2_cols) == 15
    assert s2_cols == WEBSITE_AUDIT_COLUMNS

    # Sheet 03: 7 columns
    s3_cols = [cell.value for cell in wb["Business Opportunities"][1]]
    assert len(s3_cols) == 7
    assert s3_cols == BUSINESS_OPPORTUNITIES_COLUMNS

    # CSV validation: 16 columns
    csv_str = generate_lead_tracker_csv([lead])
    first_line = csv_str.strip().split("\n")[0].split(",")
    assert len(first_line) == 16


# -----------------------------------------------------------------------------
# 15. Contact Availability Scoring (Phone + MX Only Email Verification Accuracy)
# -----------------------------------------------------------------------------
def test_case_15_contact_availability_scoring_phone_and_mx_only():
    from services.opportunity_analyzer import analyze_business_opportunities

    # Case A: Phone + MX Only email (e.g. Harlen Johnson)
    res_mx_phone = calculate_lead_score({
        "Website": "https://hjac.com",
        "Phone": "+1 972-241-7771",
        "Email": "sales@hjac.com",
        "Email Status": "MX Only",
        "intelligence": {
            "seo": {"seo_score": 90},
            "features": {"lead_capture": {"status": "Detected", "details": {"has_phone_link": True}}}
        }
    })
    expl = res_mx_phone["dimension_explanations"]["contact_availability"]
    assert "telephone number" in expl.lower()
    assert "mx-only" in expl.lower()
    assert "verified direct email" not in expl.lower()
    assert "telephone number not identified" not in expl.lower()

    # Case B: Phone + SMTP Verified email
    res_verified = calculate_lead_score({
        "Website": "https://hjac.com",
        "Phone": "+1 972-241-7771",
        "Email": "sales@hjac.com",
        "Email Status": "Verified",
        "intelligence": {"seo": {"seo_score": 90}}
    })
    expl_v = res_verified["dimension_explanations"]["contact_availability"]
    assert "verified direct email" in expl_v.lower()
    assert "telephone number" in expl_v.lower()
    assert res_verified["dimension_scores"]["contact_availability"] > res_mx_phone["dimension_scores"]["contact_availability"]

    # Case C: Phone only, no email (e.g. Texas AirZone)
    res_phone_only = calculate_lead_score({
        "Website": "https://texasairzone.com",
        "Phone": "+1 214-851-3886",
        "Email": "",
        "Email Status": "Not Found",
        "intelligence": {"seo": {"seo_score": 90}}
    })
    expl_p = res_phone_only["dimension_explanations"]["contact_availability"]
    assert "telephone number available" in expl_p.lower()
    assert "direct email not identified" in expl_p.lower()

    # Case D: End-to-end through analyze_business_opportunities passing phone & email_status
    opps = analyze_business_opportunities(
        features_result={"lead_capture": {"status": "Detected", "providers": ["Click-to-Call"], "details": {"has_phone_link": True}}},
        seo_result={"seo_score": 90, "findings": []},
        technical_result={"ssl_certificate": {"status": "Valid"}, "mobile_usability": {"has_viewport": True}},
        decision_maker="",
        email="sales@hjac.com",
        business_name="Harlen Johnson HVAC",
        target_url="https://hjac.com",
        phone="+1 972-241-7771",
        email_status="MX Only"
    )
    opps_expl = opps["scoring_details"]["dimension_explanations"]["contact_availability"]
    assert "telephone number" in opps_expl.lower()
    assert "mx-only" in opps_expl.lower()
    assert "verified direct email" not in opps_expl.lower()


# -----------------------------------------------------------------------------
# 16. Feature Classification (Click-to-Call vs Form)
# -----------------------------------------------------------------------------
def test_case_16_feature_classification_click_to_call_not_form():
    from services.business_feature_detector import detect_business_features

    # Page with tel: link only and NO forms (Texas AirZone pattern)
    html_tel_only = """
    <html>
    <body>
        <h1>Texas AirZone</h1>
        <a href="tel:2148513886">(214) 851-3886</a>
    </body>
    </html>
    """
    feats = detect_business_features(html_tel_only)
    lc = feats["lead_capture"]
    assert lc["status"] == "Detected"
    assert lc["details"]["has_contact_form"] is False
    assert lc["details"]["has_quote_form"] is False
    assert lc["details"]["has_phone_link"] is True
    assert lc["providers"] == ["Click-to-Call"]
    assert not any("form" in p.lower() for p in lc["providers"])

    # Page with contact form + tel link
    html_contact = """
    <html><body>
        <a href="tel:9724230012">Call</a>
        <form action="/contact"><input name="name"/><input name="email"/></form>
    </body></html>
    """
    lc_contact = detect_business_features(html_contact)["lead_capture"]
    assert "On-Page Contact Form" in lc_contact["providers"]
    assert "Click-to-Call" in lc_contact["providers"]

    # Page with quote form + tel link
    html_quote = """
    <html><body>
        <a href="tel:9722147002">Call</a>
        <form action="/free-quote"><input name="name"/><input name="phone"/><button>Request Quote</button></form>
    </body></html>
    """
    lc_quote = detect_business_features(html_quote)["lead_capture"]
    assert "Quote / Estimate Form" in lc_quote["providers"]
    assert "Click-to-Call" in lc_quote["providers"]


# -----------------------------------------------------------------------------
# 17. Main Opportunity Consistency Across Lead Tracker and Business Opportunities
# -----------------------------------------------------------------------------
def test_case_17_main_opportunity_matches_business_opportunities_sheet():
    from services.opportunity_analyzer import analyze_business_opportunities

    # Click-to-call only business (no interactive inquiry form, no technical issues)
    opps = analyze_business_opportunities(
        features_result={
            "lead_capture": {
                "status": "Detected",
                "providers": ["Click-to-Call"],
                "details": {"has_contact_form": False, "has_quote_form": False, "has_phone_link": True}
            },
            "booking": {"status": "Detected"},
            "chatbot": {"status": "Not Detected"},
            "voice_agent": {"status": "Not Detected"},
            "crm": {"status": "Not Detected"},
            "review_management": {"status": "Not Detected"}
        },
        seo_result={"seo_score": 92, "findings": []},
        technical_result={"ssl_certificate": {"status": "Valid"}, "mobile_usability": {"has_viewport": True}},
        decision_maker="",
        email="",
        business_name="Texas AirZone LLC",
        target_url="https://www.texasairzone.com/",
        phone="+1 214-851-3886",
        email_status="Not Found"
    )

    findings = [o["Finding"] for o in opps["detected_opportunities"]]
    # Must contain an evidence-backed Lead Capture opportunity
    assert "No Public Web Inquiry or Quote Form Detected" in findings
    # Main Opportunity must be an exact Finding in detected_opportunities
    assert opps["main_gap"] in findings
    assert opps["scoring_details"]["main_identified_gap"] == opps["main_gap"]

    # Verify in 3-sheet Excel workbook that Sheet 01 Main Opportunity exists in Sheet 03 Findings
    lead = {
        "Business Name": "Texas AirZone LLC",
        "Website": "https://www.texasairzone.com/",
        "Phone": "+1 214-851-3886",
        "Priority": opps["priority"],
        "Lead Score": opps["lead_score"],
        "Main Opportunity": opps["main_gap"],
        "Notes": opps["priority_reason"],
        "intelligence": {
            "seo": {"status": "Online", "seo_score": 92},
            "technical": {"ssl_certificate": {"status": "Valid"}, "mobile_usability": {"status": "Responsive"}},
            "performance": {"audit_status": "API Key Not Configured", "mobile_score": None},
            "opportunities": opps
        }
    }
    wb_bytes = generate_standard_intelligence_workbook([lead])
    wb = openpyxl.load_workbook(io.BytesIO(wb_bytes.getvalue()))
    ws_leads = wb["Lead Tracker"]
    ws_opps = wb["Business Opportunities"]

    sheet1_main_opp = ws_leads.cell(row=2, column=15).value  # Main Opportunity column
    sheet3_findings = [
        ws_opps.cell(row=r, column=3).value
        for r in range(2, ws_opps.max_row + 1)
        if ws_opps.cell(row=r, column=1).value == "Texas AirZone LLC"
    ]
    assert sheet1_main_opp in sheet3_findings


# -----------------------------------------------------------------------------
# 18. Blank Top-Level Priority/Score/Main Opportunity Fallback (Cozy - D Pattern)
# -----------------------------------------------------------------------------
def test_case_18_blank_fields_fallback_and_mx_only_lead_cozy_pattern():
    # Simulates an audited lead (like Cozy - D Heating & A/C) with MX-only email and phone,
    # where top-level Priority, Lead Score, and Main Opportunity were blank/missing before export.
    lead_missing_top_fields = {
        "Business Name": "Cozy - D Heating & A/C LLC",
        "Category": "HVAC contractor",
        "City": "Dallas",
        "State": "TX",
        "Phone": "+1 972-291-8002",
        "Website": "https://cozydair.com/",
        "Email": "info@cozydair.com",
        "Email Status": "MX Only",
        "Priority": "",
        "Lead Score": "",
        "Main Opportunity": "",
        "Notes": "",
        "intelligence": {
            "seo": {
                "status": "Online",
                "seo_score": 60,
                "metrics": {"title": "Cozy-D HVAC", "meta_description": "HVAC Dallas", "h1_tags": ["A", "B"]},
                "findings": [
                    {"name": "Multiple H1 Headings", "severity": "Medium"},
                    {"name": "Missing Canonical Tag", "severity": "Medium"}
                ]
            },
            "technical": {
                "ssl_certificate": {"status": "Valid"},
                "mobile_usability": {"status": "Needs Improvement (Responsive warnings detected)", "has_viewport": True, "overflow_risk": True},
                "findings": [{"name": "Potential Mobile Horizontal Overflow", "severity": "Medium"}]
            },
            "features": {
                "lead_capture": {"status": "Detected", "providers": ["Click-to-Call"], "details": {"has_phone_link": True, "has_contact_form": False, "has_quote_form": False}},
                "booking": {"status": "Detected"},
                "chatbot": {"status": "Not Detected"},
                "voice_agent": {"status": "Not Detected"},
                "crm": {"status": "Detected"},
                "review_management": {"status": "Not Detected"}
            },
            "performance": {"audit_status": "API Key Not Configured", "mobile_score": None},
            "opportunities": {
                "detected_opportunities": [
                    {
                        "Opportunity Category": "Lead Capture",
                        "Finding": "No Public Web Inquiry or Quote Form Detected",
                        "Evidence": "Only Click-to-Call detected on scanned pages.",
                        "Confidence": "Medium",
                        "Research Status": "Needs Review",
                        "Recommended Service": "Interactive Web Inquiry Form"
                    },
                    {
                        "Opportunity Category": "Technical SEO",
                        "Finding": "On-Page Metadata Gaps",
                        "Evidence": "Multiple H1 Headings and Missing Canonical Tag.",
                        "Confidence": "High",
                        "Research Status": "Detected",
                        "Recommended Service": "Technical SEO Optimization"
                    }
                ]
            }
        }
    }

    # Excel export must resolve valid Priority, Lead Score, Main Opportunity (from Sheet 03), and Sheet 02 statuses
    wb_bytes = generate_standard_intelligence_workbook([lead_missing_top_fields])
    wb = openpyxl.load_workbook(io.BytesIO(wb_bytes.getvalue()))
    ws1 = wb["Lead Tracker"]
    ws2 = wb["Website Audit"]
    ws3 = wb["Business Opportunities"]

    priority = ws1.cell(row=2, column=13).value
    score = ws1.cell(row=2, column=14).value
    main_opp = ws1.cell(row=2, column=15).value
    notes = ws1.cell(row=2, column=16).value

    assert priority in ["High", "Medium", "Low"]
    assert isinstance(score, int) and score > 0
    assert main_opp == "On-Page Metadata Gaps"  # Confirmed Detected finding from Sheet 03
    assert notes != ""

    # Confirm Sheet 01 Main Opportunity exists in Sheet 03
    s3_findings = [ws3.cell(row=r, column=3).value for r in range(2, ws3.max_row + 1)]
    assert main_opp in s3_findings

    # Confirm Sheet 02 canonical, H1, and mobile statuses align with findings (no contradiction)
    assert ws2.cell(row=2, column=6).value == "Confirmed issue"  # Canonical Status
    assert ws2.cell(row=2, column=8).value == "Confirmed issue"  # H1 Status
    assert ws2.cell(row=2, column=10).value == "Confirmed issue"  # Mobile / Viewport Status

    # CSV export must resolve identical non-blank Priority, Score, and Main Opportunity
    csv_str = generate_lead_tracker_csv([lead_missing_top_fields])
    assert f",{priority},{score},{main_opp}," in csv_str


# -----------------------------------------------------------------------------
# 19. Reachable Site with Zero Opportunities Fallback Handling
# -----------------------------------------------------------------------------
def test_case_19_reachable_site_zero_opportunities_fallback():
    from services.opportunity_analyzer import analyze_business_opportunities

    opps = analyze_business_opportunities(
        features_result={
            "lead_capture": {"status": "Detected", "providers": ["Quote / Estimate Form", "Click-to-Call"], "details": {"has_quote_form": True, "has_contact_form": True, "has_phone_link": True}},
            "booking": {"status": "Detected"},
            "chatbot": {"status": "Detected"},
            "voice_agent": {"status": "Detected"},
            "crm": {"status": "Detected"},
            "review_management": {"status": "Detected"}
        },
        seo_result={"status": "Online", "seo_score": 98, "findings": []},
        technical_result={"ssl_certificate": {"status": "Valid"}, "mobile_usability": {"status": "Mobile-Friendly", "has_viewport": True, "overflow_risk": False}},
        decision_maker="Alice Owner",
        email="alice@modernhvac.com",
        business_name="Modern HVAC Pro",
        target_url="https://modernhvac.com",
        phone="+1 214-555-0199",
        email_status="Verified"
    )

    assert opps["opportunities_count"] == 0
    assert opps["main_gap"] == "No opportunity detected"

    lead = {
        "Business Name": "Modern HVAC Pro",
        "Website": "https://modernhvac.com",
        "Phone": "+1 214-555-0199",
        "Email": "alice@modernhvac.com",
        "Email Status": "Verified",
        "Priority": opps["priority"],
        "Lead Score": opps["lead_score"],
        "Main Opportunity": opps["main_gap"],
        "Notes": opps["priority_reason"],
        "intelligence": {
            "seo": {"status": "Online", "seo_score": 98},
            "technical": {"ssl_certificate": {"status": "Valid"}, "mobile_usability": {"status": "Mobile-Friendly", "has_viewport": True}},
            "performance": {"audit_status": "API Key Not Configured", "mobile_score": None},
            "opportunities": opps
        }
    }

    wb_bytes = generate_standard_intelligence_workbook([lead])
    wb = openpyxl.load_workbook(io.BytesIO(wb_bytes.getvalue()))
    ws1 = wb["Lead Tracker"]
    ws3 = wb["Business Opportunities"]

    assert ws1.cell(row=2, column=13).value == opps["priority"]
    assert ws1.cell(row=2, column=13).value in ["High", "Medium", "Low"]
    assert ws1.cell(row=2, column=14).value == opps["lead_score"]
    assert ws1.cell(row=2, column=15).value == "No opportunity detected"
    # Zero phantom rows in Sheet 03
    assert ws3.max_row == 1


# -----------------------------------------------------------------------------
# 20. Stale Main Opportunity on Reachable Site Re-Aligned to Sheet 03 Finding
# -----------------------------------------------------------------------------
def test_case_20_reachable_site_stale_main_opportunity_aligned_to_sheet_03():
    lead = {
        "Business Name": "Aligned HVAC LLC",
        "Website": "https://alignedhvac.com",
        "Priority": "Medium",
        "Lead Score": 55,
        "Main Opportunity": "Outdated or Unmatched Gap String",
        "intelligence": {
            "seo": {"status": "Online", "seo_score": 88},
            "technical": {"ssl_certificate": {"status": "Valid"}, "mobile_usability": {"status": "Responsive", "has_viewport": True}},
            "performance": {"audit_status": "API Key Not Configured", "mobile_score": None},
            "opportunities": {
                "priority": "Medium",
                "lead_score": 55,
                "main_gap": "Outdated or Unmatched Gap String",
                "detected_opportunities": [
                    {
                        "Opportunity Category": "Lead Capture",
                        "Finding": "No Public Web Inquiry or Quote Form Detected",
                        "Evidence": "Only Click-to-Call detected.",
                        "Confidence": "Medium",
                        "Research Status": "Needs Review",
                        "Recommended Service": "Interactive Web Inquiry Form"
                    }
                ]
            }
        }
    }

    wb_bytes = generate_standard_intelligence_workbook([lead])
    wb = openpyxl.load_workbook(io.BytesIO(wb_bytes.getvalue()))
    ws1 = wb["Lead Tracker"]
    ws3 = wb["Business Opportunities"]

    s1_main_opp = ws1.cell(row=2, column=15).value
    s3_findings = [ws3.cell(row=r, column=3).value for r in range(2, ws3.max_row + 1)]
    assert s1_main_opp == "No Public Web Inquiry or Quote Form Detected"
    assert s1_main_opp in s3_findings


# -----------------------------------------------------------------------------
# 21. Google Maps Feed Dynamic Pagination Reaches 30 Unique Businesses
# -----------------------------------------------------------------------------
def test_case_21_maps_feed_pagination_reaches_30_unique_businesses():
    from services.maps_scraper import scrape_maps_search_feed

    # Simulate a Google Maps feed that loads 5 new cards per feed container scroll (up to 35 total)
    state = {"loaded": 5, "scroll_calls": 0}

    def make_mock_card(idx: int):
        card = MagicMock()
        name_loc = MagicMock()
        name_loc.count.return_value = 1
        name_loc.inner_text.return_value = f"Dallas HVAC Business #{idx}"

        link_loc = MagicMock()
        link_loc.count.return_value = 1
        link_loc.first.get_attribute.return_value = f"https://www.google.com/maps/place/Dallas+HVAC+{idx}/data=!1s0x{idx:04x}"

        empty_loc = MagicMock()
        empty_loc.count.return_value = 0

        def card_locator(sel):
            if "div.qBF1Pd" in sel:
                return name_loc
            if "a.hfpxzc" in sel:
                return link_loc
            return empty_loc

        card.locator.side_effect = card_locator
        card.inner_text.return_value = f"Dallas HVAC Business #{idx}\n4.8(50) · HVAC contractor\n100 Main St, Dallas, TX 75201\n(214) 555-{idx:04d}"
        # Prevent click path since City & Phone are already present in card text
        del card.click
        return card

    all_cards = [make_mock_card(i) for i in range(1, 36)]

    feed_first = MagicMock()
    feed_first.inner_text.return_value = "Results list"

    def feed_evaluate(js_expr):
        assert "scrollTop" in js_expr
        state["scroll_calls"] += 1
        state["loaded"] = min(35, state["loaded"] + 5)

    feed_first.evaluate.side_effect = feed_evaluate

    feed_loc = MagicMock()
    feed_loc.count.return_value = 1
    feed_loc.first = feed_first

    cards_loc = MagicMock()
    cards_loc.all.side_effect = lambda: all_cards[:state["loaded"]]

    page = MagicMock()

    def page_locator(sel):
        if sel == 'div[role="feed"]':
            return feed_loc
        if sel == 'div.Nv2PK':
            return cards_loc
        m = MagicMock()
        m.count.return_value = 0
        return m

    page.locator.side_effect = page_locator

    with patch("services.maps_scraper.time.sleep", return_value=None):
        leads = scrape_maps_search_feed(page, max_results=30)

    # Must scroll the actual feed container beyond 4 scrolls and reach all 30 unique businesses
    assert len(leads) == 30
    assert state["scroll_calls"] >= 5
    assert len({l["Business Name"] for l in leads}) == 30


# -----------------------------------------------------------------------------
# 22. Email Extraction Excludes Form Placeholders & Keeps Legitimate Emails
# -----------------------------------------------------------------------------
def test_case_22_email_extraction_excludes_form_placeholders_and_preserves_legitimate():
    # Exact pattern observed on askmoss.com + textarea/value examples
    html_with_form_placeholders = """
    <html>
    <body>
        <form id="contact">
            <input name="input_2" id="input_1_2" type="email" value="" class="large"
                   placeholder="jsmith@gmail.com" aria-required="true" autocomplete="email" />
            <input type="email" value="bob.example@gmail.com" data-placeholder="jane@gmail.com" />
            <textarea placeholder="Write to sample.owner@gmail.com"></textarea>
        </form>
        <p>Call us today at (972) 733-6802.</p>
    </body>
    </html>
    """
    best, _, _, _, all_valid = extract_emails_and_socials(html_with_form_placeholders, base_url="https://www.askmoss.com/")
    assert best == ""
    assert all_valid == []

    # Generic dummy examples on public webmail providers are rejected even outside <input>
    cleaned_public_examples = clean_and_validate_emails(
        ["jsmith@gmail.com", "johndoe@gmail.com", "jane.doe@yahoo.com", "acowboyair@yahoo.com"],
        base_url="https://cowboyair.com/"
    )
    assert "jsmith@gmail.com" not in cleaned_public_examples
    assert "johndoe@gmail.com" not in cleaned_public_examples
    assert "jane.doe@yahoo.com" not in cleaned_public_examples
    assert "acowboyair@yahoo.com" in cleaned_public_examples

    # Legitimate company-domain emails (including real owner jsmith@smithhvac.com) must NOT be rejected
    html_legit = """
    <html>
    <body>
        <form><input type="email" placeholder="jsmith@gmail.com" /></form>
        <footer>
            <a href="mailto:sales@hjac.com">Email Sales</a>
            <p>Owner contact: jsmith@hjac.com</p>
        </footer>
    </body>
    </html>
    """
    best_legit, _, _, _, all_legit = extract_emails_and_socials(html_legit, base_url="https://hjac.com/")
    assert "sales@hjac.com" in all_legit
    assert "jsmith@hjac.com" in all_legit
    assert "jsmith@gmail.com" not in all_legit
    assert best_legit in ("jsmith@hjac.com", "sales@hjac.com")


# -----------------------------------------------------------------------------
# 23. SSL Inspection Uses certifi CA Bundle & Preserves Original SNI Hostname
# -----------------------------------------------------------------------------
def test_case_23_ssl_inspection_uses_certifi_and_preserves_original_sni_hostname():
    import ssl
    import certifi
    from services.technical_audit import inspect_ssl_certificate

    fake_cert = {
        "notAfter": "Jan 13 15:24:55 2028 GMT",
        "issuer": ((("organizationName", "Sectigo Limited"),),)
    }

    mock_ssock = MagicMock()
    mock_ssock.__enter__.return_value = mock_ssock
    mock_ssock.getpeercert.return_value = fake_cert

    mock_ctx = MagicMock()
    mock_ctx.verify_mode = ssl.CERT_REQUIRED
    mock_ctx.check_hostname = True
    mock_ctx.wrap_socket.return_value = mock_ssock

    mock_sock = MagicMock()
    mock_sock.__enter__.return_value = mock_sock

    with patch("services.technical_audit.ssl.create_default_context", return_value=mock_ctx) as mock_create_ctx, \
         patch("services.technical_audit.create_pinned_public_socket", return_value=(mock_sock, "93.184.216.34")) as mock_pinned_connect:
        res = inspect_ssl_certificate("www.airtron.com")

    # Must pass certifi CA bundle (never disable verification)
    mock_create_ctx.assert_called_once_with(cafile=certifi.where())
    # Must connect via DNS-pinned public socket while preserving original hostname ("www.airtron.com") for SNI
    mock_pinned_connect.assert_called_once_with("www.airtron.com", 443, timeout=4, allow_ip_literal=False)
    mock_ctx.wrap_socket.assert_called_once_with(mock_sock, server_hostname="www.airtron.com")
    assert res["status"] == "Valid"
    assert res["days_remaining"] > 0


# -----------------------------------------------------------------------------
# 24. Mobile Overflow Detector Excludes Responsive CSS, max-width & Image Widths
# -----------------------------------------------------------------------------
def test_case_24_mobile_overflow_ignores_responsive_css_breakpoints_and_image_widths():
    from services.technical_audit import audit_technical_and_mobile
    from services.opportunity_analyzer import analyze_business_opportunities

    # 1. Negative test: modern responsive page with @media (min-width: 1024px), max-width: 1200px,
    #    <img width="1600">, <svg width="2400">, og:image:width=1200, JSON-LD width: 1200
    responsive_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta property="og:image:width" content="1200">
        <script type="application/ld+json">{"@type": "ImageObject", "width": 1200}</script>
        <style>
            .container { max-width: 1170px; margin: 0 auto; }
            @media (min-width: 1024px) { .grid { display: grid; } }
            @media (min-width: 1200px) { .hero { max-width: 1400px; } }
        </style>
    </head>
    <body>
        <div class="container" style="width: 1200px; max-width: 100%;">
            <img src="hero.jpg" width="1600" height="900" alt="HVAC" />
            <svg width="2400" height="100"></svg>
        </div>
    </body>
    </html>
    """
    with patch("services.technical_audit.inspect_ssl_certificate", return_value={"status": "Valid", "days_remaining": 60}):
        tech = audit_technical_and_mobile(responsive_html, "https://example.com", "https://example.com", 200, True)

    mob = tech["mobile_usability"]
    assert mob["has_viewport"] is True
    assert mob["overflow_risk"] is False
    assert mob["overflow_warning"] is False
    assert "Optimized" in mob["status"]
    assert not any("Overflow" in f.get("name", "") for f in tech["findings"])

    opps = analyze_business_opportunities(
        features_result={}, seo_result={"seo_score": 95, "findings": []},
        technical_result=tech, decision_maker="", email="", business_name="Resp HVAC", target_url="https://example.com"
    )
    assert not any(o["Opportunity Category"] == "Website Development" for o in opps["detected_opportunities"])

    # 2. Inline wide container without max-width: 100% on a valid device-width page -> Needs Review / Low (NOT High/Detected)
    inline_wide_html = """
    <html><head><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
    <body><div style="width: 1400px;">Wide Container</div></body></html>
    """
    with patch("services.technical_audit.inspect_ssl_certificate", return_value={"status": "Valid", "days_remaining": 60}):
        tech_warn = audit_technical_and_mobile(inline_wide_html, "https://example.com", "https://example.com", 200, True)
    assert tech_warn["mobile_usability"]["overflow_risk"] is False
    assert tech_warn["mobile_usability"]["overflow_warning"] is True
    assert "Needs Review" in tech_warn["mobile_usability"]["status"]

    opps_warn = analyze_business_opportunities(
        features_result={}, seo_result={"seo_score": 95, "findings": []},
        technical_result=tech_warn, decision_maker="", email="", business_name="Warn HVAC", target_url="https://example.com"
    )
    webdev_opps = [o for o in opps_warn["detected_opportunities"] if o["Opportunity Category"] == "Website Development"]
    assert len(webdev_opps) == 1
    assert webdev_opps[0]["Research Status"] == "Needs Review"
    assert webdev_opps[0]["Confidence"] == "Low"

    # 3. Positive test: Explicit fixed-width non-responsive viewport -> Confirmed High-Confidence Detected
    fixed_vp_html = """
    <html><head><meta name="viewport" content="width=1200"></head><body><p>Desktop only</p></body></html>
    """
    with patch("services.technical_audit.inspect_ssl_certificate", return_value={"status": "Valid", "days_remaining": 60}):
        tech_fixed = audit_technical_and_mobile(fixed_vp_html, "https://example.com", "https://example.com", 200, True)
    assert tech_fixed["mobile_usability"]["fixed_viewport_width"] is True
    assert tech_fixed["mobile_usability"]["overflow_risk"] is True

    opps_fixed = analyze_business_opportunities(
        features_result={}, seo_result={"seo_score": 95, "findings": []},
        technical_result=tech_fixed, decision_maker="", email="", business_name="Fixed VP HVAC", target_url="https://example.com"
    )
    webdev_fixed = [o for o in opps_fixed["detected_opportunities"] if o["Opportunity Category"] == "Website Development"]
    assert len(webdev_fixed) == 1
    assert webdev_fixed[0]["Research Status"] == "Detected"
    assert webdev_fixed[0]["Confidence"] == "High"


# -----------------------------------------------------------------------------
# 25. Contact Person Extraction Fixes Truncation, Multi-Word Names & Non-Persons
# -----------------------------------------------------------------------------
def test_case_25_contact_person_fixes_truncation_preserves_multiword_and_rejects_non_persons():
    # 1. Fixed truncation cases observed in Phase 09
    html_cody = "<html><body><p>Phillip Cody, Owner of Cody &amp; Sons Plumbing, Heating &amp; Air</p></body></html>"
    name_cody, _ = find_decision_maker_from_html(html_cody, business_name="Cody & Sons Plumbing, Heating & Air")
    assert name_cody == "Phillip Cody"

    html_kiser = "<html><body><p>Richard Henderson | Founder</p></body></html>"
    name_kiser, _ = find_decision_maker_from_html(html_kiser, business_name="M. B. Kiser Heating & Air Conditioning Co. Inc.")
    assert name_kiser == "Richard Henderson"

    # 2. Multi-word & hyphenated/apostrophe human names preserved
    html_multi = "<html><body><p>Founder: Jose Luis Mondragon</p></body></html>"
    name_multi, _ = find_decision_maker_from_html(html_multi, business_name="Mondragon Mechanical LLC")
    assert name_multi == "Jose Luis Mondragon"

    html_hyph = "<html><body><p>Mary-Anne O'Connor, CEO</p></body></html>"
    name_hyph, _ = find_decision_maker_from_html(html_hyph, business_name="Apex Cooling")
    assert name_hyph == "Mary-Anne O'Connor"

    # 3. Negative tests: Non-person phrases and business names MUST be rejected (return None)
    html_texas_home = "<html><body><p>Every Texas Home Owner deserves reliable AC repair.</p></body></html>"
    name_tx, _ = find_decision_maker_from_html(html_texas_home, business_name="5 Star HVAC Contractors")
    assert name_tx is None

    html_biz_as_owner = "<html><body><p>Owner: Dallas Comfort Systems</p></body></html>"
    name_biz, _ = find_decision_maker_from_html(html_biz_as_owner, business_name="Dallas Comfort Systems")
    assert name_biz is None

    html_brand = "<html><body><p>Trusted Family Experts, President</p></body></html>"
    name_brand, _ = find_decision_maker_from_html(html_brand, business_name="Acme Air")
    assert name_brand is None


# -----------------------------------------------------------------------------
# 26. Safe UTF-8 Encoding Detection Prevents Mojibake When Charset Header Omitted
# -----------------------------------------------------------------------------
def test_case_26_utf8_mojibake_safe_encoding_detection():
    import requests
    from services.security import safe_http_get

    raw_utf8 = "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Dallas\u2013Fort Worth | Texas AirZone</title></head><body></body></html>".encode("utf-8")

    fake_resp = requests.Response()
    fake_resp.status_code = 200
    fake_resp.url = "https://www.texasairzone.com/"
    fake_resp.headers["Content-Type"] = "text/html"  # No charset -> requests defaults to ISO-8859-1
    fake_resp.encoding = "ISO-8859-1"
    fake_resp.iter_content = lambda chunk_size=16384: iter([raw_utf8])
    fake_resp.close = lambda: None

    with patch("services.security.validate_and_sanitize_url", side_effect=lambda u: u), \
         patch("services.security.requests.Session.get", return_value=fake_resp):
        resp = safe_http_get("https://www.texasairzone.com/")

    assert resp.encoding.lower() == "utf-8"
    assert "Dallas\u2013Fort Worth" in resp.text
    assert "â€" not in resp.text


# -----------------------------------------------------------------------------
# 27. ScheduleEngine Verified DOM/Script Markers Detection
# -----------------------------------------------------------------------------
def test_case_27_schedule_engine_verified_markers():
    from services.business_feature_detector import detect_business_features

    # Airtron live markers: router.scheduleengine.net (booking) + webchat.scheduleengine.net (chatbot)
    html_airtron = """
    <html><head>
        <script src="https://webchat.scheduleengine.net/webchat-v1.js"></script>
        <script src="https://router.scheduleengine.net/common/v2/se_inc.js"></script>
    </head><body></body></html>
    """
    feats_a = detect_business_features(html_airtron)
    assert feats_a["booking"]["status"] == "Detected"
    assert "ScheduleEngine" in feats_a["booking"]["providers"]
    assert feats_a["chatbot"]["status"] == "Detected"
    assert "ScheduleEngine Webchat" in feats_a["chatbot"]["providers"]

    # Moss live marker: ScheduleEngine.show() (booking only, should NOT falsely trigger chatbot)
    html_moss = """
    <html><body>
        <script>function openBook() { typeof ScheduleEngine !== 'undefined' && ScheduleEngine.show(); }</script>
    </body></html>
    """
    feats_m = detect_business_features(html_moss)
    assert feats_m["booking"]["status"] == "Detected"
    assert "ScheduleEngine" in feats_m["booking"]["providers"]
    assert feats_m["chatbot"]["status"] == "Not Detected"




