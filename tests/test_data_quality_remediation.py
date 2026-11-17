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
            "Main Opportunity": "Missing Online Booking Workflow",
            "Notes": "High opportunity score with key gaps in Booking.",
            "intelligence": {
                "seo": {"status": "Online", "seo_score": 75},
                "opportunities": {
                    "priority": "High",
                    "lead_score": 82,
                    "main_gap": "Missing Online Booking Workflow",
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
