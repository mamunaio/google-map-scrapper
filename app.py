"""
LeadHunter Studio - Lead Intelligence & Business Opportunity Detection Platform
Flask Application & API Gateway
"""

import io
import time
import random
from flask import Flask, render_template, request, jsonify, send_file
from playwright.sync_api import sync_playwright

from services.security import SecurityError, validate_google_maps_url
from services.website_crawler import crawl_and_audit_website
from services.export_service import generate_styled_excel, generate_lead_tracker_csv
from services.maps_scraper import scrape_google_maps

app = Flask(__name__)

def get_random_delay():
    return random.uniform(1.2, 2.5)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scrape', methods=['POST'])
def scrape_api():
    """
    Main lead enrichment and intelligence endpoint.
    Maintains 100% backward compatibility with existing API contracts while providing
    deep Website Intelligence, SEO Audit, Feature Detection, and Opportunity Scoring.
    """
    data = request.json or {}
    url = data.get('url', '').strip()
    type_ = data.get('type', 'website')
    hint_dm = data.get('decision_maker', '')
    
    if not url:
        return jsonify({"success": False, "error": "URL is required"}), 400

    result = {
        "Business Name": data.get("business_name", ""),
        "Phone Number": "",
        "Website": "",
        "Decision Maker": "",
        "Email": "",
        "Email Verification": "Unverified",
        "Facebook": "",
        "Instagram": "",
        "LinkedIn": "",
        "About Page Link": "",
        "Source URL": url,
        "intelligence": None
    }

    try:
        # Option A: Google Maps Extraction (Search URLs and Place URLs)
        if type_ == 'maps':
            clean_url = validate_google_maps_url(url)
            max_res = min(int(data.get('max_results', 20)), 50)
            maps_res = scrape_google_maps(clean_url, max_results=max_res)

            if not maps_res.get("success"):
                return jsonify({
                    "success": False,
                    "error": maps_res.get("error", "No business details or listings could be extracted from this Google Maps URL."),
                    "leads": [],
                    "count": 0,
                    "data": None
                }), 422

            extracted_leads = maps_res.get("leads", [])
            enriched_leads = []

            for raw_lead in extracted_leads:
                lead = dict(raw_lead)
                if data.get("business_name") and not lead.get("Business Name"):
                    lead["Business Name"] = data.get("business_name")

                # If website was extracted, run Website Intelligence & Contact Enrichment
                if lead.get("Website"):
                    try:
                        audit_data = crawl_and_audit_website(
                            lead["Website"],
                            hint_decision_maker=hint_dm,
                            business_name=lead.get("Business Name", "")
                        )
                        lead["Website"] = audit_data.get("Website", lead["Website"])
                        lead["Email"] = audit_data.get("Email", "")
                        lead["Contact Person"] = audit_data.get("Contact Person") or audit_data.get("Decision Maker", "")
                        lead["Decision Maker"] = audit_data.get("Decision Maker", "")
                        lead["Email Status"] = audit_data.get("Email Status") or audit_data.get("Email Verification", "Not Found")
                        lead["Email Verification"] = audit_data.get("Email Verification", "Not Found")
                        lead["Facebook"] = audit_data.get("Facebook", "")
                        lead["Instagram"] = audit_data.get("Instagram", "")
                        lead["LinkedIn"] = audit_data.get("LinkedIn", "")
                        lead["About Page Link"] = audit_data.get("About Page Link", "")
                        lead["intelligence"] = audit_data.get("intelligence")

                        intel = audit_data.get("intelligence") or {}
                        opps = intel.get("opportunities") or {}
                        scoring = opps.get("scoring_details") or {}
                        lead["Priority"] = opps.get("priority") or "Manual Review"
                        lead["Lead Score"] = opps.get("lead_score") or 0
                        lead["Main Opportunity"] = opps.get("main_gap") or ""
                        lead["Notes"] = scoring.get("priority_reason") or ""
                    except Exception as e:
                        print(f"Website enrichment error for {lead.get('Website')}: {e}")

                enriched_leads.append(lead)

            return jsonify({
                "success": True,
                "is_search": maps_res.get("is_search", False),
                "leads": enriched_leads,
                "count": len(enriched_leads),
                "data": enriched_leads[0] if enriched_leads else None
            })

        elif type_ == 'website':
            # Option B: Direct Website Intelligence & Contact Enrichment
            result = {
                "Business Name": data.get("business_name", ""),
                "Category": "Unknown",
                "City": "Unknown",
                "State": "Unknown",
                "Phone": "",
                "Phone Number": "",
                "Website": url,
                "Google Maps URL": "",
                "Rating": None,
                "Reviews": None,
                "Contact Person": "",
                "Decision Maker": "",
                "Email": "",
                "Email Status": "Not Found",
                "Email Verification": "Not Found",
                "Priority": "Manual Review",
                "Lead Score": 0,
                "Main Opportunity": "",
                "Notes": "",
                "Facebook": "",
                "Instagram": "",
                "LinkedIn": "",
                "About Page Link": "",
                "Source URL": url,
                "intelligence": None
            }

            audit_data = crawl_and_audit_website(
                url,
                hint_decision_maker=hint_dm,
                business_name=result["Business Name"]
            )

            result["Website"] = audit_data.get("Website", url)
            result["Email"] = audit_data.get("Email", "")
            result["Contact Person"] = audit_data.get("Contact Person") or audit_data.get("Decision Maker", "")
            result["Decision Maker"] = audit_data.get("Decision Maker", "")
            result["Email Status"] = audit_data.get("Email Status") or audit_data.get("Email Verification", "Not Found")
            result["Email Verification"] = audit_data.get("Email Verification", "Not Found")
            result["Facebook"] = audit_data.get("Facebook", "")
            result["Instagram"] = audit_data.get("Instagram", "")
            result["LinkedIn"] = audit_data.get("LinkedIn", "")
            result["About Page Link"] = audit_data.get("About Page Link", "")
            result["intelligence"] = audit_data.get("intelligence")

            intel = audit_data.get("intelligence") or {}
            opps = intel.get("opportunities") or {}
            scoring = opps.get("scoring_details") or {}
            result["Priority"] = opps.get("priority") or "Manual Review"
            result["Lead Score"] = opps.get("lead_score") or 0
            result["Main Opportunity"] = opps.get("main_gap") or ""
            result["Notes"] = scoring.get("priority_reason") or ""

            return jsonify({
                "success": True,
                "is_search": False,
                "leads": [result],
                "count": 1,
                "data": result
            })

    except SecurityError as se:
        print(f"Security validation blocked {url}: {se}")
        return jsonify({"success": False, "error": f"Security restriction: {se}", "data": None, "leads": []}), 400
    except Exception as e:
        print(f"API Error processing {url}: {e}")
        return jsonify({"success": False, "error": str(e), "data": None, "leads": []}), 500

@app.route('/api/audit', methods=['POST'])
def audit_api():
    """Dedicated modular endpoint for direct website intelligence auditing."""
    data = request.json or {}
    url = data.get('url', '').strip()
    dm = data.get('decision_maker', '')
    biz = data.get('business_name', '')

    if not url:
        return jsonify({"success": False, "error": "URL is required"}), 400

    try:
        res = crawl_and_audit_website(url, hint_decision_maker=dm, business_name=biz)
        return jsonify({"success": True, "data": res})
    except SecurityError as se:
        return jsonify({"success": False, "error": f"Security restriction: {se}"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/export-excel', methods=['POST'])
def export_excel_api():
    """Generates and serves a styled Excel file in Format A or Format B."""
    data = request.json or {}
    leads = data.get('leads', [])
    format_type = data.get('format_type', 'standard_3_sheet')
    if not leads:
        return jsonify({"success": False, "error": "No lead records provided"}), 400

    try:
        excel_buffer = generate_styled_excel(leads, format_type=format_type)
        filename = "LeadHunter_3Sheet_Intelligence.xlsx" if format_type == "standard_3_sheet" else "LeadHunter_Source_Enriched.xlsx"
        return send_file(
            excel_buffer,
            as_attachment=True,
            download_name=filename,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/export-csv', methods=['POST'])
def export_csv_api():
    """Generates and serves the standardized 16-field Lead Tracker CSV."""
    data = request.json or {}
    leads = data.get('leads', [])
    if not leads:
        return jsonify({"success": False, "error": "No lead records provided"}), 400

    try:
        csv_str = generate_lead_tracker_csv(leads)
        csv_buffer = io.BytesIO(csv_str.encode('utf-8-sig'))
        return send_file(
            csv_buffer,
            as_attachment=True,
            download_name="LeadHunter_Lead_Tracker.csv",
            mimetype="text/csv; charset=utf-8"
        )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
