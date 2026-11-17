"""
LeadHunter Studio - Lead Intelligence & Business Opportunity Detection Platform
Flask Application & API Gateway
"""

import io
import time
import random
import logging
from flask import Flask, render_template, request, jsonify, send_file
from playwright.sync_api import sync_playwright

from services.security import SecurityError, validate_google_maps_url
from services.website_crawler import crawl_and_audit_website
from services.export_service import generate_styled_excel, generate_lead_tracker_csv
from services.maps_scraper import scrape_google_maps, clean_external_website_url, ensure_english_maps_url

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("leadhunter.app")

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
            clean_url = ensure_english_maps_url(validate_google_maps_url(url))
            max_res = min(int(data.get('max_results', 20)), 50)
            logger.info(f"[Maps] Starting extraction for URL: {clean_url} (max_results={max_res})")
            maps_res = scrape_google_maps(clean_url, max_results=max_res)

            if not maps_res.get("success"):
                logger.warning(f"[Maps] Extraction failed or returned no listings for: {clean_url}")
                return jsonify({
                    "success": False,
                    "error": maps_res.get("error", "No business details or listings could be extracted from this Google Maps URL."),
                    "leads": [],
                    "count": 0,
                    "data": None
                }), 422

            extracted_leads = maps_res.get("leads", [])
            total_leads = len(extracted_leads)
            logger.info(f"[Maps] Extracted {total_leads} listing(s) from Maps feed. Beginning lead enrichment...")
            enriched_leads = []

            for idx, raw_lead in enumerate(extracted_leads, 1):
                lead = dict(raw_lead)
                if data.get("business_name") and not lead.get("Business Name"):
                    lead["Business Name"] = data.get("business_name")

                biz_name = lead.get("Business Name") or f"Listing #{idx}"
                raw_website = lead.get("Website") or ""
                # Ensure website is a valid external URL, sanitizing redirect / adclick URLs
                clean_website = clean_external_website_url(raw_website)
                lead["Website"] = clean_website

                # If website was extracted and valid, run Website Intelligence & Contact Enrichment
                if clean_website:
                    logger.info(f"[Enrichment {idx}/{total_leads}] Auditing website for '{biz_name}': {clean_website}")
                    try:
                        audit_data = crawl_and_audit_website(
                            clean_website,
                            hint_decision_maker=hint_dm,
                            business_name=lead.get("Business Name", ""),
                            phone=lead.get("Phone") or lead.get("Phone Number") or ""
                        )
                        lead["Website"] = audit_data.get("Website", clean_website)
                        lead["Website Status"] = audit_data.get("Website Status", "Online")
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
                        lead["Priority"] = audit_data.get("Priority") or opps.get("priority") or "Manual Review"
                        lead["Lead Score"] = audit_data.get("Lead Score") if audit_data.get("Lead Score") is not None else (opps.get("lead_score") or 0)
                        lead["Main Opportunity"] = audit_data.get("Main Opportunity") or opps.get("main_gap") or ""
                        lead["Notes"] = audit_data.get("Notes") or scoring.get("priority_reason") or ""
                        logger.info(f"[Enrichment {idx}/{total_leads}] Successfully enriched '{biz_name}' (Email: {lead['Email'] or 'None'}, Priority: {lead['Priority']})")
                    except Exception as e:
                        logger.warning(f"[Enrichment {idx}/{total_leads}] Website enrichment failed for '{biz_name}' ({clean_website}): {e}. Retaining Maps lead data.")
                        lead.setdefault("Website Status", "Crawl failed")
                        lead.setdefault("Priority", "Manual Review")
                        lead.setdefault("Lead Score", 0)
                        lead.setdefault("Main Opportunity", "Website inspection failed — manual review required")
                        lead.setdefault("Notes", f"Website audit failed: {e}")
                else:
                    logger.info(f"[Enrichment {idx}/{total_leads}] No valid external website for '{biz_name}'. Retaining Maps lead data.")
                    lead.setdefault("Website Status", "Not checked")
                    lead.setdefault("Priority", "Manual Review")
                    lead.setdefault("Lead Score", 0)
                    lead.setdefault("Main Opportunity", "No website provided — manual review required")
                    lead.setdefault("Notes", "No valid external website available for automated audit.")

                enriched_leads.append(lead)

            logger.info(f"[Maps] Completed processing all {len(enriched_leads)} leads for {clean_url}")

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
            result["Website Status"] = audit_data.get("Website Status", "Online")
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
            result["Priority"] = audit_data.get("Priority") or opps.get("priority") or "Manual Review"
            result["Lead Score"] = audit_data.get("Lead Score") if audit_data.get("Lead Score") is not None else (opps.get("lead_score") or 0)
            result["Main Opportunity"] = audit_data.get("Main Opportunity") or opps.get("main_gap") or ""
            result["Notes"] = audit_data.get("Notes") or scoring.get("priority_reason") or ""

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
