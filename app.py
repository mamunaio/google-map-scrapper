"""
LeadHunter Studio - Lead Intelligence & Business Opportunity Detection Platform
Flask Application & API Gateway
"""

import time
import random
from flask import Flask, render_template, request, jsonify, send_file
from playwright.sync_api import sync_playwright

from services.security import SecurityError
from services.website_crawler import crawl_and_audit_website
from services.export_service import generate_styled_excel

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
        # Option A: Google Maps Extraction
        if type_ == 'maps':
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(url, timeout=60000, wait_until='domcontentloaded')
                time.sleep(get_random_delay())

                try:
                    name_loc = page.locator('h1.DUwDvf.lfPIob')
                    if name_loc.count() > 0:
                        result["Business Name"] = name_loc.first.inner_text().strip()
                except Exception:
                    pass

                try:
                    web_loc = page.locator('a[data-item-id="authority"]')
                    if web_loc.count() > 0:
                        result["Website"] = web_loc.first.get_attribute('href').strip()
                except Exception:
                    pass

                try:
                    phone_loc = page.locator('button[data-tooltip*="Copy phone number"]')
                    if phone_loc.count() > 0:
                        result["Phone Number"] = phone_loc.first.inner_text().strip()
                except Exception:
                    pass

                browser.close()

        elif type_ == 'website':
            result["Website"] = url

        # Option B / Secondary Step: Deep Website Intelligence & Contact Enrichment
        if result["Website"]:
            audit_data = crawl_and_audit_website(
                result["Website"],
                hint_decision_maker=hint_dm,
                business_name=result["Business Name"]
            )

            result["Website"] = audit_data.get("Website", result["Website"])
            result["Email"] = audit_data.get("Email", "")
            result["Decision Maker"] = audit_data.get("Decision Maker", "")
            result["Email Verification"] = audit_data.get("Email Verification", "Unverified")
            result["Facebook"] = audit_data.get("Facebook", "")
            result["Instagram"] = audit_data.get("Instagram", "")
            result["LinkedIn"] = audit_data.get("LinkedIn", "")
            result["About Page Link"] = audit_data.get("About Page Link", "")
            result["intelligence"] = audit_data.get("intelligence")

        return jsonify({"success": True, "data": result})

    except SecurityError as se:
        print(f"Security validation blocked {url}: {se}")
        return jsonify({"success": False, "error": f"Security restriction: {se}", "data": result}), 400
    except Exception as e:
        print(f"API Error processing {url}: {e}")
        return jsonify({"success": False, "error": str(e), "data": result}), 500

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

if __name__ == '__main__':
    app.run(debug=True, port=5000)
