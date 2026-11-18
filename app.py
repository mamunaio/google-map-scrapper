"""
LeadHunter Studio - Lead Intelligence & Business Opportunity Detection Platform
Flask Application & API Gateway
"""

import io
import os
import hmac
import time
import random
import logging
import threading
from collections import deque
from functools import wraps
from flask import Flask, render_template, request, jsonify, send_file

from services.security import SecurityError, validate_google_maps_url
from services.website_crawler import crawl_and_audit_website
from services.export_service import generate_styled_excel, generate_lead_tracker_csv
from services.maps_scraper import scrape_google_maps, clean_external_website_url, ensure_english_maps_url

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("leadhunter.app")

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 5 * 1024 * 1024))  # 5 MB

ALLOWED_SCRAPE_TYPES = {'maps', 'website'}
ALLOWED_EXCEL_FORMATS = {'standard_3_sheet', 'source_enriched'}
MAX_URL_LENGTH = 2048
MAX_TEXT_FIELD_LENGTH = 200
MAX_RESULTS_MIN = 1
MAX_RESULTS_MAX = 50
MAX_EXPORT_LEADS = 1000


def is_production_env() -> bool:
    """Detects production execution mode from standard environment variables."""
    leadhunter_env = os.getenv('LEADHUNTER_ENV', '').strip().lower()
    flask_env = os.getenv('FLASK_ENV', '').strip().lower()
    render_flag = os.getenv('RENDER', '').strip().lower()
    return (
        leadhunter_env in ('prod', 'production')
        or flask_env in ('prod', 'production')
        or render_flag in ('1', 'true', 'yes')
    )


def should_enable_debug() -> bool:
    """
    Flask debug mode is disabled by default and strictly forbidden in production.
    Can only be enabled locally via FLASK_DEBUG=true when not in production.
    """
    if is_production_env():
        return False
    return os.getenv('FLASK_DEBUG', '').strip().lower() in ('1', 'true', 'yes')


def get_configured_api_key() -> str:
    """Reads the API key strictly from environment configuration (never hardcoded)."""
    return os.getenv('LEADHUNTER_API_KEY', '').strip()


class SlidingWindowRateLimiter:
    """
    Thread-safe in-memory sliding-window rate limiter keyed strictly on the peer IP
    (`request.remote_addr`). Spoofable headers such as `X-Forwarded-For` are ignored.

    Limitation: In-memory state is per-process. Multi-worker or multi-instance
    deployments require a shared store (e.g., Redis) for global rate limiting.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._hits: dict[str, deque[float]] = {}

    def _get_limits(self) -> tuple[int, int]:
        try:
            max_req = max(1, int(os.getenv('RATE_LIMIT_MAX_REQUESTS', '30')))
        except ValueError:
            max_req = 30
        try:
            window_sec = max(1, int(os.getenv('RATE_LIMIT_WINDOW_SECONDS', '60')))
        except ValueError:
            window_sec = 60
        return max_req, window_sec

    def check(self, client_key: str) -> tuple[bool, int]:
        max_req, window_sec = self._get_limits()
        now = time.monotonic()
        cutoff = now - window_sec
        with self._lock:
            bucket = self._hits.setdefault(client_key, deque())
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= max_req:
                retry_after = max(1, int(window_sec - (now - bucket[0])) + 1)
                return False, retry_after
            bucket.append(now)
            return True, 0

    def reset(self):
        with self._lock:
            self._hits.clear()


rate_limiter = SlidingWindowRateLimiter()


def _extract_provided_api_key() -> str:
    """Extracts API key from `X-API-Key` or `Authorization: Bearer <key>` headers."""
    header_key = (request.headers.get('X-API-Key') or '').strip()
    if header_key:
        return header_key
    auth_header = (request.headers.get('Authorization') or '').strip()
    if auth_header.lower().startswith('bearer '):
        return auth_header[7:].strip()
    return ''


def require_api_auth_and_rate_limit(fn):
    """
    Enforces fail-closed API key authentication and per-client rate limiting on API endpoints.
    Uses explicit headers (`X-API-Key` / `Authorization: Bearer`), avoiding ambient cookie CSRF.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # 1. Fail-closed authentication check
        expected_key = get_configured_api_key()
        if not expected_key:
            logger.error("API access blocked: LEADHUNTER_API_KEY is not configured.")
            return jsonify({
                "success": False,
                "error": "Service authentication is not configured."
            }), 503

        provided_key = _extract_provided_api_key()
        if not provided_key or not hmac.compare_digest(provided_key, expected_key):
            return jsonify({
                "success": False,
                "error": "Unauthorized: valid API key required."
            }), 401

        # 2. Per-client sliding-window rate limit (strictly keyed on peer remote_addr)
        client_ip = request.remote_addr or "unknown"
        allowed, retry_after = rate_limiter.check(client_ip)
        if not allowed:
            resp = jsonify({
                "success": False,
                "error": "Rate limit exceeded. Please try again later."
            })
            resp.status_code = 429
            resp.headers['Retry-After'] = str(retry_after)
            return resp

        return fn(*args, **kwargs)
    return wrapper


def _parse_json_object():
    """Parses and validates that the request body is a JSON object (dict)."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None, (jsonify({"success": False, "error": "Request body must be a valid JSON object."}), 400)
    return data, None


def _validate_optional_text(value, field_name: str, max_len: int = MAX_TEXT_FIELD_LENGTH):
    if value is None:
        return "", None
    if not isinstance(value, str):
        return None, f"Field '{field_name}' must be a string."
    cleaned = value.strip()
    if len(cleaned) > max_len:
        return None, f"Field '{field_name}' exceeds maximum length of {max_len} characters."
    return cleaned, None


@app.after_request
def add_security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'no-referrer')
    return response


@app.errorhandler(413)
def handle_payload_too_large(_err):
    return jsonify({
        "success": False,
        "error": "Request payload exceeds maximum allowed size."
    }), 413


def get_random_delay():
    return random.uniform(1.2, 2.5)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/scrape', methods=['POST'])
@require_api_auth_and_rate_limit
def scrape_api():
    """
    Main lead enrichment and intelligence endpoint.
    Maintains backward compatibility with existing API contracts while providing
    deep Website Intelligence, SEO Audit, Feature Detection, and Opportunity Scoring.
    """
    data, err_resp = _parse_json_object()
    if err_resp:
        return err_resp

    raw_url = data.get('url')
    if not isinstance(raw_url, str) or not raw_url.strip():
        return jsonify({"success": False, "error": "URL is required"}), 400
    url = raw_url.strip()
    if len(url) > MAX_URL_LENGTH:
        return jsonify({"success": False, "error": f"URL exceeds maximum length of {MAX_URL_LENGTH} characters."}), 400

    type_ = data.get('type', 'website')
    if not isinstance(type_, str) or type_ not in ALLOWED_SCRAPE_TYPES:
        return jsonify({"success": False, "error": "Invalid 'type'. Must be 'website' or 'maps'."}), 400

    hint_dm, dm_err = _validate_optional_text(data.get('decision_maker', ''), 'decision_maker')
    if dm_err:
        return jsonify({"success": False, "error": dm_err}), 400

    biz_name_input, biz_err = _validate_optional_text(data.get('business_name', ''), 'business_name')
    if biz_err:
        return jsonify({"success": False, "error": biz_err}), 400

    # Strict validation for max_results when provided
    raw_max_res = data.get('max_results', 20)
    if isinstance(raw_max_res, bool):
        return jsonify({"success": False, "error": "Invalid 'max_results'. Must be an integer between 1 and 50."}), 400
    try:
        if isinstance(raw_max_res, float) and not raw_max_res.is_integer():
            raise ValueError("non-integer float")
        max_res = int(raw_max_res)
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid 'max_results'. Must be an integer between 1 and 50."}), 400
    if not (MAX_RESULTS_MIN <= max_res <= MAX_RESULTS_MAX):
        return jsonify({"success": False, "error": f"Invalid 'max_results'. Must be between {MAX_RESULTS_MIN} and {MAX_RESULTS_MAX}."}), 400

    result = {
        "Business Name": biz_name_input,
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
                if biz_name_input and not lead.get("Business Name"):
                    lead["Business Name"] = biz_name_input

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
                        lead.setdefault("Notes", "Website audit failed — manual review required.")
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
                "Business Name": biz_name_input,
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
        logger.warning("Security validation blocked %s: %s", url, se)
        return jsonify({"success": False, "error": f"Security restriction: {se}", "data": None, "leads": []}), 400
    except Exception:
        logger.exception("Internal API error processing scrape request")
        return jsonify({"success": False, "error": "Internal server error while processing request.", "data": None, "leads": []}), 500


@app.route('/api/audit', methods=['POST'])
@require_api_auth_and_rate_limit
def audit_api():
    """Dedicated modular endpoint for direct website intelligence auditing."""
    data, err_resp = _parse_json_object()
    if err_resp:
        return err_resp

    raw_url = data.get('url')
    if not isinstance(raw_url, str) or not raw_url.strip():
        return jsonify({"success": False, "error": "URL is required"}), 400
    url = raw_url.strip()
    if len(url) > MAX_URL_LENGTH:
        return jsonify({"success": False, "error": f"URL exceeds maximum length of {MAX_URL_LENGTH} characters."}), 400

    dm, dm_err = _validate_optional_text(data.get('decision_maker', ''), 'decision_maker')
    if dm_err:
        return jsonify({"success": False, "error": dm_err}), 400
    biz, biz_err = _validate_optional_text(data.get('business_name', ''), 'business_name')
    if biz_err:
        return jsonify({"success": False, "error": biz_err}), 400

    try:
        res = crawl_and_audit_website(url, hint_decision_maker=dm, business_name=biz)
        return jsonify({"success": True, "data": res})
    except SecurityError as se:
        return jsonify({"success": False, "error": f"Security restriction: {se}"}), 400
    except Exception:
        logger.exception("Internal API error processing audit request")
        return jsonify({"success": False, "error": "Internal server error while processing request."}), 500


@app.route('/api/export-excel', methods=['POST'])
@require_api_auth_and_rate_limit
def export_excel_api():
    """Generates and serves a styled Excel file in Format A or Format B."""
    data, err_resp = _parse_json_object()
    if err_resp:
        return err_resp

    leads = data.get('leads')
    if not isinstance(leads, list) or not leads or not all(isinstance(item, dict) for item in leads):
        return jsonify({"success": False, "error": "Field 'leads' must be a non-empty list of lead objects."}), 400
    if len(leads) > MAX_EXPORT_LEADS:
        return jsonify({"success": False, "error": f"Maximum export limit of {MAX_EXPORT_LEADS} leads exceeded."}), 400

    format_type = data.get('format_type', 'standard_3_sheet')
    if not isinstance(format_type, str) or format_type not in ALLOWED_EXCEL_FORMATS:
        return jsonify({"success": False, "error": "Invalid 'format_type'."}), 400

    try:
        excel_buffer = generate_styled_excel(leads, format_type=format_type)
        filename = "LeadHunter_3Sheet_Intelligence.xlsx" if format_type == "standard_3_sheet" else "LeadHunter_Source_Enriched.xlsx"
        return send_file(
            excel_buffer,
            as_attachment=True,
            download_name=filename,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    except Exception:
        logger.exception("Internal API error generating Excel export")
        return jsonify({"success": False, "error": "Internal server error while generating export."}), 500


@app.route('/api/export-csv', methods=['POST'])
@require_api_auth_and_rate_limit
def export_csv_api():
    """Generates and serves the standardized 16-field Lead Tracker CSV."""
    data, err_resp = _parse_json_object()
    if err_resp:
        return err_resp

    leads = data.get('leads')
    if not isinstance(leads, list) or not leads or not all(isinstance(item, dict) for item in leads):
        return jsonify({"success": False, "error": "Field 'leads' must be a non-empty list of lead objects."}), 400
    if len(leads) > MAX_EXPORT_LEADS:
        return jsonify({"success": False, "error": f"Maximum export limit of {MAX_EXPORT_LEADS} leads exceeded."}), 400

    try:
        csv_str = generate_lead_tracker_csv(leads)
        csv_buffer = io.BytesIO(csv_str.encode('utf-8-sig'))
        return send_file(
            csv_buffer,
            as_attachment=True,
            download_name="LeadHunter_Lead_Tracker.csv",
            mimetype="text/csv; charset=utf-8"
        )
    except Exception:
        logger.exception("Internal API error generating CSV export")
        return jsonify({"success": False, "error": "Internal server error while generating export."}), 500


if __name__ == '__main__':
    app.run(debug=should_enable_debug(), port=int(os.getenv('PORT', 5000)))
