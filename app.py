"""
LeadHunter Studio - Lead Intelligence & Business Opportunity Detection Platform
Flask Application & API Gateway
"""

import io
import os
import re
import hmac
import time
import uuid
import random
import logging
from functools import wraps
from flask import Flask, render_template, request, jsonify, send_file, g
from werkzeug.middleware.proxy_fix import ProxyFix
from whitenoise import WhiteNoise

from services.browser_runtime import check_chromium_available
from services.job_queue import (
    JobNotFoundError,
    QueueUnavailableError,
    WorkerUnavailableError,
    check_redis_health,
    count_active_workers,
    enqueue_scrape_job,
    get_job_result_payload,
    get_job_status_payload,
)
from services.rate_limiter import SharedSlidingWindowRateLimiter
from services.runtime_config import (
    configure_logging,
    get_bool_env,
    get_configured_api_key,
    get_int_env,
    get_redis_url,
    get_trusted_proxy_hops,
    is_production_env,
    redact_email_for_log,
    redact_url_for_log,
    request_id_var,
    should_enable_debug,
    validate_startup_config,
)
from services.security import SecurityError, validate_and_sanitize_url, validate_google_maps_url
from services.website_crawler import crawl_and_audit_website
from services.export_service import generate_styled_excel, generate_lead_tracker_csv
from services.maps_scraper import scrape_google_maps, clean_external_website_url, ensure_english_maps_url

configure_logging()
logger = logging.getLogger("leadhunter.app")

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = get_int_env(
    'MAX_CONTENT_LENGTH',
    5 * 1024 * 1024,
    min_value=1024,
    max_value=50 * 1024 * 1024,
)

# Serve static assets efficiently with cache headers
_static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if os.path.isdir(_static_dir):
    app.wsgi_app = WhiteNoise(
        app.wsgi_app,
        root=_static_dir,
        prefix="static/",
        max_age=31536000 if is_production_env() else 0,
    )

_base_wsgi_app = app.wsgi_app


def apply_trusted_proxy_middleware(flask_app: Flask, hops: int | None = None) -> int:
    """
    Applies Werkzeug `ProxyFix` ONLY when `TRUSTED_PROXY_HOPS` is explicitly > 0.
    When `hops == 0`, leaves the WSGI app unwrapped so spoofable X-Forwarded-* headers are ignored.
    """
    resolved_hops = get_trusted_proxy_hops(strict=True) if hops is None else int(hops)
    if resolved_hops < 0 or resolved_hops > 10:
        raise ValueError("TRUSTED_PROXY_HOPS must be an integer between 0 and 10.")
    if resolved_hops > 0:
        flask_app.wsgi_app = ProxyFix(
            _base_wsgi_app,
            x_for=resolved_hops,
            x_proto=resolved_hops,
            x_host=resolved_hops,
            x_prefix=resolved_hops,
        )
    else:
        flask_app.wsgi_app = _base_wsgi_app
    return resolved_hops


_configured_proxy_hops = apply_trusted_proxy_middleware(app, hops=get_trusted_proxy_hops(strict=False))

ALLOWED_SCRAPE_TYPES = {'maps', 'website'}
ALLOWED_EXCEL_FORMATS = {'standard_3_sheet', 'source_enriched'}
MAX_URL_LENGTH = 2048
MAX_TEXT_FIELD_LENGTH = 200
MAX_RESULTS_MIN = 1
MAX_RESULTS_MAX = 50
MAX_EXPORT_LEADS = 1000
SAFE_ID_PATTERN = re.compile(r'^[A-Za-z0-9_.:-]{1,128}$')

rate_limiter = SharedSlidingWindowRateLimiter()


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

        # 2. Per-client sliding-window rate limit (keyed on peer/trusted-proxy remote_addr)
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


def _validate_scrape_payload(data: dict):
    """Shared strict payload validation for both synchronous `/api/scrape` and async `/api/jobs`."""
    raw_url = data.get('url')
    if not isinstance(raw_url, str) or not raw_url.strip():
        return None, (jsonify({"success": False, "error": "URL is required"}), 400)
    url = raw_url.strip()
    if len(url) > MAX_URL_LENGTH:
        return None, (jsonify({"success": False, "error": f"URL exceeds maximum length of {MAX_URL_LENGTH} characters."}), 400)

    type_ = data.get('type', 'website')
    if not isinstance(type_, str) or type_ not in ALLOWED_SCRAPE_TYPES:
        return None, (jsonify({"success": False, "error": "Invalid 'type'. Must be 'website' or 'maps'."}), 400)

    hint_dm, dm_err = _validate_optional_text(data.get('decision_maker', ''), 'decision_maker')
    if dm_err:
        return None, (jsonify({"success": False, "error": dm_err}), 400)

    biz_name_input, biz_err = _validate_optional_text(data.get('business_name', ''), 'business_name')
    if biz_err:
        return None, (jsonify({"success": False, "error": biz_err}), 400)

    # Strict validation for max_results when provided (genuine JSON int only, range 1..50)
    if 'max_results' not in data:
        max_res = 20
    else:
        raw_max_res = data['max_results']
        if isinstance(raw_max_res, bool) or not isinstance(raw_max_res, int):
            return None, (jsonify({"success": False, "error": "Invalid 'max_results'. Must be an integer between 1 and 50."}), 400)
        max_res = raw_max_res
    if not (MAX_RESULTS_MIN <= max_res <= MAX_RESULTS_MAX):
        return None, (jsonify({"success": False, "error": f"Invalid 'max_results'. Must be between {MAX_RESULTS_MIN} and {MAX_RESULTS_MAX}."}), 400)

    return {
        "url": url,
        "type": type_,
        "decision_maker": hint_dm,
        "business_name": biz_name_input,
        "max_results": max_res,
    }, None


@app.before_request
def bind_request_correlation_id():
    incoming = (request.headers.get('X-Request-ID') or '').strip()
    req_id = incoming if (incoming and SAFE_ID_PATTERN.match(incoming)) else uuid.uuid4().hex[:16]
    g._request_id_token = request_id_var.set(req_id)
    g.request_id = req_id


@app.after_request
def add_security_headers(response):
    req_id = getattr(g, 'request_id', None)
    if req_id:
        response.headers['X-Request-ID'] = req_id
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'no-referrer')
    return response


@app.teardown_request
def clear_request_correlation_id(_exc):
    token = getattr(g, '_request_id_token', None)
    if token is not None:
        try:
            request_id_var.reset(token)
        except Exception:
            pass


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


@app.route('/healthz', methods=['GET'])
def healthz():
    """Lightweight unauthenticated liveness endpoint for container orchestrators."""
    return jsonify({
        "status": "ok",
        "service": "leadhunter-studio",
    }), 200


@app.route('/readyz', methods=['GET'])
def readyz():
    """
    Readiness endpoint checking required runtime dependencies without exposing secrets:
    - LEADHUNTER_API_KEY presence
    - Redis broker connectivity (required when REDIS_URL is configured or in production)
    - Active RQ worker visibility (required when REQUIRE_ACTIVE_WORKER=true)
    - Playwright Chromium executable availability
    """
    prod = is_production_env()
    api_key_ok = bool(get_configured_api_key())
    redis_configured = bool(get_redis_url())
    require_redis = prod or redis_configured
    require_worker = get_bool_env("REQUIRE_ACTIVE_WORKER", False)

    if require_redis:
        redis_ok, redis_msg = check_redis_health()
        workers_online = count_active_workers() if redis_ok else 0
    else:
        redis_ok, redis_msg = True, "Redis not configured (local fallback mode)"
        workers_online = 0

    chromium_ok, chromium_msg = check_chromium_available()
    worker_ok = (workers_online >= 1) if require_worker else True

    ready = api_key_ok and redis_ok and worker_ok and chromium_ok
    payload = {
        "status": "ready" if ready else "not_ready",
        "checks": {
            "api_key_configured": api_key_ok,
            "redis": {"ok": redis_ok, "detail": redis_msg},
            "workers": {"ok": worker_ok, "online": workers_online, "required": require_worker},
            "chromium": {"ok": chromium_ok, "detail": chromium_msg},
        },
    }
    return jsonify(payload), (200 if ready else 503)


@app.route('/api/jobs', methods=['POST'])
@require_api_auth_and_rate_limit
def create_job_api():
    """
    Asynchronous background job submission endpoint (Redis + RQ).
    Enqueues Google Maps multi-lead scraping or website enrichment without blocking web workers.
    """
    data, err_resp = _parse_json_object()
    if err_resp:
        return err_resp

    validated, val_err = _validate_scrape_payload(data)
    if val_err:
        return val_err

    url = validated["url"]
    scrape_type = validated["type"]

    # Fail fast on SSRF / invalid target URLs before enqueueing to Redis
    try:
        if scrape_type == 'maps':
            validate_google_maps_url(url)
        else:
            validate_and_sanitize_url(url)
    except SecurityError as se:
        logger.warning("Job submission blocked by security policy for %s: %s", redact_url_for_log(url), se)
        return jsonify({"success": False, "error": f"Security restriction: {se}"}), 400

    try:
        enqueued = enqueue_scrape_job(
            url=url,
            scrape_type=scrape_type,
            max_results=validated["max_results"],
            business_name=validated["business_name"],
            decision_maker=validated["decision_maker"],
        )
        job_id = enqueued["job_id"]
        return jsonify({
            "success": True,
            "job_id": job_id,
            "status": enqueued["status"],
            "deduplicated": enqueued["deduplicated"],
            "workers_online": enqueued["workers_online"],
            "poll_url": f"/api/jobs/{job_id}",
            "result_url": f"/api/jobs/{job_id}/result",
        }), 202
    except QueueUnavailableError:
        logger.error("Failed to enqueue job: Redis queue unavailable")
        return jsonify({
            "success": False,
            "code": "queue_unavailable",
            "error": "Background job queue is temporarily unavailable.",
        }), 503
    except WorkerUnavailableError:
        logger.error("Failed to enqueue job: no active RQ workers")
        return jsonify({
            "success": False,
            "code": "worker_unavailable",
            "error": "No background workers are currently available to process jobs.",
        }), 503
    except Exception:
        logger.exception("Internal error enqueueing background job")
        return jsonify({
            "success": False,
            "error": "Internal server error while scheduling background job.",
        }), 500


@app.route('/api/jobs/<job_id>', methods=['GET'])
@require_api_auth_and_rate_limit
def get_job_status_api(job_id: str):
    """Returns status and progress metadata for an asynchronous scrape/enrichment job."""
    if not SAFE_ID_PATTERN.match(job_id or ""):
        return jsonify({"success": False, "error": "Invalid job_id format."}), 400

    try:
        payload = get_job_status_payload(job_id)
        return jsonify(payload), 200
    except JobNotFoundError:
        return jsonify({"success": False, "error": "Job not found or expired."}), 404
    except QueueUnavailableError:
        return jsonify({
            "success": False,
            "code": "queue_unavailable",
            "error": "Background job queue is temporarily unavailable.",
        }), 503
    except Exception:
        logger.exception("Internal error fetching status for job_id=%s", job_id)
        return jsonify({"success": False, "error": "Internal server error while checking job status."}), 500


@app.route('/api/jobs/<job_id>/result', methods=['GET'])
@require_api_auth_and_rate_limit
def get_job_result_api(job_id: str):
    """Returns the completed result payload for an asynchronous scrape/enrichment job."""
    if not SAFE_ID_PATTERN.match(job_id or ""):
        return jsonify({"success": False, "error": "Invalid job_id format."}), 400

    try:
        payload, status_code = get_job_result_payload(job_id)
        return jsonify(payload), status_code
    except JobNotFoundError:
        return jsonify({"success": False, "error": "Job not found or expired."}), 404
    except QueueUnavailableError:
        return jsonify({
            "success": False,
            "code": "queue_unavailable",
            "error": "Background job queue is temporarily unavailable.",
        }), 503
    except Exception:
        logger.exception("Internal error fetching result for job_id=%s", job_id)
        return jsonify({"success": False, "error": "Internal server error while retrieving job result."}), 500


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

    validated, val_err = _validate_scrape_payload(data)
    if val_err:
        return val_err

    url = validated["url"]
    type_ = validated["type"]
    hint_dm = validated["decision_maker"]
    biz_name_input = validated["business_name"]
    max_res = validated["max_results"]

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
            logger.info("[Maps] Starting extraction for target=%s (max_results=%d)", redact_url_for_log(clean_url), max_res)
            maps_res = scrape_google_maps(clean_url, max_results=max_res)

            if not maps_res.get("success"):
                logger.warning("[Maps] Extraction failed or returned no listings for target=%s", redact_url_for_log(clean_url))
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
                    logger.info("[Enrichment %d/%d] Auditing website for '%s': %s", idx, total_leads, biz_name, redact_url_for_log(clean_website))
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
                        logger.info(
                            "[Enrichment %d/%d] Successfully enriched '%s' (email=%s, priority=%s)",
                            idx,
                            total_leads,
                            biz_name,
                            redact_email_for_log(lead['Email']),
                            lead['Priority'],
                        )
                    except Exception as e:
                        logger.warning(
                            "[Enrichment %d/%d] Website enrichment failed for '%s' (%s): %s. Retaining Maps lead data.",
                            idx,
                            total_leads,
                            biz_name,
                            redact_url_for_log(clean_website),
                            e,
                        )
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

            logger.info("[Maps] Completed processing all %d leads for target=%s", len(enriched_leads), redact_url_for_log(clean_url))

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
        logger.warning("Security validation blocked target=%s: %s", redact_url_for_log(url), se)
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
    port = get_int_env('PORT', 5000, min_value=1, max_value=65535)
    app.run(debug=should_enable_debug(), port=port)
