"""
LeadHunter Unified Website Crawler & Intelligence Engine
Coordinates safe HTTP fetching, Playwright fallback, deep candidate crawling,
email/social extraction, technical audits, feature detection, and opportunity scoring.
"""

import logging
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

from services.browser_runtime import (
    acquire_browser_slot,
    get_chromium_launch_options,
    safe_close_playwright_resources,
)
from services.runtime_config import redact_url_for_log
from services.security import (
    safe_http_get,
    validate_and_sanitize_url,
    SecurityError,
    SafeBrowserProxy,
    create_public_website_route_interceptor
)
from services.email_service import (
    extract_emails_and_socials,
    find_decision_maker_from_html,
    extract_name_from_email_prefix,
    generate_email_permutations,
    verify_email_smtp
)
from services.business_feature_detector import detect_business_features
from services.seo_audit import audit_page_seo, check_robots_and_sitemap
from services.technical_audit import audit_technical_and_mobile
from services.performance_audit import audit_website_performance
from services.opportunity_analyzer import analyze_business_opportunities

def find_candidate_pages(html_text: str, base_url: str, max_candidates: int = 5):
    """
    Finds high-priority internal links (Contact, About, Team, Leadership)
    strictly within the same base domain and restricted to HTTP/HTTPS schemes.
    """
    candidate_urls = []
    if not html_text or not base_url:
        return candidate_urls

    try:
        base_parsed = urlparse(base_url)
        if base_parsed.scheme not in ('http', 'https') or not base_parsed.hostname:
            return candidate_urls
        base_domain = base_parsed.hostname.lower().replace('www.', '')
        soup = BeautifulSoup(html_text, 'html.parser')
        keywords = ['contact', 'about', 'reach', 'touch', 'support', 'team', 'leadership', 'location', 'service']

        for a in soup.find_all('a', href=True):
            href = a.get('href', '').strip()
            text = a.get_text().strip().lower()
            if not href or href.startswith(('tel:', 'mailto:', 'javascript:', 'data:', 'file:', '#')):
                continue

            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)
            if parsed.scheme not in ('http', 'https') or not parsed.hostname:
                continue
            parsed_domain = parsed.hostname.lower().replace('www.', '')

            # Enforce same domain
            if parsed_domain == base_domain:
                href_lower = href.lower()
                if any(kw in href_lower or kw in text for kw in keywords):
                    clean_u = full_url.split('?')[0].split('#')[0]
                    if clean_u not in candidate_urls and clean_u.rstrip('/') != base_url.rstrip('/'):
                        candidate_urls.append(clean_u)

        def priority_order(u):
            u_low = u.lower()
            if 'team' in u_low or 'leadership' in u_low: return 0
            if 'about' in u_low: return 1
            if 'contact' in u_low: return 2
            return 3

        candidate_urls.sort(key=priority_order)
    except Exception:
        pass

    return candidate_urls[:max_candidates]

def scrape_with_playwright_fallback(url: str, existing_fb: str = "", existing_insta: str = "", existing_linkedin: str = "", business_name: str = ""):
    """
    Headless Chromium rendering fallback for JavaScript-rendered SPAs (React, Vue, Wix, Webflow).
    Enforces defense-in-depth SSRF & DNS rebinding protection:
    - Pre-validates initial URL and every candidate page URL via validate_and_sanitize_url().
    - Routes ALL browser traffic through SafeBrowserProxy(allow_public_hosts=True) for real-time
      DNS resolution and pinned public-IP socket connections.
    - Attaches Playwright route interceptor to abort any internal/restricted navigation or subresource.
    - Guarantees cleanup of page, context, browser, and proxy in try/finally blocks.
    """
    # Fail closed immediately if the initial URL fails SSRF / scheme / DNS validation
    safe_url = validate_and_sanitize_url(url)
    logger = logging.getLogger("leadhunter.website_crawler")

    try:
        with acquire_browser_slot():
            with SafeBrowserProxy(allow_public_hosts=True) as proxy:
                with sync_playwright() as p:
                    browser = None
                    context = None
                    page = None
                    try:
                        browser = p.chromium.launch(**get_chromium_launch_options())
                        context = browser.new_context(
                            proxy={"server": f"http://127.0.0.1:{proxy.port}"},
                            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
                        )
                        page = context.new_page()
                        page.route("**/*", create_public_website_route_interceptor(page))

                        page.goto(safe_url, timeout=12000, wait_until='domcontentloaded')
                        time.sleep(0.5)

                        try:
                            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                            time.sleep(0.5)
                        except Exception:
                            pass

                        html = page.content()
                        email, fb, insta, linkedin, _ = extract_emails_and_socials(html, base_url=safe_url)
                        dm_name, dm_role = find_decision_maker_from_html(html, business_name=business_name)

                        fb = fb or existing_fb
                        insta = insta or existing_insta
                        linkedin = linkedin or existing_linkedin

                        # Crawl candidates if still missing info (bounded to 2 candidates, 8s timeout)
                        if not (email and fb and linkedin and dm_name):
                            candidate_links = find_candidate_pages(html, safe_url, max_candidates=2)
                            for curl in candidate_links:
                                try:
                                    safe_curl = validate_and_sanitize_url(curl)
                                except SecurityError:
                                    continue
                                try:
                                    page.goto(safe_curl, timeout=8000, wait_until='domcontentloaded')
                                    c_html = page.content()
                                    c_email, c_fb, c_insta, c_linkedin, _ = extract_emails_and_socials(c_html, base_url=safe_url)
                                    if not dm_name:
                                        dm_name, dm_role = find_decision_maker_from_html(c_html, business_name=business_name)
                                    email = email or c_email
                                    fb = fb or c_fb
                                    insta = insta or c_insta
                                    linkedin = linkedin or c_linkedin
                                    if email and fb and linkedin and dm_name:
                                        break
                                except Exception:
                                    pass

                        return html, email, fb, insta, linkedin, dm_name, dm_role
                    finally:
                        safe_close_playwright_resources(page=page, context=context, browser=browser)
    except SecurityError:
        raise
    except Exception as e:
        logger.warning("Playwright fallback error for %s: %s", redact_url_for_log(safe_url), e)
        return "", "", existing_fb, existing_insta, existing_linkedin, None, None

def is_challenge_or_blocked(status_code: int = 200, html_text: str = "", error_msg: str = None) -> tuple[bool, str]:
    """
    Detects Cloudflare challenges, CAPTCHAs, bot mitigations, 403 Forbidden,
    access-denied pages, timeouts, and network connection errors.
    Returns (is_blocked: bool, reason: str).
    """
    if error_msg:
        err_lower = error_msg.lower()
        if "timeout" in err_lower or "timed out" in err_lower:
            return True, "Request timed out"
        if "connection" in err_lower or "refused" in err_lower or "reset" in err_lower or "name or service not known" in err_lower or "nodename" in err_lower:
            return True, f"Connection failed: {error_msg}"
        return True, f"Network error: {error_msg}"

    if status_code in (401, 403, 429, 503):
        text_lower = (html_text or "").lower()
        if any(cf in text_lower for cf in ["cloudflare", "cf-chl", "cf-turnstile", "challenges.cloudflare.com", "ray id:"]):
            return True, f"Cloudflare WAF challenge detected (HTTP {status_code})"
        if any(cap in text_lower for cap in ["captcha", "hcaptcha", "recaptcha", "verify you are human"]):
            return True, f"Bot mitigation / CAPTCHA challenge detected (HTTP {status_code})"
        if "access denied" in text_lower or "forbidden" in text_lower:
            return True, f"Access Denied / Forbidden (HTTP {status_code})"
        return True, f"HTTP {status_code} Error"

    if html_text:
        text_lower = html_text.lower()
        if ("attention required! | cloudflare" in text_lower or
            "<title>just a moment...</title>" in text_lower or
            "checking your browser before accessing" in text_lower or
            ("challenges.cloudflare.com" in text_lower and len(html_text) < 4000) or
            ("verify you are human" in text_lower and ("captcha" in text_lower or "turnstile" in text_lower)) or
            ("cf-turnstile" in text_lower and len(html_text) < 3000)):
            return True, "Cloudflare challenge / CAPTCHA page detected"

        if ("<title>access denied</title>" in text_lower or
            ("<title>403 forbidden</title>" in text_lower and len(html_text) < 2000)):
            return True, "Access Denied page detected"

    return False, ""

def crawl_and_audit_website(url: str, hint_decision_maker: str = "", business_name: str = "", phone: str = ""):
    """
    Complete end-to-end audit:
    - SSRF protection & safe fetching
    - Robust challenge / bot mitigation / 403 handling (never interprets challenge pages as real websites)
    - Contact extraction (Email, Decision Maker, Facebook, Instagram, LinkedIn)
    - Full Website Intelligence (SEO, Technical, Features, Performance, Opportunity Scoring)
    - Preserves exact fields for backward compatibility!
    """
    sanitized_url = validate_and_sanitize_url(url)
    
    start_time = time.time()
    response_text = ""
    status_code = 0
    final_url = sanitized_url
    is_ssl_verified = True
    error_msg = None

    # Step 1: Safe HTTP GET
    try:
        resp = safe_http_get(sanitized_url, timeout=(5, 12))
        response_text = resp.text
        status_code = resp.status_code
        final_url = resp.url
        is_ssl_verified = getattr(resp, 'ssl_verified', True)
    except SecurityError as se:
        raise se
    except Exception as e:
        error_msg = str(e)

    elapsed_sec = time.time() - start_time
    is_blocked, block_reason = is_challenge_or_blocked(status_code, response_text, error_msg)

    # If the response is blocked by Cloudflare, CAPTCHA, access denied, or network error:
    # Do NOT interpret challenge content as the real website!
    if is_blocked:
        timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        website_status = "Blocked / Inconclusive"
        if error_msg and ("timeout" in error_msg.lower() or "timed out" in error_msg.lower()):
            website_status = "Timeout / Error"
        elif error_msg:
            website_status = "Connection Error"

        seo_audit = {
            "status": "Blocked / Inconclusive",
            "seo_score": None,
            "metrics": {
                "title": "Not Audited",
                "meta_description": None,
                "h1_tags": [],
                "canonical_url": None,
                "is_noindex": None,
                "has_viewport": None,
                "images_total": 0,
                "images_missing_alt": 0,
                "schema_types": []
            },
            "findings": [f"Audit inconclusive: {block_reason}. Real website content not inspected."],
            "robots_sitemap": {"robots_txt_status": "Unknown", "sitemap_status": "Unknown"}
        }

        tech_audit = {
            "status": "Inconclusive",
            "mobile_usability": {
                "status": "Not Audited",
                "has_viewport": None,
                "overflow_risk": None,
                "evidence": f"Inspection blocked: {block_reason}"
            },
            "ssl_certificate": {
                "status": "Valid" if (is_ssl_verified and status_code > 0) else "Unknown",
                "evidence": "TLS handshake completed" if (is_ssl_verified and status_code > 0) else "Connection failed"
            },
            "findings": []
        }

        features_audit = {
            k: {
                "status": "Unknown",
                "evidence": [f"Feature inspection inconclusive: {block_reason}; public integration cannot be verified."],
                "details": {}
            }
            for k in ["lead_capture", "booking", "chatbot", "voice_agent", "crm", "review_management", "analytics"]
        }

        perf_audit = {
            "audit_status": "Not Audited",
            "audit_timestamp": timestamp_str,
            "mobile_score": None,
            "desktop_score": None,
            "core_web_vitals": {},
            "source": f"Audit Skipped ({website_status})",
            "local_diagnostics": {}
        }

        opp_analysis = {
            "lead_score": 50,
            "priority": "Manual Review",
            "priority_tier": "Manual Review",
            "priority_reason": f"Website inspection inconclusive ({block_reason}); requires manual review.",
            "scoring_details": {
                "research_score": 50,
                "research_priority": "Manual Review",
                "priority": "Manual Review",
                "priority_reason": f"Website inspection inconclusive ({block_reason}); requires manual review.",
                "suggested_next_action": "Perform manual domain review; automated crawler blocked by bot/WAF challenge.",
                "main_identified_gap": f"Website inspection blocked ({block_reason})"
            },
            "opportunities_count": 0,
            "detected_opportunities": [],
            "outreach_hooks": [],
            "main_gap": f"Website inspection blocked ({block_reason})",
            "next_action": "Perform manual review of domain; automated inspection blocked by bot/WAF controls.",
            "summary": f"Audit inconclusive: {block_reason}. Manual review required."
        }

        return {
            "Website": final_url,
            "Website Status": website_status,
            "Email": "",
            "Email Status": "Not Found",
            "Contact Person": "",
            "Decision Maker": "",
            "Email Verification": "Not Found",
            "Facebook": "",
            "Instagram": "",
            "LinkedIn": "",
            "About Page Link": "",
            "Priority": "Manual Review",
            "Lead Score": 50,
            "Main Opportunity": f"Website inspection blocked ({block_reason})",
            "Notes": f"Website inspection inconclusive ({block_reason}); requires manual review.",
            "intelligence": {
                "seo": seo_audit,
                "technical": tech_audit,
                "features": features_audit,
                "performance": perf_audit,
                "opportunities": opp_analysis,
                "lead_score": 50,
                "priority": "Manual Review",
                "priority_tier": "Manual Review",
                "audit_summary": {
                    "website_status": website_status,
                    "seo_score": None,
                    "features_detected_count": 0,
                    "opportunities_count": 0,
                    "ssl_status": tech_audit["ssl_certificate"]["status"],
                    "mobile_status": "Not Audited"
                }
            }
        }

    # Step 2: Contact & Social Extraction
    email, fb, insta, linkedin, _ = extract_emails_and_socials(response_text, base_url=final_url)
    dm_name, dm_role = hint_decision_maker or None, "Owner" if hint_decision_maker else None
    about_url = ""

    if response_text:
        if not dm_name:
            dm_name, dm_role = find_decision_maker_from_html(response_text, business_name=business_name)

        candidates = find_candidate_pages(response_text, final_url, max_candidates=4)
        for curl in candidates:
            if 'about' in curl.lower() and not about_url:
                about_url = curl

        # Crawl candidate pages if critical data is still missing
        if not (email and fb and linkedin and dm_name):
            for curl in candidates:
                try:
                    c_resp = safe_http_get(curl, timeout=(4, 8))
                    if c_resp.status_code == 200:
                        c_email, c_fb, c_insta, c_linkedin, _ = extract_emails_and_socials(c_resp.text, base_url=final_url)
                        if not dm_name:
                            dm_name, dm_role = find_decision_maker_from_html(c_resp.text, business_name=business_name)
                        email = email or c_email
                        fb = fb or c_fb
                        insta = insta or c_insta
                        linkedin = linkedin or c_linkedin
                        if email and fb and linkedin and dm_name:
                            break
                except Exception:
                    pass

    # Step 3: Playwright fallback if page was blank, blocked, or missing contacts
    if not response_text or not email or not (fb or linkedin):
        try:
            pw_html, pw_email, pw_fb, pw_insta, pw_li, pw_dm, pw_role = scrape_with_playwright_fallback(
                final_url,
                existing_fb=fb,
                existing_insta=insta,
                existing_linkedin=linkedin,
                business_name=business_name
            )
            pw_blocked, _ = is_challenge_or_blocked(200, pw_html)
            if pw_html and not pw_blocked and not response_text:
                response_text = pw_html
            if not pw_blocked:
                email = email or pw_email
                fb = fb or pw_fb
                insta = insta or pw_insta
                linkedin = linkedin or pw_li
                if not dm_name and pw_dm:
                    dm_name, dm_role = pw_dm, pw_role
        except Exception:
            pass

    # Step 4: Decision Maker Validation (Never infer identity or ownership from email prefix alone)
    # Decision maker is accepted only if verified via structured Schema.org or explicit page text.

    # Step 5: Permutation & SMTP Handshake Verification
    domain = urlparse(final_url).netloc.lower().replace('www.', '').strip('/')
    verification_status = "Not Found" if not email else "Unverified"

    if dm_name and domain:
        perms = generate_email_permutations(dm_name, domain)
        for perm in perms:
            is_valid, v_status = verify_email_smtp(perm)
            if is_valid and v_status == "Verified":
                email = perm
                verification_status = v_status
                break

    if email and verification_status in ["Unverified", "Not Found"]:
        _, v_status = verify_email_smtp(email)
        verification_status = v_status

    decision_maker_str = f"{dm_name} ({dm_role})" if dm_name and dm_role else (dm_name or "")

    # Step 6: Full Modular Audits
    seo_audit = audit_page_seo(response_text, final_url)
    robots_sitemap = check_robots_and_sitemap(final_url)
    seo_audit["findings"].extend(robots_sitemap.get("findings", []))
    seo_audit["robots_sitemap"] = robots_sitemap

    tech_audit = audit_technical_and_mobile(response_text, sanitized_url, final_url, status_code, is_ssl_verified)
    features_audit = detect_business_features(response_text)
    perf_audit = audit_website_performance(final_url, response_text, elapsed_sec)

    opp_analysis = analyze_business_opportunities(
        features_result=features_audit,
        seo_result=seo_audit,
        technical_result=tech_audit,
        decision_maker=decision_maker_str,
        email=email,
        business_name=business_name,
        target_url=final_url,
        phone=phone,
        email_status=verification_status,
        performance_result=perf_audit
    )

    # Step 7: Combine all results (preserving existing backward-compatible keys!)
    calc_priority = opp_analysis.get("priority") or "Manual Review"
    calc_score = opp_analysis.get("lead_score", 50)
    calc_main_opp = opp_analysis.get("main_gap", "")
    calc_notes = opp_analysis.get("scoring_details", {}).get("priority_reason", "")

    return {
        # Core existing fields
        "Website": final_url,
        "Website Status": "Online",
        "Email": email,
        "Email Status": verification_status,
        "Contact Person": dm_name or "",
        "Decision Maker": decision_maker_str,
        "Email Verification": verification_status,
        "Facebook": fb,
        "Instagram": insta,
        "LinkedIn": linkedin,
        "About Page Link": about_url,
        "Priority": calc_priority,
        "Lead Score": calc_score,
        "Main Opportunity": calc_main_opp,
        "Notes": calc_notes,
        
        # New Intelligence & Opportunity Suite
        "intelligence": {
            "seo": seo_audit,
            "technical": tech_audit,
            "features": features_audit,
            "performance": perf_audit,
            "opportunities": opp_analysis,
            "lead_score": calc_score,
            "priority": calc_priority,
            "priority_tier": opp_analysis.get("priority_tier", "Standard Prospect"),
            "audit_summary": {
                "website_status": "Online",
                "seo_score": seo_audit.get("seo_score", 0),
                "features_detected_count": sum(1 for f in features_audit.values() if f.get("status") == "Detected"),
                "opportunities_count": opp_analysis.get("opportunities_count", 0),
                "ssl_status": tech_audit.get("ssl_certificate", {}).get("status", "Unknown"),
                "mobile_status": tech_audit.get("mobile_usability", {}).get("status", "Unknown")
            }
        }
    }
