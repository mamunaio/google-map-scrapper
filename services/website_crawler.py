"""
LeadHunter Unified Website Crawler & Intelligence Engine
Coordinates safe HTTP fetching, Playwright fallback, deep candidate crawling,
email/social extraction, technical audits, feature detection, and opportunity scoring.
"""

import time
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

from services.security import safe_http_get, validate_and_sanitize_url, SecurityError
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
    strictly within the same base domain.
    """
    candidate_urls = []
    if not html_text or not base_url:
        return candidate_urls

    try:
        base_domain = urlparse(base_url).netloc.lower().replace('www.', '')
        soup = BeautifulSoup(html_text, 'html.parser')
        keywords = ['contact', 'about', 'reach', 'touch', 'support', 'team', 'leadership', 'location', 'service']

        for a in soup.find_all('a', href=True):
            href = a.get('href', '').strip()
            text = a.get_text().strip().lower()
            if not href or href.startswith(('tel:', 'mailto:', 'javascript:', '#')):
                continue

            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)
            parsed_domain = parsed.netloc.lower().replace('www.', '')

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

def scrape_with_playwright_fallback(url: str, existing_fb: str = "", existing_insta: str = "", existing_linkedin: str = ""):
    """
    Headless Chromium rendering fallback for JavaScript-rendered SPAs (React, Vue, Wix, Webflow).
    """
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, timeout=12000, wait_until='domcontentloaded')
            time.sleep(0.5)

            try:
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                time.sleep(0.5)
            except Exception:
                pass

            html = page.content()
            email, fb, insta, linkedin, _ = extract_emails_and_socials(html, base_url=url)
            dm_name, dm_role = find_decision_maker_from_html(html)

            fb = fb or existing_fb
            insta = insta or existing_insta
            linkedin = linkedin or existing_linkedin

            # Crawl candidates if still missing info (bounded to 2 candidates, 8s timeout)
            if not (email and fb and linkedin and dm_name):
                candidate_links = find_candidate_pages(html, url, max_candidates=2)
                for curl in candidate_links:
                    try:
                        page.goto(curl, timeout=8000, wait_until='domcontentloaded')
                        c_html = page.content()
                        c_email, c_fb, c_insta, c_linkedin, _ = extract_emails_and_socials(c_html, base_url=url)
                        if not dm_name:
                            dm_name, dm_role = find_decision_maker_from_html(c_html)
                        email = email or c_email
                        fb = fb or c_fb
                        insta = insta or c_insta
                        linkedin = linkedin or c_linkedin
                        if email and fb and linkedin and dm_name:
                            break
                    except Exception:
                        pass

            browser.close()
            return html, email, fb, insta, linkedin, dm_name, dm_role
    except Exception as e:
        print(f"Playwright fallback error for {url}: {e}")
        return "", "", existing_fb, existing_insta, existing_linkedin, None, None

def crawl_and_audit_website(url: str, hint_decision_maker: str = "", business_name: str = ""):
    """
    Complete end-to-end audit:
    - SSRF protection & safe fetching
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
                final_url, existing_fb=fb, existing_insta=insta, existing_linkedin=linkedin
            )
            if pw_html and not response_text:
                response_text = pw_html
            email = email or pw_email
            fb = fb or pw_fb
            insta = insta or pw_insta
            linkedin = linkedin or pw_li
            if not dm_name and pw_dm:
                dm_name, dm_role = pw_dm, pw_role
        except Exception:
            pass

    # Step 4: Fallback to personal name extraction from email prefix
    if not dm_name and email:
        extracted = extract_name_from_email_prefix(email)
        if extracted:
            dm_name = extracted
            dm_role = "Business Owner"

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
        target_url=final_url
    )

    # Step 7: Combine all results (preserving existing backward-compatible keys!)
    return {
        # Core existing fields
        "Website": final_url,
        "Email": email,
        "Email Status": verification_status,
        "Contact Person": dm_name or "",
        "Decision Maker": decision_maker_str,
        "Email Verification": verification_status,
        "Facebook": fb,
        "Instagram": insta,
        "LinkedIn": linkedin,
        "About Page Link": about_url,
        
        # New Intelligence & Opportunity Suite
        "intelligence": {
            "seo": seo_audit,
            "technical": tech_audit,
            "features": features_audit,
            "performance": perf_audit,
            "opportunities": opp_analysis,
            "lead_score": opp_analysis.get("lead_score", 50),
            "priority_tier": opp_analysis.get("priority_tier", "Standard Prospect"),
            "audit_summary": {
                "seo_score": seo_audit.get("seo_score", 0),
                "features_detected_count": sum(1 for f in features_audit.values() if f.get("status") == "Detected"),
                "opportunities_count": opp_analysis.get("opportunities_count", 0),
                "ssl_status": tech_audit.get("ssl_certificate", {}).get("status", "Unknown"),
                "mobile_status": tech_audit.get("mobile_usability", {}).get("status", "Unknown")
            }
        }
    }
