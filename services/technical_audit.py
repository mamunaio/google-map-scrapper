"""
LeadHunter Technical Audit & Mobile Usability Module
Inspects SSL certificate health, redirect chains, canonical consistency,
and nuanced mobile usability without false claims.
"""

import ssl
import socket
import certifi
from datetime import datetime, timezone
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import re

def inspect_ssl_certificate(hostname: str, port: int = 443, timeout: int = 4):
    """
    Connects to the server over SSL and extracts expiration, issuer, and days remaining.
    Uses certifi CA bundle with strict certificate verification and preserves the original hostname for SNI.
    """
    if not hostname:
        return {"status": "Unknown", "evidence": "No hostname provided"}

    clean_host = hostname.strip().lower().split(':')[0]
    context = ssl.create_default_context(cafile=certifi.where())

    try:
        with socket.create_connection((clean_host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=clean_host) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return {"status": "Warning", "evidence": "No peer certificate returned"}

                # Expiration parsing
                not_after_str = cert.get('notAfter')
                if not_after_str:
                    # Format: 'May 20 12:00:00 2026 GMT'
                    expiry_date = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                    days_remaining = (expiry_date - datetime.now(timezone.utc)).days

                    issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                    issuer_org = issuer_dict.get('organizationName', issuer_dict.get('commonName', 'Unknown Issuer'))

                    is_expired = days_remaining <= 0
                    is_expiring_soon = 0 < days_remaining <= 30

                    return {
                        "status": "Expired" if is_expired else ("Expiring Soon" if is_expiring_soon else "Valid"),
                        "days_remaining": days_remaining,
                        "expiry_date": expiry_date.strftime('%Y-%m-%d'),
                        "issuer": issuer_org,
                        "evidence": f"Issuer: {issuer_org}, Expires: {expiry_date.strftime('%Y-%m-%d')} ({days_remaining} days left)"
                    }
    except ssl.SSLCertVerificationError as e:
        return {"status": "Invalid", "days_remaining": 0, "evidence": f"SSL Verification Failed: {e}"}
    except Exception as e:
        return {"status": "Check Failed", "evidence": f"Could not inspect SSL on port {port}: {e}"}

def audit_technical_and_mobile(html_text: str, current_url: str, final_url: str, status_code: int, is_ssl_verified: bool):
    """
    Evaluates technical infrastructure, HTTPS, redirect behavior, and mobile usability indicators.
    """
    findings = []
    parsed_curr = urlparse(current_url)
    parsed_final = urlparse(final_url)

    # 1. HTTPS and SSL evaluation
    uses_https = parsed_final.scheme == 'https'
    if not uses_https:
        findings.append({
            "name": "Website Not Using HTTPS Encryption",
            "severity": "High",
            "affected_url": final_url,
            "evidence": f"Protocol is plain HTTP ({final_url}).",
            "explanation": "Modern browsers mark non-HTTPS websites as 'Not Secure', damaging visitor trust and local conversion rates.",
            "suggested_improvement": "Install an SSL certificate and configure an automated 301 redirect from HTTP to HTTPS.",
            "detection_method": "URL Scheme & Protocol Inspection"
        })

    ssl_info = {"status": "Plain HTTP", "evidence": "Site does not use HTTPS"}
    if uses_https:
        ssl_info = inspect_ssl_certificate(parsed_final.hostname or parsed_curr.hostname)
        if ssl_info.get("status") == "Expired":
            findings.append({
                "name": "SSL Certificate Expired",
                "severity": "High",
                "affected_url": final_url,
                "evidence": ssl_info.get("evidence", "Certificate is past its expiration date."),
                "explanation": "An expired certificate triggers full-screen browser security warnings that deter virtually all potential clients.",
                "suggested_improvement": "Immediately renew or reinstall the SSL certificate with your domain registrar or host.",
                "detection_method": "TLS Handshake Inspection"
            })
        elif ssl_info.get("status") == "Expiring Soon":
            findings.append({
                "name": "SSL Certificate Expiring Soon",
                "severity": "Medium",
                "affected_url": final_url,
                "evidence": ssl_info.get("evidence"),
                "explanation": "The SSL certificate expires in less than 30 days and needs renewal to prevent security warnings.",
                "suggested_improvement": "Set up automated certificate renewal (e.g. Let's Encrypt / Certbot).",
                "detection_method": "TLS Handshake Inspection"
            })

    # 2. Redirect behavior
    has_redirect = (current_url.rstrip('/') != final_url.rstrip('/'))
    redirect_info = {
        "initial_url": current_url,
        "final_url": final_url,
        "redirect_occurred": has_redirect,
        "status_code": status_code
    }

    # 3. Mobile Usability Evaluation
    # Explicit rule: Do not claim that a website is mobile-friendly based only on the presence of a viewport tag!
    soup = BeautifulSoup(html_text or "", 'html.parser')

    viewport_tag = soup.find('meta', attrs={'name': re.compile(r'^viewport$', re.IGNORECASE)})
    has_viewport = bool(viewport_tag and viewport_tag.get('content'))
    viewport_content = viewport_tag.get('content', '') if viewport_tag else ""

    # Check for responsive CSS indicators
    responsive_indicators = []
    if 'width=device-width' in viewport_content.lower():
        responsive_indicators.append("Device-width viewport configuration")
    if 'initial-scale=1' in viewport_content.lower():
        responsive_indicators.append("Initial-scale zoom initialization")

    # Search styles for media queries
    styles_text = " ".join([s.get_text() for s in soup.find_all('style')])
    has_media_queries = bool(re.search(r'@media\s*\([^{]+\)', styles_text))
    if has_media_queries:
        responsive_indicators.append("Embedded CSS media queries")

    # Framework responsive cues (Tailwind, Bootstrap, Flexbox, Grid)
    html_sample = (html_text or "")[:40000].lower()
    if any(fw in html_sample for fw in ['bootstrap', 'tailwind', 'flex', 'grid', 'col-sm-', 'col-md-', 'w-full', 'max-w-']):
        responsive_indicators.append("Responsive layout utility classes")

    # Horizontal overflow risk checks (fixed wide pixel widths like width="1200" or style="width: 1400px")
    fixed_wide_elements = re.findall(r'(?:width|min-width)\s*[:=]\s*["\']?\s*([1-9]\d{3,4})\s*(?:px)?["\']?', html_sample)
    overflow_risk = len(fixed_wide_elements) > 0

    if not has_viewport:
        findings.append({
            "name": "Missing Viewport Meta Tag",
            "severity": "High",
            "affected_url": final_url,
            "evidence": "No <meta name='viewport'> tag detected.",
            "explanation": "Without a viewport tag, mobile devices render the page as a desktop screen, forcing users to pinch and zoom.",
            "suggested_improvement": "Add <meta name='viewport' content='width=device-width, initial-scale=1.0'> to the HTML head.",
            "detection_method": "DOM Head Parser"
        })
    elif overflow_risk:
        findings.append({
            "name": "Potential Mobile Horizontal Overflow",
            "severity": "Medium",
            "affected_url": final_url,
            "evidence": f"Found fixed width definitions exceeding 1000px ({fixed_wide_elements[:2]}).",
            "explanation": "Hardcoded pixel widths can exceed smartphone screen widths, causing awkward horizontal scrolling.",
            "suggested_improvement": "Replace fixed pixel widths with relative percentages or responsive CSS (max-width: 100%).",
            "detection_method": "CSS Dimension Scanner"
        })

    # Nuanced mobile readiness status
    if not has_viewport:
        mobile_status = "Poor (No Viewport)"
    elif len(responsive_indicators) >= 2 and not overflow_risk:
        mobile_status = "Optimized (Viewport & Responsive Structure Detected)"
    elif has_viewport and not overflow_risk:
        mobile_status = "Standard (Viewport configured, basic layout)"
    else:
        mobile_status = "Needs Improvement (Responsive warnings detected)"

    return {
        "ssl_certificate": ssl_info,
        "redirect_info": redirect_info,
        "mobile_usability": {
            "status": mobile_status,
            "has_viewport": has_viewport,
            "viewport_content": viewport_content,
            "responsive_indicators": responsive_indicators,
            "overflow_risk": overflow_risk
        },
        "findings": findings
    }
