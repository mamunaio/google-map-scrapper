"""
LeadHunter Performance Audit Service
Integrates with Google PageSpeed Insights API (Core Web Vitals, mobile/desktop scores)
and provides local asset diagnostics when no API key is set. Never fabricates scores.
"""

import os
import time
from datetime import datetime, timezone
import requests
from bs4 import BeautifulSoup

PAGESPEED_API_URL = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"

def fetch_pagespeed_data(url: str, strategy: str = "mobile", api_key: str = None, timeout: int = 25):
    """
    Calls Google PageSpeed Insights API for a specific device strategy ('mobile' or 'desktop').
    """
    key = api_key or os.getenv("GOOGLE_PAGESPEED_API_KEY", "")
    params = {
        "url": url,
        "strategy": strategy,
        "category": "performance"
    }
    if key:
        params["key"] = key

    try:
        resp = requests.get(PAGESPEED_API_URL, params=params, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            lighthouse = data.get("lighthouseResult", {})
            categories = lighthouse.get("categories", {})
            perf = categories.get("performance", {})
            score = round(perf.get("score", 0) * 100) if perf.get("score") is not None else None

            audits = lighthouse.get("audits", {})

            # Extract Core Web Vitals
            lcp = audits.get("largest-contentful-paint", {}).get("displayValue")
            inp = audits.get("interaction-to-next-paint", {}).get("displayValue") or audits.get("max-potential-fid", {}).get("displayValue")
            cls = audits.get("cumulative-layout-shift", {}).get("displayValue")
            fcp = audits.get("first-contentful-paint", {}).get("displayValue")
            ttfb = audits.get("server-response-time", {}).get("displayValue")

            return {
                "success": True,
                "score": score,
                "core_web_vitals": {
                    "largest_contentful_paint": lcp,
                    "interaction_to_next_paint": inp,
                    "cumulative_layout_shift": cls,
                    "first_contentful_paint": fcp,
                    "time_to_first_byte": ttfb
                }
            }
        else:
            err_msg = f"HTTP {resp.status_code}: {resp.text[:120]}"
            return {"success": False, "error": err_msg}
    except Exception as e:
        return {"success": False, "error": str(e)}

def analyze_local_asset_diagnostics(html_text: str, elapsed_seconds: float = None):
    """
    Computes local asset diagnostics (payload size, script count, stylesheet count)
    to provide actionable performance context without fabricating fake Lighthouse scores.
    """
    soup = BeautifulSoup(html_text or "", 'html.parser')
    html_bytes = len(html_text.encode('utf-8')) if html_text else 0

    scripts = soup.find_all('script')
    stylesheets = soup.find_all('link', rel=lambda r: r and 'stylesheet' in r)
    images = soup.find_all('img')

    external_scripts = [s.get('src') for s in scripts if s.get('src')]
    inline_scripts = [s for s in scripts if not s.get('src')]

    diagnostics = {
        "html_size_kb": round(html_bytes / 1024, 1),
        "total_scripts": len(scripts),
        "external_scripts": len(external_scripts),
        "inline_scripts": len(inline_scripts),
        "total_stylesheets": len(stylesheets),
        "total_images": len(images),
        "local_response_time_ms": round(elapsed_seconds * 1000, 1) if elapsed_seconds else None
    }
    return diagnostics

def audit_website_performance(url: str, html_text: str = "", local_elapsed_sec: float = None, api_key: str = None):
    """
    Comprehensive performance audit:
    - Runs PageSpeed Insights if API key is present or requested.
    - Accurately tracks audit status, timestamp, Core Web Vitals, and local diagnostics.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    key = api_key or os.getenv("GOOGLE_PAGESPEED_API_KEY", "")

    local_diag = analyze_local_asset_diagnostics(html_text, local_elapsed_sec)

    if not key:
        return {
            "audit_status": "API Key Not Configured",
            "audit_timestamp": timestamp,
            "mobile_score": None,
            "desktop_score": None,
            "core_web_vitals": {},
            "source": "Local Asset Diagnostics",
            "local_diagnostics": local_diag,
            "note": "To enable official Google PageSpeed Insights & Core Web Vitals scoring, set the GOOGLE_PAGESPEED_API_KEY environment variable."
        }

    # Query Google PageSpeed Insights for Mobile & Desktop
    mobile_res = fetch_pagespeed_data(url, strategy="mobile", api_key=key)
    desktop_res = fetch_pagespeed_data(url, strategy="desktop", api_key=key)

    if mobile_res.get("success") or desktop_res.get("success"):
        return {
            "audit_status": "Complete",
            "audit_timestamp": timestamp,
            "mobile_score": mobile_res.get("score"),
            "desktop_score": desktop_res.get("score"),
            "core_web_vitals": mobile_res.get("core_web_vitals", {}),
            "source": "Google PageSpeed Insights API",
            "local_diagnostics": local_diag,
            "errors": {
                "mobile": mobile_res.get("error"),
                "desktop": desktop_res.get("error")
            } if (not mobile_res.get("success") or not desktop_res.get("success")) else None
        }
    else:
        return {
            "audit_status": "API Query Failed",
            "audit_timestamp": timestamp,
            "mobile_score": None,
            "desktop_score": None,
            "core_web_vitals": {},
            "source": "Google PageSpeed Insights API (Failed)",
            "local_diagnostics": local_diag,
            "error_details": mobile_res.get("error") or desktop_res.get("error")
        }
