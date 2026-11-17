"""
LeadHunter Google Maps Scraper Service
Supports both:
  1. Google Maps Search URLs (/maps/search/): multi-lead feed extraction with scrolling & deduplication
  2. Google Maps Place URLs (/maps/place/): single-lead detail panel extraction
Provides honest extraction validation (no empty phantom leads).
"""

import time
import re
from urllib.parse import urlparse, parse_qs, unquote
from playwright.sync_api import sync_playwright

from services.security import (
    SecurityError,
    validate_google_maps_url,
    is_safe_browser_url,
    is_google_maps_domain
)

PHONE_REGEX = re.compile(r'(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}')

def is_maps_search_url(url: str) -> bool:
    """Detects whether a URL is a Google Maps search results query URL."""
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        if not is_google_maps_domain(hostname):
            return False
        path = parsed.path.lower()
        query = parsed.query.lower()
        return ("/maps/search" in path or
                path.startswith("/search") or
                ("maps" in hostname and (query.startswith("q=") or "&q=" in query) and "/place/" not in path))
    except Exception:
        return False

def create_playwright_route_interceptor(page=None):
    """
    Creates a Playwright route interceptor that verifies every outgoing request,
    redirect, and subresource against strict SSRF and Google authorization policies.
    """
    def route_interceptor(route):
        request = route.request
        req_url = request.url

        # Check if this is a main document navigation request
        is_main = False
        try:
            if hasattr(request, 'is_navigation_request') and callable(request.is_navigation_request):
                if request.is_navigation_request():
                    if page and hasattr(page, 'main_frame'):
                        is_main = (request.frame == page.main_frame)
                    else:
                        is_main = True
        except Exception:
            is_main = False

        is_safe, reason = is_safe_browser_url(req_url, is_main_document=is_main)
        if not is_safe:
            try:
                route.abort("blockedbyclient")
            except Exception:
                pass
            return

        try:
            route.continue_()
        except Exception:
            pass

    return route_interceptor

def normalize_place_url(raw_url: str) -> str:
    """Normalizes a Google Maps place URL for stable deduplication."""
    if not raw_url:
        return ""
    try:
        parsed = urlparse(raw_url)
        # Retain clean path without transient tracking params
        clean_path = parsed.path.rstrip('/')
        return f"{parsed.netloc}{clean_path}".lower()
    except Exception:
        return raw_url.strip().lower()

def clean_google_redirect_url(url_str: str) -> str:
    """Extracts external target website from Google redirect links (/url?q=...)."""
    if not url_str:
        return ""
    if url_str.startswith('/url?q='):
        qs = parse_qs(urlparse(url_str).query)
        target = qs.get('q', [''])[0]
        return unquote(target)
    return url_str.strip()

def extract_search_listing_card(card) -> dict:
    """Extracts business data from a single div.Nv2PK listing card in search feed."""
    try:
        # 1. Business Name
        name_el = card.locator('div.qBF1Pd')
        name = name_el.inner_text().strip() if name_el.count() > 0 else ""
        if not name:
            link_el = card.locator('a.hfpxzc')
            if link_el.count() > 0:
                name = (link_el.first.get_attribute('aria-label') or '').strip()

        # 2. Place URL
        link_el = card.locator('a.hfpxzc')
        place_url = ""
        if link_el.count() > 0:
            place_url = link_el.first.get_attribute('href') or ""

        # 3. Website
        web_el = card.locator('a.lcr4fd, a[data-value*="Website" i], a[aria-label*="website" i]')
        website = ""
        if web_el.count() > 0:
            raw_href = web_el.first.get_attribute('href') or ""
            website = clean_google_redirect_url(raw_href)

        # 4. Text lines for Phone, Category, and Rating
        card_text = card.inner_text()
        phone_match = PHONE_REGEX.search(card_text)
        phone = phone_match.group(0) if phone_match else ""

        # Rating
        rating_el = card.locator('span.MW4etd')
        rating = rating_el.inner_text().strip() if rating_el.count() > 0 else ""

        # Reviews Count
        rev_el = card.locator('span.UY7F9')
        reviews = rev_el.inner_text().strip().strip('()') if rev_el.count() > 0 else ""

        return {
            "Business Name": name,
            "Phone Number": phone,
            "Website": website,
            "Rating": rating,
            "Review Count": reviews,
            "Google Maps Profile": place_url,
            "Decision Maker": "",
            "Email": "",
            "Email Verification": "Unverified",
            "Facebook": "",
            "Instagram": "",
            "LinkedIn": "",
            "About Page Link": "",
            "Source URL": place_url or ""
        }
    except Exception as e:
        print(f"Error extracting search card: {e}")
        return None

def scrape_maps_search_feed(page, max_results: int = 20) -> list[dict]:
    """Scrolls and extracts multiple distinct businesses from Google Maps search feed."""
    leads = []
    seen_identities = set()

    # Wait for feed or listing cards
    try:
        page.wait_for_selector('div[role="feed"], div.Nv2PK', timeout=15000)
    except Exception:
        pass

    feed = page.locator('div[role="feed"]')
    has_feed = feed.count() > 0

    # Perform bounded scrolls to load additional listings
    scroll_attempts = 0
    max_scrolls = 4 if max_results > 10 else 2

    while scroll_attempts < max_scrolls:
        cards = page.locator('div.Nv2PK').all()
        for card in cards:
            if len(leads) >= max_results:
                break

            lead = extract_search_listing_card(card)
            if not lead or not lead.get("Business Name"):
                continue

            # Deduplicate by normalized place URL or business name + phone
            identity = normalize_place_url(lead.get("Google Maps Profile")) or f"{lead['Business Name'].lower()}:{lead['Phone Number']}"
            if identity in seen_identities:
                continue

            seen_identities.add(identity)
            leads.append(lead)

        if len(leads) >= max_results or not has_feed:
            break

        # Scroll feed down
        try:
            page.mouse.wheel(0, 3000)
            time.sleep(1.2)
        except Exception:
            break
        scroll_attempts += 1

    return leads

def scrape_maps_place_detail(page, url: str) -> dict:
    """Extracts single place details from an individual Google Maps place page."""
    try:
        page.wait_for_selector('h1.DUwDvf, div[role="main"]', timeout=15000)
    except Exception:
        pass

    # 1. Business Name
    name = ""
    name_loc = page.locator('h1.DUwDvf')
    if name_loc.count() > 0:
        name = name_loc.first.inner_text().strip()

    # 2. Website Authority Link
    website = ""
    web_loc = page.locator('a[data-item-id="authority"], a[aria-label*="website" i]')
    if web_loc.count() > 0:
        raw_href = web_loc.first.get_attribute('href') or ""
        website = clean_google_redirect_url(raw_href)

    # 3. Phone Number
    phone = ""
    phone_loc = page.locator('button[data-tooltip*="Copy phone number" i], button[data-item-id*="phone" i], button[aria-label*="Phone" i]')
    if phone_loc.count() > 0:
        raw_phone = phone_loc.first.inner_text().strip()
        m = PHONE_REGEX.search(raw_phone)
        phone = m.group(0) if m else raw_phone
    if not phone:
        # Fallback to page text search
        try:
            body_text = page.locator('div[role="main"]').inner_text()
            m = PHONE_REGEX.search(body_text)
            if m:
                phone = m.group(0)
        except Exception:
            pass

    # 4. Rating & Reviews
    rating = ""
    rating_loc = page.locator('div.F7nice span[aria-hidden="true"], span.ceNzKf')
    if rating_loc.count() > 0:
        rating = rating_loc.first.inner_text().strip()

    reviews = ""
    rev_loc = page.locator('div.F7nice span span[aria-label*="review" i]')
    if rev_loc.count() > 0:
        reviews = rev_loc.first.inner_text().strip().strip('()')

    return {
        "Business Name": name,
        "Phone Number": phone,
        "Website": website,
        "Rating": rating,
        "Review Count": reviews,
        "Google Maps Profile": url,
        "Decision Maker": "",
        "Email": "",
        "Email Verification": "Unverified",
        "Facebook": "",
        "Instagram": "",
        "LinkedIn": "",
        "About Page Link": "",
        "Source URL": url
    }

def scrape_google_maps(url: str, max_results: int = 20) -> dict:
    """
    Main entry point for Google Maps scraping.
    Handles both Search URLs (multi-lead) and Place URLs (single-lead).
    Enforces SSRF prevention, Google domain whitelist, and browser request interception.
    Returns honest failure when no business data can be extracted.
    """
    clean_url = validate_google_maps_url(url)
    is_search = is_maps_search_url(clean_url)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            locale="en-US",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
        )
        page = context.new_page()

        # Enforce SSRF and unauthorized redirect/subresource protection at browser level
        page.route("**/*", create_playwright_route_interceptor(page))

        try:
            try:
                page.goto(clean_url, timeout=45000, wait_until="domcontentloaded")
            except Exception as e:
                err_str = str(e)
                if "BLOCKED_BY_CLIENT" in err_str or "net::ERR_" in err_str or "blocked" in err_str.lower():
                    raise SecurityError(f"Navigation was blocked by security policy: {err_str}")
                raise

            time.sleep(2.0)

            # Dismiss Google consent dialog if encountered
            try:
                consent_btn = page.locator('button:has-text("Accept all"), form[action*="consent"] button')
                if consent_btn.count() > 0:
                    consent_btn.first.click()
                    time.sleep(1.0)
            except Exception:
                pass

            if is_search:
                leads = scrape_maps_search_feed(page, max_results=max_results)
                if not leads:
                    return {
                        "success": False,
                        "error": "No business listings found at the provided Google Maps search URL.",
                        "leads": [],
                        "count": 0,
                        "is_search": True
                    }
                return {
                    "success": True,
                    "leads": leads,
                    "count": len(leads),
                    "is_search": True,
                    "data": leads[0]
                }
            else:
                lead = scrape_maps_place_detail(page, clean_url)
                if not lead or (not lead.get("Business Name") and not lead.get("Website")):
                    return {
                        "success": False,
                        "error": "No business details found at the provided Google Maps place URL.",
                        "leads": [],
                        "count": 0,
                        "is_search": False,
                        "data": None
                    }
                return {
                    "success": True,
                    "leads": [lead],
                    "count": 1,
                    "is_search": False,
                    "data": lead
                }
        finally:
            page.close()
            context.close()
            browser.close()
