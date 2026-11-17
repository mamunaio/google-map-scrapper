"""
LeadHunter Google Maps Scraper Service
Supports both:
  1. Google Maps Search URLs (/maps/search/): multi-lead feed extraction with scrolling & deduplication
  2. Google Maps Place URLs (/maps/place/): single-lead detail panel extraction
Provides honest extraction validation (no empty phantom leads).
"""

import time
import re
import logging
from urllib.parse import urlparse, parse_qs, unquote
from playwright.sync_api import sync_playwright

from services.security import (
    SecurityError,
    validate_google_maps_url,
    is_safe_browser_url,
    is_google_maps_domain,
    is_authorized_maps_subresource_host,
    SafeBrowserProxy
)

logger = logging.getLogger("leadhunter.maps_scraper")

PHONE_REGEX = re.compile(r'(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}')

BENGALI_DIGITS = str.maketrans('০১২৩৪৫৬৭৮৯', '0123456789')

STATE_ABBRS = {
    'AL', 'AK', 'AZ', 'AR', 'CA', 'CO', 'CT', 'DE', 'FL', 'GA',
    'HI', 'ID', 'IL', 'IN', 'IA', 'KS', 'KY', 'LA', 'ME', 'MD',
    'MA', 'MI', 'MN', 'MS', 'MO', 'MT', 'NE', 'NV', 'NH', 'NJ',
    'NM', 'NY', 'NC', 'ND', 'OH', 'OK', 'OR', 'PA', 'RI', 'SC',
    'SD', 'TN', 'TX', 'UT', 'VT', 'VA', 'WA', 'WV', 'WI', 'WY', 'DC'
}

def normalize_rating(rating_raw) -> float | None:
    """Normalizes rating string/numeric into a float (0.0 to 5.0) or None."""
    if rating_raw is None or rating_raw == "":
        return None
    if isinstance(rating_raw, (int, float)):
        return float(rating_raw) if 0 <= rating_raw <= 5 else None
    s = str(rating_raw).translate(BENGALI_DIGITS).replace(',', '.').strip()
    m = re.search(r'\b([0-5](?:\.[0-9])?)\b', s)
    if m:
        try:
            val = float(m.group(1))
            if 0.0 <= val <= 5.0:
                return round(val, 1)
        except ValueError:
            pass
    return None

def normalize_review_count(reviews_raw) -> int | None:
    """Normalizes review count into an integer or None."""
    if reviews_raw is None or reviews_raw == "":
        return None
    if isinstance(reviews_raw, int):
        return reviews_raw
    if isinstance(reviews_raw, float):
        return int(reviews_raw)
    s = str(reviews_raw).translate(BENGALI_DIGITS).strip()
    s = re.sub(r'(?<=\d),(?=\d)', '', s)
    m = re.search(r'(?<!\.)\b(\d+)\b(?!\.)', s)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            pass
    return None

def parse_city_state(text: str) -> tuple[str, str]:
    """
    Extracts City and State from address strings.
    Returns ('Unknown', 'Unknown') if no reliable address components found.
    Never fabricates city or state.
    """
    if not text:
        return "Unknown", "Unknown"
    matches = re.findall(r'(?:[,\n·]\s*|^)([A-Za-z\s.-]+),\s*([A-Za-z]{2})\b(?:\s+\d{5})?', text)
    for city_cand, state_cand in reversed(matches):
        state_upper = state_cand.upper()
        if state_upper in STATE_ABBRS:
            city_clean = city_cand.strip().split('\n')[-1].split(',')[-1].split('·')[-1].strip()
            city_clean = re.sub(r'^\d+\s+[A-Za-z0-9\s.-]+?\s+(?=[A-Z][a-z])', '', city_clean).strip()
            if city_clean and len(city_clean) >= 2 and not any(ch.isdigit() for ch in city_clean):
                return city_clean, state_upper
    return "Unknown", "Unknown"

def extract_category_from_text(card_text: str) -> str:
    """Extracts business category from Google Maps card text lines."""
    if not card_text:
        return "Unknown"
    for line in card_text.split('\n'):
        if '·' in line:
            parts = [p.strip() for p in line.split('·') if p.strip()]
            for p in parts:
                if not re.search(r'^[0-5]\.[0-9]|^\(?\d+\)?|open|closed|\$|hours|am|pm|min|miles|\b[A-Z]{2}\b', p, re.IGNORECASE):
                    if len(p) >= 3 and not any(ch.isdigit() for ch in p):
                        return p
    return "Unknown"

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

GOOGLE_INTERNAL_DOMAINS = (
    'google.com', 'googleadservices.com', 'googlesyndication.com',
    'doubleclick.net', 'gstatic.com', 'googleapis.com', 'googleusercontent.com',
    'ggpht.com', 'goo.gl'
)

def is_google_internal_host(hostname: str) -> bool:
    """Checks whether a hostname belongs to Google internal services, ad networks, or Maps."""
    if not hostname:
        return False
    h = hostname.lower().strip('.')
    if is_google_maps_domain(h) or is_authorized_maps_subresource_host(h):
        return True
    for g_dom in GOOGLE_INTERNAL_DOMAINS:
        if h == g_dom or h.endswith('.' + g_dom):
            return True
    return False

def clean_external_website_url(url_str: str) -> str:
    """
    Extracts and sanitizes a valid external business website URL from Google Maps hrefs.
    - Extracts external targets from Google redirects (/url?q=...) and Google Ads (/aclk?...&adurl=...).
    - Unquotes URL-encoded destinations safely.
    - Rejects internal Google/Maps/Ads URLs, relative URLs, non-HTTP(S) schemes, localhost/private IPs, and empty links.
    - Returns a clean absolute URL (http:// or https://) or "" if invalid.
    """
    if not url_str or not isinstance(url_str, str):
        return ""

    s = url_str.strip()
    if not s or s.startswith(('#', 'javascript:', 'tel:', 'mailto:', 'data:')):
        return ""

    # Protocol-relative URLs: //example.com -> https://example.com
    if s.startswith('//'):
        s = 'https:' + s

    # Handle Google redirect or ad click URLs (both relative and absolute)
    is_redirect_or_ad = (
        s.startswith(('/url?', 'url?', '/aclk?', 'aclk?', '/pagead/aclk?')) or
        bool(re.search(r'^(?:https?://[^/]+)?/(?:url|aclk|pagead/aclk)\?', s, re.IGNORECASE))
    )

    if is_redirect_or_ad:
        try:
            query_str = s.split('?', 1)[1] if '?' in s else ''
            qs = parse_qs(query_str)
            # Check adurl (Google Ads /aclk), q (Google /url), and url parameters
            target = qs.get('adurl', [''])[0] or qs.get('q', [''])[0] or qs.get('url', [''])[0]
            if target:
                target = unquote(target.strip())
                # Recursively clean target in case of nested redirect wrappers
                return clean_external_website_url(target)
            else:
                # Ad or redirect link with no external destination
                return ""
        except Exception:
            return ""

    # Reject relative URLs without external target
    if s.startswith('/'):
        return ""

    # Validate scheme and host
    try:
        parsed = urlparse(s)
        scheme = (parsed.scheme or "").lower()
        if scheme not in ('http', 'https'):
            return ""

        hostname = (parsed.hostname or "").lower().strip('.')
        if not hostname or '.' not in hostname:
            return ""

        # Reject loopback, localhost, and metadata hosts
        if hostname in ('localhost', '127.0.0.1', '::1', '169.254.169.254'):
            return ""

        # Reject all Google internal, ad, or maps hosts
        if is_google_internal_host(hostname):
            return ""

        return s
    except Exception:
        return ""

# Backward-compatibility alias
clean_google_redirect_url = clean_external_website_url

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
            website = clean_external_website_url(raw_href)

        # 4. Text lines for Phone, Category, Location, and Rating
        card_text = card.inner_text()
        phone_match = PHONE_REGEX.search(card_text)
        phone = phone_match.group(0) if phone_match else ""

        # Rating
        rating_el = card.locator('span.MW4etd')
        rating_raw = rating_el.inner_text().strip() if rating_el.count() > 0 else ""
        rating = normalize_rating(rating_raw)

        # Reviews Count
        rev_el = card.locator('span.UY7F9')
        reviews_raw = rev_el.inner_text().strip().strip('()') if rev_el.count() > 0 else ""
        reviews = normalize_review_count(reviews_raw)

        if rating is None:
            rating = normalize_rating(card_text)
        if reviews is None:
            reviews = normalize_review_count(card_text)

        category = extract_category_from_text(card_text)
        city, state = parse_city_state(card_text)

        return {
            "Business Name": name,
            "Category": category,
            "City": city,
            "State": state,
            "Phone": phone,
            "Website": website,
            "Google Maps URL": place_url,
            "Rating": rating,
            "Reviews": reviews,
            "Contact Person": "",
            "Email": "",
            "Email Status": "Not Found",
            "Priority": "Manual Review",
            "Lead Score": 0,
            "Main Opportunity": "",
            "Notes": "",

            # Backward-compatibility aliases
            "Google Category": category,
            "Phone Number": phone,
            "Google Rating": rating if rating is not None else "",
            "Review Count": reviews if reviews is not None else "",
            "Google Maps Profile": place_url,
            "Decision Maker": "",
            "Email Verification": "Not Found",
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
    logger.info(f"[Maps Feed] Starting feed extraction (target: up to {max_results} listings)")
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

    logger.info(f"[Maps Feed] Extraction complete: collected {len(leads)} distinct lead(s)")
    return leads

def scrape_maps_place_detail(page, url: str) -> dict:
    """Extracts single place details from an individual Google Maps place page."""
    logger.info(f"[Maps Place] Extracting single place details for: {url}")
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
        website = clean_external_website_url(raw_href)

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
    rating_raw = ""
    rating_loc = page.locator('div.F7nice span[aria-hidden="true"], span.ceNzKf')
    if rating_loc.count() > 0:
        rating_raw = rating_loc.first.inner_text().strip()
    rating = normalize_rating(rating_raw)

    reviews_raw = ""
    rev_loc = page.locator('div.F7nice span span[aria-label*="review" i]')
    if rev_loc.count() > 0:
        reviews_raw = rev_loc.first.inner_text().strip().strip('()')
    reviews = normalize_review_count(reviews_raw)

    # 5. Category
    category = "Unknown"
    cat_loc = page.locator('button.DkEaL, button[jsaction*="category"], span.YhemCb')
    if cat_loc.count() > 0:
        category = cat_loc.first.inner_text().strip() or "Unknown"

    # 6. City and State
    city, state = "Unknown", "Unknown"
    addr_loc = page.locator('button[data-item-id="address"], button[aria-label*="Address" i]')
    if addr_loc.count() > 0:
        addr_text = addr_loc.first.inner_text().strip()
        city, state = parse_city_state(addr_text)

    # Fallback to page text for category / location if needed
    if city == "Unknown" or category == "Unknown":
        try:
            main_text = page.locator('div[role="main"]').inner_text()
            if city == "Unknown":
                city, state = parse_city_state(main_text)
            if category == "Unknown":
                category = extract_category_from_text(main_text)
        except Exception:
            pass

    return {
        "Business Name": name,
        "Category": category,
        "City": city,
        "State": state,
        "Phone": phone,
        "Website": website,
        "Google Maps URL": url,
        "Rating": rating,
        "Reviews": reviews,
        "Contact Person": "",
        "Email": "",
        "Email Status": "Not Found",
        "Priority": "Manual Review",
        "Lead Score": 0,
        "Main Opportunity": "",
        "Notes": "",

        # Backward-compatibility aliases
        "Google Category": category,
        "Phone Number": phone,
        "Google Rating": rating if rating is not None else "",
        "Review Count": reviews if reviews is not None else "",
        "Google Maps Profile": url,
        "Decision Maker": "",
        "Email Verification": "Not Found",
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
    Enforces SSRF prevention, Google domain whitelist, browser request interception,
    and network-level destination pinning via SafeBrowserProxy.
    Returns honest failure when no business data can be extracted.
    """
    clean_url = validate_google_maps_url(url)
    is_search = is_maps_search_url(clean_url)
    url_kind = "search query" if is_search else "place detail"
    logger.info(f"[Maps] Initiating Google Maps navigation ({url_kind}): {clean_url}")

    with SafeBrowserProxy() as proxy:
        with sync_playwright() as p:
            browser = None
            context = None
            page = None
            try:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    locale="en-US",
                    proxy={"server": f"http://127.0.0.1:{proxy.port}"},
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
                )
                page = context.new_page()

                # Enforce SSRF and unauthorized redirect/subresource protection at browser level
                page.route("**/*", create_playwright_route_interceptor(page))

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
                if page:
                    try:
                        page.close()
                    except Exception:
                        pass
                if context:
                    try:
                        context.close()
                    except Exception:
                        pass
                if browser:
                    try:
                        browser.close()
                    except Exception:
                        pass
