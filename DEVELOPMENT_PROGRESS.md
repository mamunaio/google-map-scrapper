# LeadHunter Studio - Development Progress Tracker
**Project:** Lead Intelligence & Business Opportunity Detection Platform  
**Repository:** https://github.com/mamunaio/google-map-scrapper  
**Status:** In Active Development (Phased Evolution)

---

## Phase Overview & Roadmap

| Phase | Description | Status | Test Coverage |
| :--- | :--- | :--- | :--- |
| **Phase 01** | Existing System Stabilization, SSRF & Security, SMTP Rigor | **COMPLETED & VERIFIED** | 6 Security & 6 Email Tests Passing |
| **Phase 02** | Website Intelligence Engine (SSL, Canonical, Mobile, PageSpeed) | **COMPLETED & VERIFIED** | Unit & Live Integration Tested |
| **Phase 03** | SEO & Technical Audit (On-Page, Schema, Sitemap, Robots, Broken Links) | **COMPLETED & VERIFIED** | 3 SEO Tests Passing |
| **Phase 04** | Business Feature Detection Engine (7 Provider Registries) | **COMPLETED & VERIFIED** | 7 Feature Tests Passing |
| **Phase 05** | Business Opportunity Analyzer (9-Field Strict Schema, Real Evidence) | **COMPLETED & VERIFIED** | 1 Opportunity Schema Test Passing |
| **Phase 06** | Lead Scoring Engine (9 Configurable Dimensions = 100 Pts) | **COMPLETED & VERIFIED** | 5 Scoring Matrix Tests Passing |
| **Phase 07** | Dashboard & Selective Export (7 Metrics, Row Select, Dual Buttons) | **COMPLETED & VERIFIED** | UI Verified & API Tests Passing |
| **Phase 08** | Dual Export Engine (Format A Source-Preserved + Format B 3-Sheet) | **COMPLETED & VERIFIED** | 3 OpenPyXL Dual-Format Tests Passing |

---

## Detailed Phase Status & Changelog

### Phase 01: Existing System Stabilization & Security
- **Tasks Completed:**
  - Audited backend architecture; extracted monolithic code from `app.py` into modular `services/`.
  - Implemented `services/security.py` with strict SSRF protection (blocks `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, IPv6 loopback/link-local).
  - Enforced socket-level DNS rebinding protection via IP pinning, max response body limits (5 MB), and safe redirect checking on every hop.
  - Separated email verification statuses: `Valid (SMTP Verified)`, `Valid (Catch-All)`, `Valid (MX Only)`, `Invalid (Mailbox Not Found)`, `Invalid (No MX Record)`.
  - Added explicit `dnspython` to `requirements.txt`.
- **Files Changed:** `services/security.py`, `services/email_service.py`, `requirements.txt`, `app.py`.
- **Tests Executed:** `tests/test_security.py`, `tests/test_email_service.py`.
- **Test Results:** 12 unit tests passing.

---

### Phase 02: Website Intelligence Engine
- **Tasks Completed:**
  - Implemented `services/technical_audit.py` with TLS socket handshake to inspect SSL certificate validity, issuer, and days remaining.
  - Built nuanced mobile usability detection (viewport configuration, CSS media queries, responsive class indicators, and horizontal overflow checks). Avoids false "mobile friendly" claims based solely on viewport tag.
  - Built `services/performance_audit.py` with Google PageSpeed Insights API integration (LCP, INP, CLS, FCP, TTFB) and fallback local asset diagnostics without score fabrication.
- **Files Changed:** `services/technical_audit.py`, `services/performance_audit.py`, `services/website_crawler.py`.
- **Tests Executed:** Unit and live integration checks.

---

### Phase 03: SEO & Technical Audit
- **Tasks Completed:**
  - Built `services/seo_audit.py` analyzing title length, meta description length, single H1 validation, heading structure, canonical URL, robots meta tags, XML sitemap, and robots.txt.
  - Image alt coverage calculation (total images, missing alt count, coverage ratio).
  - JSON-LD / Schema.org structured data detection and Open Graph metadata parser.
  - Bounded broken internal link verification (HEAD/GET probe on up to 3 internal links, 3s timeout) safely reporting count.
  - Formatted findings with Name, Severity, Affected URL, Evidence, Explanation, Suggested Improvement, Detection Method.
- **Files Changed:** `services/seo_audit.py`.
- **Tests Executed:** `tests/test_seo_audit.py`.

---

### Phase 04: Business Feature Detection Engine
- **Tasks Completed:**
  - Built extensible signature registry in `services/business_feature_detector.py` covering:
    1. Lead Capture (Forms, Quote requests, `tel:`, `mailto:`, prominent CTAs)
    2. Booking & Appointment (Calendly, Acuity, Setmore, Square, Housecall Pro, Jobber, ServiceTitan, etc.)
    3. Live Chat & Chatbots (Intercom, Drift, Tidio, Zendesk, LiveChat, Crisp, ManyChat, HubSpot, etc.)
    4. AI Voice Agents (Bland AI, Vapi, Retell AI, Air AI, Synthflow, Dialpad AI, etc.)
    5. CRM & Lead Management (HubSpot, GoHighLevel, Salesforce, Zoho, ActiveCampaign, Keap, Pipedrive, etc.)
    6. Review Management (Birdeye, Podium, Trustpilot, Google Reviews widgets, Yelp, etc.)
    7. Marketing & Analytics (GA4, GTM, Meta Pixel, Hotjar, Klaviyo, Mailchimp, etc.)
  - Distinguishes 4 explicit statuses: `Detected`, `Not Detected`, `Unknown`, `Scan Failed`.
  - Disclaims that missing script/DOM evidence does not prove business absence.
- **Files Changed:** `services/business_feature_detector.py`.
- **Tests Executed:** `tests/test_feature_detector.py`.

---

### Phase 05: Business Opportunity Analyzer
- **Tasks Completed:**
  - Enforced strict 9-field Opportunity record schema:
    1. `Business Name`
    2. `Opportunity Category`
    3. `Related Finding`
    4. `Evidence URL`
    5. `Evidence Description`
    6. `Potential Business Impact`
    7. `Recommended Service`
    8. `Confidence Level` (`High`, `Medium`, `Low`)
    9. `Research Status` (`Identified`, `Verified`, `Needs Review`)
  - Purged all unsupported conversion claims (e.g., "25-30% booking lift", "guaranteed top 3 Google rank").
  - Tied every opportunity strictly to observable DOM or HTTP evidence.
- **Files Changed:** `services/opportunity_analyzer.py`, `services/website_crawler.py`.
- **Tests Executed:** `tests/test_opportunity_analyzer.py`.

---

### Phase 06: Dedicated Lead Scoring Engine
- **Tasks Completed:**
  - Created `services/lead_scoring.py` with 9 configurable dimensions totaling exactly 100 points:
    1. `website_performance` (10 pts)
    2. `technical_seo` (15 pts)
    3. `lead_capture` (15 pts)
    4. `booking_automation` (15 pts)
    5. `chatbot_voice` (10 pts)
    6. `business_relevance` (10 pts)
    7. `contact_availability` (10 pts)
    8. `decision_maker_availability` (10 pts)
    9. `mobile_ssl_security` (5 pts)
  - Removed arbitrary baseline (+30 pts); score evaluates actual evidence from 0 to 100.
  - Weight normalization ensures total is always 100 even with custom overrides.
  - Standard Priority Tiers: `High Priority` (>=68), `Medium Priority` (45-67), `Low Priority` (<45), `Manual Review` (unreachable/failed audit).
- **Files Changed:** `services/lead_scoring.py`, `services/opportunity_analyzer.py`.
- **Tests Executed:** `tests/test_lead_scoring.py`.

---

### Phase 07: Dashboard UI & Selective Export
- **Tasks Completed:**
  - Added 7 live summary metrics to the dashboard header:
    1. Total Leads
    2. High Priority Leads
    3. Missing Booking Systems
    4. Missing Lead Capture
    5. SEO Improvement Gaps
    6. Verified Decision Makers
    7. Valid Contact Emails
  - Added row-level selection checkboxes with "Select All" and live counter badge (`X Selected`).
  - Added dual export buttons:
    - `Export Format A (Preserve Source CSV/Excel)`
    - `Export Format B (Standard 3-Sheet Workbook)`
- **Files Changed:** `templates/index.html`.
- **Tests Executed:** `tests/test_api.py`.

---

### Phase 08: Dual-Format Excel Export Engine
- **Tasks Completed:**
  - Implemented `services/export_service.py` supporting two distinct export contracts:
    - **Format A (`generate_source_compatible_excel`):**
      - Preserves all 22+ original uploaded columns in exact order and values.
      - Preserves duplicate rows without deduplicating uploaded data.
      - Appends enrichment columns (`Research Priority`, `Research Score`, `Main Opportunity Gap`, etc.).
    - **Format B (`generate_standard_intelligence_workbook`):**
      - Generates exactly 3 sheets:
        1. `Lead Tracker`: exactly 15 columns.
        2. `Website Audit`: exactly 18 columns.
        3. `Business Opportunities`: exactly 10 columns.
      - Professional styling: frozen header rows (`A2`), auto-filters on all tables, color-coded priority fills, auto-fit column widths, and clickable website links.
  - Updated API `/api/export-excel` to accept `format_type: "standard_3_sheet"` or `"source_compatible"`.
- **Files Changed:** `services/export_service.py`, `app.py`.
- **Tests Executed:** `tests/test_export_service.py`.

---

---

### Targeted Code Review Fixes (Post-Phase 08 Hardening)
- **Issue 1: Unknown & Incomplete Audit Scoring Fixes (`services/lead_scoring.py`):**
  - Explicit handling for `Unknown`, `Scan Failed`, missing, and incomplete audit data without penalizing or treating missing scripts as proof of absence.
  - Neutral confidence scoring applied for incomplete dimensions (e.g. 5.0/10 pts) without logging unverified gaps.
  - Dimension-level explanations added in `dimension_explanations` for all 9 scoring dimensions.
  - Preserved priority labels: `High Priority`, `Medium Priority`, `Low Priority`, and `Manual Review` for failed/insufficient data.
  - Added 10 dedicated regression tests in `tests/test_lead_scoring.py`.
- **Issue 2: Verified DNS Rebinding, Proxy Hardening & Live Requests Path Verification (`services/security.py`):**
  - Confirmed `urllib3` (v2.8.0) and `requests` (v2.34.2) connection execution path: `requests.Session.get()` -> `HTTPAdapter.send()` -> `HTTPConnectionPool.urlopen()` -> `HTTPConnection._new_conn()` -> `urllib3.util.connection.create_connection`.
  - Verified that `urllib3.util.connection.create_connection` and `urllib3.connection.connection.create_connection` directly reference `_safe_create_connection`.
  - Added `SafeHTTPAdapter` for adapter-level URL pre-validation on all session requests.
  - Disabled environment proxy inheritance (`session.trust_env = False`) in `safe_http_get()` so `HTTP_PROXY` and `HTTPS_PROXY` cannot be used to bypass SSRF / rebinding filters.
  - Guaranteed resource cleanup: redirect response sockets are closed before advancing hops, stream sockets are closed in `finally`, and `session.close()` is executed on lifecycle completion.
  - Integration tests verified live `requests.Session.get()` blocking DNS rebinding to localhost (`127.0.0.1`), metadata (`169.254.169.254`), private IPv4 (`10.0.0.1`), and IPv6 link-local (`fe80::1`) before any socket connection.
  - Verified that public destinations connect directly to pinned IP addresses without secondary DNS lookup.
- **Issue 3: Unsupported Fallback Opportunities Removed (`services/export_service.py`):**
  - Completely removed automatic fallback entries ("General Optimization", "Maintenance / Retainer").
  - When no verified opportunities exist, outputs neutral status row: `No Verified Opportunity Identified` with `No Verified Gap` status (never falsely labeling leads as "Verified"), and `N/A` for impact, recommended service, and confidence.
  - Preserved strict 3-sheet Format B structure (15 cols, 18 cols, 10 cols) and Format A 22+ source column preservation.
  - Added 8 regression tests in `tests/test_export_service.py`.

---

## Acceptance Test Summary
- Total Automated Regression Tests: **59 Tests**
- Pass Rate: **100% (59/59 passing)**
- Execution Time: ~2.28s
- Security Verification: Live Requests & urllib3 integration tests for DNS rebinding, localhost, cloud metadata, private IPv4/IPv6, link-local, proxy bypass prevention (trust_env=False), public proxy isolation, redirect SSRF, TLS failure, and 5MB size limits.
- Backward Compatibility: Original Google Maps crawler, CSV/Excel upload, email extraction, and original 22+ columns completely preserved.

---

## Phase 09: Google Maps Scraper Fix (Search URLs + Place URLs + Honest Validation)

### 1. Root Cause Identification
- Previous scraper relied exclusively on single-place DOM selectors (`h1.DUwDvf`, `a[data-item-id="authority"]`, etc.) which fail on Google Maps Search URLs (`/maps/search/` or queries with listing cards in `div.Nv2PK`).
- When search URLs returned 0 place details, `app.py` previously returned an empty record with `success: True`, causing the frontend to report 100% success and display blank phantom leads.

### 2. Implementation Overview
- **Dedicated Maps Scraper (`services/maps_scraper.py`):**
  - `is_maps_search_url()`: Identifies `/maps/search/`, `?q=`, and Google Maps query patterns distinct from place detail pages.
  - `scrape_maps_search_feed()`: Navigates Google Maps search feeds, locates listing cards (`div.Nv2PK`), extracts Business Name (`div.qBF1Pd`), Place URL (`a.hfpxzc`), Website (`a.lcr4fd`, `a[data-value*="Website"]`), Phone (`PHONE_REGEX`), Rating (`span.MW4etd`), and Review Count (`span.UY7F9`).
  - Supports bounded scrolling and deduplication by normalized place URL.
  - `scrape_maps_place_detail()`: Preserves single-lead place detail extraction for `/maps/place/` URLs.
  - Consent dialog auto-dismissal for headless browsing.
  - Honest extraction validation: Returns `success: False` with descriptive error if 0 businesses are found.
- **Backend API Integration (`app.py`):**
  - Updated `/api/scrape` for `type == 'maps'`.
  - If 0 listings are extracted, returns HTTP 422 with `{"success": False, "leads": [], "count": 0, "error": ...}`.
  - If N listings are extracted, runs website intelligence and contact enrichment for each lead with a website.
  - Returns `{"success": True, "is_search": is_search, "leads": enriched_leads, "count": len(enriched_leads), "data": enriched_leads[0]}` ensuring full backward compatibility with single-lead callers.
- **Frontend Real-time UI & Honest Progress Tracking (`templates/index.html`):**
  - Separate progress tracking: `${completed} / ${total} URLs (${totalLeads} Leads)`.
  - For manual search queries, expands multi-lead batches into `finalData` and displays all extracted businesses.
  - When extraction yields 0 listings or errors occur, increments failure counter, logs failure in activity console, and **never** pushes blank/phantom rows to `finalData`.
- **Test Suite (`tests/test_maps_scraper.py` & `tests/test_api.py`):**
  - 10 new dedicated maps scraper tests covering URL detection, redirect cleanup, search card parsing, feed deduplication, place detail extraction, and honest empty failure.
  - 4 API integration tests verifying multi-lead search scraping, place URL scraping, HTTP 422 empty failure, and website fallback contracts.
  - Total automated test suite expanded from 59 to **73 tests** (100% passing).

---

## Phase 10: Google Maps Playwright SSRF, Redirect & Subresource Security Hardening

### 1. Security Threat Identification
- Initial Google Maps URL was previously passed directly to Playwright's `page.goto(url)` without pre-validation against the SSRF rules in `services/security.py`.
- Browser navigations could potentially be targeted with internal destinations (`127.0.0.1`, `10.0.0.0/8`, `169.254.169.254`), arbitrary external hosts, or redirected to unauthorized endpoints.
- Page subresources (scripts, images, stylesheets, fetch/XHR) were unmonitored by the Playwright process.

### 2. Implementation Overview
- **Strict Pre-Navigation URL Validation (`services/security.py`):**
  - `is_google_maps_domain(hostname)`: Strictly allows only legitimate Google Maps hosts (`*.google.com`, `*.google.<ccTLD>`, `goo.gl`, `*.goo.gl`) using combined regex and structured token verification. Rejects `attacker-google.com` or `google.com.attacker.com`.
  - `validate_google_maps_url(url)`: Runs standard `validate_and_sanitize_url(url)` (blocking localhost, private IPv4/IPv6, cloud metadata, link-local, and verifying DNS resolution), enforces domain whitelist, and checks supported feature patterns (`/maps/search`, `/maps/place`, `/search?`, `?q=`, `goo.gl/maps`).
- **Playwright Route Interception & SSRF Filter (`services/maps_scraper.py`):**
  - `create_playwright_route_interceptor(page)`: Attached via `page.route("**/*", ...)` to inspect every request across main navigation, redirects, and subresources.
  - `is_safe_browser_url(url, is_main_document)`:
    - Main document navigation & redirects: Must be an authorized Google Maps domain resolving to a public IP. Redirects to localhost, private IPs, or external arbitrary domains are aborted with `blockedbyclient`.
    - Subresources: Must be authorized Google static / CDN assets (`*.gstatic.com`, `*.googleapis.com`, `*.googleusercontent.com`, `*.ggpht.com`, `*.googletagmanager.com`, `*.google-analytics.com`) or inline base64 data URLs. All subresources to private IPs, metadata, or unauthorized third-party domains are aborted with `blockedbyclient`.
    - Integrated DNS caching (`_BROWSER_DNS_CACHE`) ensures zero latency overhead while guaranteeing continuous SSRF defense.
- **Preflight Enforcement in API Gateway (`app.py`):**
  - `/api/scrape` for `type == 'maps'` invokes `validate_google_maps_url(url)` before initiating Playwright. Catches `SecurityError` and returns HTTP 400 with descriptive error.
- **Automated Security Regression Test Suite (`tests/test_security.py` & `tests/test_api.py`):**
  - Added `TestGoogleMapsPlaywrightSecurity` with 8 dedicated tests:
    - Valid Google Maps Search URL accepted.
    - Valid Google Maps Place URL accepted.
    - Arbitrary external host rejected.
    - Localhost and private IP URLs rejected.
    - Cloud metadata and IPv6 link-local destinations rejected.
    - Redirects to unauthorized destinations blocked.
    - Browser subresource requests to unauthorized destinations blocked.
    - Preflight rejection before Playwright launch.
  - Added 3 API SSRF tests for `type == 'maps'` in `tests/test_api.py`.
  - Total automated test suite expanded to **84 tests** (100% passing).

---

## Phase 11: Playwright DNS Rebinding Remediation & `SafeBrowserProxy` Destination Pinning

### 1. Root Cause & DNS Rebinding Investigation
- **Chromium Independent Host Resolver**: Chromium runs an internal asynchronous C++ resolver (`net::HostResolverImpl`) and does not share Python's socket layer or DNS cache. A route handler validating DNS in Python cannot by itself constrain Chromium's C++ sockets.
- **Cache Poisoning Bug**: The previous `_BROWSER_DNS_CACHE` permanently stored boolean `True` in memory, allowing a domain that flips from public to private (0-second TTL rebinding) to bypass re-evaluation.
- **CDP Limitations**: `Fetch.continueRequest` in Chrome DevTools Protocol only accepts headers/URL and cannot specify the physical destination IP address.
- **Infrastructure Assessment**: Kernel-level packet filters (e.g., Windows Filtering Platform / Linux `iptables`) require root/admin privileges unavailable in standard unprivileged hosting environments (Render/Docker/Windows).

### 2. Implementation Overview
- **Elimination of Unsafe DNS Cache (`services/security.py`):**
  - Removed `_BROWSER_DNS_CACHE` completely.
  - Implemented `resolve_and_validate_hostname(hostname, port)`: Always performs real-time DNS resolution, validating that every resolved IPv4/IPv6 address is public and non-restricted (`is_ip_allowed()`).
- **Network-Level Destination Pinning via `SafeBrowserProxy` (`services/security.py`):**
  - Implemented local ephemeral loopback proxy (`SafeBrowserProxy`) configured via Playwright's `proxy={"server": f"http://127.0.0.1:{proxy.port}"}`.
  - Intercepts all Chromium outbound connection attempts (`CONNECT` and raw HTTP).
  - Validates domain whitelist and resolves hostname in Python.
  - Rejects connection with `HTTP/1.1 403 Forbidden` if any resolved IP belongs to `BLOCKED_IP_NETWORKS` (`127.0.0.1`, `10.0.0.0/8`, `169.254.169.254`, `fe80::/10`).
  - Directly opens the upstream TCP socket to the **pinned validated public IP**, physically constraining Chromium from connecting to private/internal IP destinations.
- **Integration in Scraper Lifecycle (`services/maps_scraper.py`):**
  - Scraper invokes `with SafeBrowserProxy() as proxy:` to bind proxy lifetime strictly to the scrape session.
- **Automated Regression Test Suite (`tests/test_security.py`):**
  - Added 5 new dedicated DNS rebinding regression tests:
    1. `test_public_to_private_dns_rebinding_rejected`: Verified public-to-private IP flip is rejected and not bypassed by stale cache.
    2. `test_dns_result_changing_between_validation_and_connection_blocked_by_proxy`: Verified proxy aborts with 403 when DNS rebinds to private IP between validation and connect.
    3. `test_redirect_to_hostname_resolving_to_private_ip_blocked`: Verified navigation redirects resolving to private IPs are intercepted and aborted.
    4. `test_browser_subresource_dns_rebinding_blocked`: Verified subresources resolving to cloud metadata (169.254.169.254) are aborted.
    5. `test_safe_browser_proxy_pins_socket_destination`: Verified upstream socket connects directly to the pinned public IP.
  - Total automated test suite expanded from 84 to **89 tests** (100% passing).
