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
| **Phase 14** | Lead Data Quality, Essential Fields Schema & Export Modernization | **COMPLETED & VERIFIED** | 109 Automated Tests Passing |
| **Phase 15** | Final Data Integrity Corrections: Unknown Priority & Evidence-Based Opportunity Language | **COMPLETED & VERIFIED** | 112 Automated Tests Passing |
| **Phase 16** | Google Maps Listing Extraction Hardening, External Website Cleaning & UI Responsiveness | **COMPLETED & VERIFIED** | 123 Automated Tests Passing |

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

---

## Phase 12: Playwright Lifecycle Scope Correction & HTTP Forward Proxy Enhancements

### 1. Issue Analysis
- **Playwright Context Early Exit**: In `services/maps_scraper.py`, `with sync_playwright() as p:` exited prematurely immediately after `page.route()`. The subsequent `page.goto()`, consent handling, search/place extraction, and resource cleanup were running outside the Playwright context.
- **HTTP Forward Proxy Gaps in `SafeBrowserProxy`**:
  - Absolute-form request targets (`http://host:port/path`) were forwarded directly upstream without conversion to origin-form (`/path`).
  - Request bodies with `Content-Length` or chunked transfer encoding risked truncation if not fully received in initial header read.
  - Unsupported HTTP methods and malformed request lines lacked standard HTTP error responses (`405 Method Not Allowed`, `400 Bad Request`).
  - Socket cleanup required explicit closing of both client and upstream sockets on error conditions.

### 2. Implementation Overview
- **Playwright Full Lifecycle Nesting (`services/maps_scraper.py`):**
  - Moved entire browser lifecycle inside `with sync_playwright() as p:` wrapped by `with SafeBrowserProxy() as proxy:`.
  - Guaranteed `page.goto()`, consent dialog dismissal, search feed extraction, and place detail extraction execute while Playwright is active.
  - Implemented safe reverse-order resource cleanup in `finally:` block (`page.close()`, `context.close()`, `browser.close()`).
  - SafeBrowserProxy remains active for the full browser lifecycle and terminates only after Playwright exits.
- **HTTP Forward Proxy Request Normalization (`services/security.py`):**
  - Converted absolute-form proxy request targets to origin-form (`/path?query`).
  - Preserved incoming `Host` header or safely auto-generated `Host: {host}:{port}`.
  - Replaced incoming `Connection` header with `Connection: close` for deterministic upstream completion.
  - Implemented complete request body reading based on `Content-Length` and chunked encoding to prevent truncation.
  - Added method validation rejecting unsupported methods with `405 Method Not Allowed`.
  - Added malformed request validation returning `400 Bad Request`.
  - Preserved full HTTPS CONNECT tunneling functionality with bidirectional byte streaming.
  - Upstream socket connects strictly to pinned, validated public IP addresses.
- **Automated Regression Test Suite:**
  - Added `test_playwright_and_proxy_lifecycle_sequence` in `tests/test_maps_scraper.py`:
    - Verified `proxy_enter` -> `playwright_enter` -> `page_goto` -> data extraction -> `page_close` -> `context_close` -> `browser_close` -> `playwright_exit` -> `proxy_exit`.
    - Verified browser closes before SafeBrowserProxy stops.
  - Added 6 dedicated HTTP forward proxy regression tests in `tests/test_security.py`:
    - `test_http_forward_proxy_absolute_to_origin_form_conversion`: Target conversion and response relay.
    - `test_http_forward_proxy_body_preserved_without_truncation`: Body preservation with `Content-Length`.
    - `test_http_forward_proxy_unsupported_method_rejected`: `405 Method Not Allowed`.
    - `test_http_forward_proxy_malformed_request_line_rejected`: `400 Bad Request`.
    - `test_http_forward_proxy_missing_host_rejected`: `400 Bad Request` on missing Host.
    - `test_http_forward_proxy_upstream_error_handled_cleanly`: `502 Bad Gateway` and socket cleanup.
  - Total automated test suite expanded from 89 to **96 tests** (100% passing).

---

## Phase 13: SafeBrowserProxy Standards-Compliant Chunked Body, Multi-IP Fallback, & Diagnostic Logging

### 1. Issue Analysis
- **Chunked Body RFC 7230 Compliance**: The previous reader stopped strictly on `0\r\n\r\n`, which failed to handle chunk extensions (e.g. `0;ext=val\r\n`) or trailer headers (`Trailer: val\r\n\r\n`) following the terminating chunk. It also lacked strict limits against oversized bodies and read timeouts.
- **Single Address Pinning Risk**: When a host resolved to multiple public IPs, only `resolved_ips[0]` was selected. If `resolved_ips[0]` was unreachable or experiencing transient failure, the proxy failed immediately without trying the other pre-validated public IPs.
- **Diagnostic Logging**: Broad exception handlers masked root-cause diagnostics without server-side log output.

### 2. Implementation Overview
- **Standards-Compliant Chunked Body Reader (`services/security.py`):**
  - Implemented `_read_chunked_body(client_sock, initial_buf, max_body_size)`.
  - Parses chunk size hex values and correctly ignores chunk extensions.
  - Verifies CRLF framing after each chunk's payload.
  - Correctly reads trailers following zero-sized terminal chunk (`0\r\n...[trailers]\r\n\r\n`).
  - Enforces `MAX_REQUEST_BODY_BYTES` (5 MB) across chunked and `Content-Length` requests, returning `413 Payload Too Large`.
  - Enforces socket read timeouts, returning `408 Request Timeout`.
  - Returns `400 Bad Request` upon premature client disconnect or malformed chunk boundaries.
  - Preserves raw chunk framing and trailers when forwarding upstream.
- **Multiple Validated Public IP Fallback (`services/security.py`):**
  - Deduplicates resolved addresses while preserving DNS response order via `dict.fromkeys()`.
  - Iterates through all pre-validated public IPs in order upon connection failure.
  - Never triggers secondary DNS lookups during fallback.
  - Never falls back to unvalidated hostname connections.
  - Closes candidate sockets before attempting the next IP address.
  - Emits `502 Bad Gateway` only if all candidate addresses fail.
- **Diagnostic Logging (`services/security.py`):**
  - Configured `logging.getLogger("leadhunter.security")`.
  - Logs warnings for domain authorization rejection, DNS validation/rebinding failure, malformed requests, unsupported methods, oversized payloads, chunk errors, and candidate IP connection failures.
  - Logs unhandled exceptions with traceback at ERROR level while returning sanitized standard HTTP status codes (`400`, `403`, `405`, `408`, `413`, `502`) to the browser client.
- **Automated Regression Test Suite (`tests/test_security.py`):**
  - Added 7 dedicated regression tests:
    1. `test_chunked_body_with_extensions_and_trailers_preserved`: Preserves chunk extensions and trailing headers.
    2. `test_chunked_body_incomplete_chunk_rejected`: Returns 400 on premature client disconnect.
    3. `test_chunked_body_missing_crlf_after_chunk_rejected`: Returns 400 on malformed chunk framing.
    4. `test_chunked_body_oversized_rejected_with_413`: Returns 413 when cumulative chunk data exceeds 5 MB.
    5. `test_multiple_validated_public_ips_fallback_success`: First IP fails, second IP succeeds with 0 extra DNS lookups and closed candidate sockets.
    6. `test_multiple_validated_public_ips_all_fail_returns_502`: All IPs fail, all sockets closed, returns 502.
    7. `test_content_length_oversized_rejected_with_413`: Returns 413 when Content-Length exceeds 5 MB.
  - Total automated test suite expanded from 96 to **103 tests** (100% passing).

---

## Phase 14: Lead Data Quality, Essential Fields Schema & Export Modernization

### 1. Product Decision & Architecture Realignment
- **Deprecation of Legacy 22-Column CSV**: Abandoned the legacy 22-column CSV schema in favor of an essential, actionable data model tailored specifically for lead generation and business development.
- **Unified 16-Field Lead Tracker (Sheet 01 & CSV)**:
  `Business Name`, `Category`, `City`, `State`, `Phone`, `Website`, `Google Maps URL`, `Rating`, `Reviews`, `Contact Person`, `Email`, `Email Status`, `Priority`, `Lead Score`, `Main Opportunity`, `Notes`.
- **Unified 15-Field Website Audit (Sheet 02)**:
  `Business Name`, `Website`, `Website Status`, `Page Title`, `Meta Description Status`, `Canonical Status`, `Indexability / Robots Status`, `H1 Status`, `Image Alt Status`, `Mobile / Viewport Status`, `HTTPS Status`, `Performance Status`, `Key SEO Issues`, `Technical Issues`, `Audit Summary`.
- **Unified 7-Field Business Opportunities (Sheet 03)**:
  `Business Name`, `Opportunity Category`, `Finding`, `Evidence`, `Confidence`, `Research Status`, `Recommended Service`.

### 2. Core Implementation Highlights
- **Rating & Reviews Normalization (`services/maps_scraper.py`)**:
  - `normalize_rating()`: Extracts numeric float (`0.0` to `5.0`), handles comma decimals (`4,8` -> `4.8`), and translates Bengali numerals (`৪.৯` -> `4.9`).
  - `normalize_review_count()`: Extracts integer, handles commas in numbers (`1,250` -> `1250`), strips parentheses (`(185)` -> `185`), and translates Bengali numerals (`১৮৫` -> `185`).
- **Location & Category Extraction (`services/maps_scraper.py`)**:
  - `parse_city_state()`: Accurately identifies City and US State from address lines, defaulting to `"Unknown"` when unresolved without guessing or hardcoding.
  - `extract_category_from_text()`: Identifies business category from listing card bullets.
- **Strict Separation of Contact Person & Business Name (`services/email_service.py`, `services/website_crawler.py`)**:
  - Rejects candidate names matching or strongly resembling the business name.
  - Filters out common commercial/trade terms from human name fields.
  - Leaves `Contact Person` empty/null if no legitimate human name is discovered.
- **Standardized Email Deliverability Statuses (`services/email_service.py`)**:
  - `Verified`: Server confirmed recipient mailbox with SMTP 250 OK and verified non-catch-all.
  - `MX Only`: Catch-all domain or port-25 timeout / ISP block with valid MX records.
  - `Invalid`: Mailbox rejected with 550 or domain lacks MX records.
  - `Not Found`: No email address present.
  - `Unverified`: Verification inconclusive.
- **Explainable Lead Scoring & Priority Thresholds (`services/lead_scoring.py`)**:
  - Supported configurable priority thresholds (`DEFAULT_PRIORITY_THRESHOLDS = {"high": 68, "medium": 40}`).
  - Added `priority_reason` field detailing exact justification for assigned priority, mapped to the `Notes` column.
- **Deduplication & Phantom Record Elimination (`services/export_service.py`)**:
  - Leads in Sheet 01 and Sheet 02 deduplicated by `(Business Name, Website/Phone/Maps URL)`.
  - Sheet 03: Zero rows emitted for businesses with 0 detected opportunities (no empty or placeholder rows).
  - OpenPyXL numeric formatting applied: Rating (`0.0`), Reviews (`#,##0`), Lead Score (`0`), and active hyperlinks for URLs.
- **Frontend Dashboard & Metrics (`templates/index.html`)**:
  - `statTotalRecords`: Displays unique businesses count.
  - `statVerifiedEmails`: Strictly counts `Verified` emails (excludes `MX Only` and `Unverified`).
  - `statWebsitesScanned`: Tracks live website audits.
  - Rebranded export buttons to "Download 3-Sheet Intelligence Workbook (.xlsx)" and "Export Lead Tracker (.csv)".
  - Added dedicated `/api/export-csv` backend endpoint serving 16-field Lead Tracker CSV.

### 3. Automated Test Suite Verification
- **Test Suite Results**:
  - `tests/test_api.py`: 11 tests passing.
  - `tests/test_email_service.py`: 7 tests passing.
  - `tests/test_export_service.py`: 6 tests passing.
  - `tests/test_feature_detector.py`: 5 tests passing.
  - `tests/test_lead_scoring.py`: 11 tests passing.
  - `tests/test_maps_scraper.py`: 14 tests passing.
  - `tests/test_opportunity_analyzer.py`: 3 tests passing.
  - `tests/test_security.py`: 50 tests passing.
  - `tests/test_seo_audit.py`: 2 tests passing.
  - **Total: 109 / 109 automated unit & integration tests passing (100% success rate)**.

---

## Phase 15: Final Data Integrity Corrections

### 1. Unknown Priority Handling (`services/export_service.py`)
- Updated `normalize_priority()`:
  - `High` remains `High`.
  - `Medium` remains `Medium`.
  - `Low` remains `Low`.
  - `Manual Review` remains `Manual Review`.
  - Missing, empty, or unrecognized priority values default to `Manual Review` (never silently classified as `Low`).
- Removed fallback `or "Low"` in `generate_standard_intelligence_workbook()` and `generate_lead_tracker_csv()`, ensuring incomplete records accurately default to `Manual Review`.
- Added dedicated regression tests in `tests/test_export_service.py` (`test_normalize_priority_handling` and `test_incomplete_record_priority_defaults_to_manual_review_in_exports`).

### 2. Evidence-Based Opportunity Language (`services/opportunity_analyzer.py`)
- Missing public website evidence (booking scripts, chatbot widgets, CRM tags, AI voice attendants, review widgets) is strictly evaluated without assuming absence of internal business workflows or systems.
- Kept research status as `Needs Review` and confidence as `Medium` for inferred gaps based on missing public elements.
- Purged all unsupported operational claims:
  - Purged claims that absence of booking scripts means appointments are handled only by phone/email.
  - Purged claims that absence of chatbot widgets means after-hours inquiries go unanswered.
  - Purged claims that absence of CRM trackers means leads are manually copied into spreadsheets.
  - Purged claims that absence of voice agent markers means callers reach voicemail or calls are missed.
- Rewrote outreach hooks as neutral, non-presumptive research questions (e.g. asking how after-hours inquiries or post-service reviews are currently managed).
- Preserved DOM evidence descriptions.
- Confirmed on-page technical issues (Technical SEO, Mobile Viewport, SSL) remain distinct with `Detected` status and `High` confidence.
- Added dedicated regression test `test_evidence_based_neutral_language_and_neutral_questions` in `tests/test_opportunity_analyzer.py`.

### 3. Automated Test Suite Verification
- Expanded test suite from 109 to **112 automated unit and integration tests** across 10 modules (100% passing).

---

## Phase 16: Google Maps Listing Extraction Hardening, External Website Cleaning & UI Responsiveness

### 1. External Website URL Cleaning & Extraction (`services/maps_scraper.py`)
- Replaced basic `/url?q=` handling with comprehensive `clean_external_website_url()`:
  - Supports Google Ads tracking links (`/aclk?...&adurl=...`, `https://www.google.com/aclk?`, `https://googleadservices.com/pagead/aclk?`).
  - Safely extracts and unquotes external target destinations from query parameters (`adurl`, `q`, `url`).
  - When `/aclk` or `/url` contains no external destination or an empty target, safely returns `""`.
  - Rejects relative URLs (`/maps/place/...`, `/search?q=...`, `/contact-us`, `relative/path.html`).
  - Rejects Google internal domains (`google.com`, `maps.google.com`, `googleadservices.com`, `doubleclick.net`, `gstatic.com`, `goo.gl`, etc.).
  - Rejects loopback, private, and metadata IP addresses (`localhost`, `127.0.0.1`, `::1`, `169.254.169.254`).
  - Rejects non-web schemes (`javascript:`, `tel:`, `mailto:`, `data:`, `#`).
  - Handles protocol-relative URLs (`//example.com` -> `https://example.com`).
  - Preserved `clean_google_redirect_url` as a backward-compatible alias.
  - Updated `extract_search_listing_card()` and `scrape_maps_place_detail()` to use `clean_external_website_url()`.

### 2. Resilient Lead Enrichment & Stage Logging (`app.py`)
- Added structured stage-specific logging across the scraping and enrichment pipeline:
  - `[Maps]` log markers for start, query type, and lead count.
  - `[Maps Feed]` and `[Maps Place]` extraction logs.
  - `[Enrichment X/Y]` per-lead progress logs with business name and target URL.
- Sanitizes `lead["Website"]` via `clean_external_website_url()` before enrichment.
- Skips website crawl if `Website` is empty or invalid, retaining all extracted Maps data.
- Enclosed `crawl_and_audit_website()` in robust `try...except Exception:` handling:
  - Logs warning with detailed error message if enrichment fails or times out.
  - Always appends the lead to `enriched_leads`, preventing lead drops.

### 3. Sensible Timeouts & Performance Optimization (`services/website_crawler.py`)
- Bounded Playwright fallback timeouts in `scrape_with_playwright_fallback()`:
  - Reduced main page navigation timeout from 35s to 12s.
  - Reduced candidate subpage navigation timeout from 18s to 8s.
  - Capped candidate subpages from 3 to 2.
  - Decreased artificial sleeps from 1.2s to 0.5s.
  - Prevents multi-minute stalls when scanning listings with offline or slow websites.

### 4. UI Progress Responsiveness (`templates/index.html`)
- Updated `processQueue()` in `templates/index.html` to provide dynamic real-time status:
  - Displays "Scanning Google Maps & Extracting Leads..." and "Extracting feed listings, verifying contact info & auditing websites."
  - Shows active query progress (`Processing query 1/1...`) instead of remaining frozen at 0 leads.

### 5. Automated Regression Test Suite (`tests/test_maps_scraper.py`, `tests/test_api.py`)
- Added 11 new automated unit and integration tests covering:
  - `test_clean_external_website_url_google_ads_aclk_with_target`
  - `test_clean_external_website_url_google_ads_aclk_without_target`
  - `test_clean_external_website_url_google_redirect_url`
  - `test_clean_external_website_url_relative_urls_rejected`
  - `test_clean_external_website_url_google_internal_domains_rejected`
  - `test_clean_external_website_url_valid_external_https_websites`
  - `test_clean_external_website_url_missing_or_disallowed_links`
  - `test_extract_search_listing_card_aclk_with_target`
  - `test_extract_search_listing_card_aclk_without_target`
  - `test_scrape_api_maps_failed_website_enrichment_preserves_maps_lead`
  - `test_scrape_api_maps_aclk_without_adurl_sanitized_and_not_crawled`
- Expanded overall test suite from 112 to **123 automated tests** (100% passing across 10 test modules).
