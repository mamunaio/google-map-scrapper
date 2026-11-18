# LeadHunter Studio - Post-Implementation Verification & Acceptance Audit

**Date of Audit:** 2026-11-17  
**Audit Target:** `LeadHunter Studio` (v2.5 / v3.0 codebase)  
**Audited Repository:** `D:\Github Files\google-map-scrapper`  
**Git Branch / Commit:** `main` (`aaed5bb`)  
**Audit Type:** Independent Post-Implementation Regression & Acceptance Verification  

---

## Executive Summary

An independent, rigorous verification of the codebase was conducted to evaluate the actual implementation against the Master Development Requirements. 

While core contact extraction, basic SSRF validation, and modular service separation have been established, **several critical gaps, unverified claims, and incomplete specifications were discovered**. 

Notably:
1. The standard **3-sheet Lead Intelligence Excel workbook** is **not implemented**; the exporter currently produces only a single flattened sheet.
2. The **Lead Scoring Engine** uses an uncalibrated, hardcoded additive formula with an arbitrary baseline and speculative priority labels, rather than explainable weights across the 9 required dimensions.
3. The **Opportunity Analyzer** injects **unsupported marketing assertions** (e.g., claiming a guaranteed "25–30% booking conversion improvement" or "pushes you into top 3 of Google Maps") which violates non-negotiable development rules.
4. Broken internal link crawling was **omitted** from the technical SEO audit.
5. Business feature detection does not distinguish an `"Unknown"` state from `"Not Detected"`, risking false negative assumptions.
6. The 22 passing automated tests verify basic string and regex helpers, but lack coverage for network timeouts, DNS rebinding, multi-sheet exports, or Playwright Google Maps extraction.

---

## 1. Verified Features

The following features were verified as functioning and correctly implemented:

| Feature | Verification Method | Status | Notes / Evidence |
| :--- | :--- | :--- | :--- |
| **API Contract Preservation** | Code inspection & API call | **Verified** | `POST /api/scrape` retains all original keys: `"Business Name"`, `"Phone Number"`, `"Website"`, `"Email"`, `"Facebook"`, `"Instagram"`, `"LinkedIn"`, `"About Page Link"`, `"Source URL"`. Enriched keys are additive. |
| **Google Maps Extraction Handler** | Code inspection (`app.py:46-77`) | **Verified** | Playwright Chromium headless extraction for business name (`h1.DUwDvf`), website (`a[data-item-id="authority"]`), and phone (`button[data-tooltip*="Copy phone number"]`) remains intact. |
| **CSV Lead Upload & 22+ Column Preservation** | PapaParse client-side trace (`templates/index.html:565`) | **Verified** | Correctly maps `Website`, `Contact Email`, `Decision Maker`, and preserves original 22 columns during CSV re-export. |
| **B2B Decision Maker Extraction** | DOM & Schema JSON-LD inspection (`services/email_service.py:180`) | **Verified** | Successfully identifies Owner, Founder, and CEO from Schema.org JSON-LD and page text patterns. Verified on `richmondsair.com` (detected "James Richmond"). |
| **Email Permutations & SMTP Check** | Unit test & live test (`services/email_service.py:270`) | **Verified** | Generates `first@domain`, `first.last@domain`, `flast@domain`. Probes DNS MX and handles Catch-All detection via randomized mailbox probe. |
| **Social Links Extraction** | Regex & DOM inspection (`services/email_service.py:120`) | **Verified** | Accurately extracts Facebook, LinkedIn, and Instagram links while filtering template dummy links (`/wix`, `/wordpress`, `/sharer.php`). |
| **Basic SSRF IP Filtering** | Unit test (`tests/test_security.py`) | **Verified** | Blocks `localhost`, `127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and AWS/GCP metadata `169.254.169.254`. |
| **On-Page SEO Diagnostics** | Unit test & live scrape (`services/seo_audit.py`) | **Verified** | Inspects title length, meta description length, single H1 hierarchy, canonical tags, `noindex` robots meta, robots.txt, and sitemap.xml. |
| **SSL Validity Inspection** | TLS socket inspection (`services/technical_audit.py:15`) | **Verified** | Handshakes port 443, extracts expiration date, issuer organization, and remaining days. |
| **PageSpeed API Graceful Fallback** | Code inspection (`services/performance_audit.py:65`) | **Verified** | When `GOOGLE_PAGESPEED_API_KEY` is omitted, reports `"API Key Not Configured"` and provides local asset diagnostics (size, script count) without fabricating fake Lighthouse scores. |

---

## 2. Failed & Incomplete Features

The following features specified in the Master Prompt failed verification or are currently incomplete:

### 2.1 Broken Internal Link Detection Omitted
- **Requirement:** Section 6 & 11 state that the technical audit and Sheet 02 must check and report "Broken internal links".
- **Finding:** `services/seo_audit.py` counts internal and external links via `href` attributes, but **never attempts HTTP head/get requests** to test if internal links return 404 or broken statuses.
- **Code Reference:** `services/seo_audit.py:240-256`.

### 2.2 Absence of "Unknown" State in Feature Detection
- **Requirement:** Section 4 & 7 require: *"Detection must distinguish between: Detected, Not detected, Unknown, Scan failed. Not detected does not necessarily mean the business does not use that system."*
- **Finding:** `services/business_feature_detector.py` uses binary logic: if a signature is found -> `"Detected"`, otherwise -> `"Not Detected"`. It never outputs `"Unknown"`. If a business uses an off-site booking portal or server-side CRM, reporting `"Not Detected"` implies absence and violates the requirement that missing scripts must never confirm absence.
- **Code Reference:** `services/business_feature_detector.py:155-255`.

### 2.3 Single-Sheet Excel Exporter (3-Sheet Standard Output Missing)
- **Requirement:** Section 11 mandates a 3-sheet workbook:
  - `Sheet 01: Lead Tracker` (exact 15 core columns)
  - `Sheet 02: Website Audit` (18 technical columns)
  - `Sheet 03: Business Opportunities` (10 opportunity columns)
- **Finding:** `services/export_service.py` (`generate_styled_excel`) writes **only one sheet** named `"Lead Intelligence"` dumping flattened fields into arbitrary column arrangements.
- **Code Reference:** `services/export_service.py:61-67`.

### 2.4 Missing Selective Lead Export UI
- **Requirement:** Section 10 states: *"Allow the user to choose which leads to export."*
- **Finding:** In `templates/index.html`, the export buttons (`downloadCSV()` and `downloadExcel()`) export either all uploaded rows or all scanned rows. There are no row checkboxes or selection states in the table UI to export a chosen subset of leads.
- **Code Reference:** `templates/index.html:810-855`.

---

## 3. Security Findings

| Vulnerability / Risk | Severity | Technical Details | Code Reference |
| :--- | :--- | :--- | :--- |
| **DNS Rebinding (TOCTOU) in Safe HTTP** | **High** | `validate_and_sanitize_url` resolves the hostname via DNS and validates the IP. However, `safe_http_get` then invokes `session.get(current_url)`, causing `urllib3` to perform a **second independent DNS resolution**. An attacker controlling a DNS server with TTL=0 can return a public IP on first resolution and `127.0.0.1` on the second resolution, bypassing the SSRF filter. | `services/security.py:72` & `108` |
| **Insecure SSL Fallback on SSLError** | **Medium** | When `requests.exceptions.SSLError` occurs, `safe_http_get` catches it and immediately retries with `verify=False`. While `ssl_verified = False` is flagged on the response, automatically executing unverified requests exposes the crawler to Machine-in-the-Middle (MitM) interception on untrusted networks. | `services/security.py:118-124` |
| **Potential SMTP Banner / Raw Error Logging** | **Low** | Server error handlers log `f"API Error processing {url}: {e}"`. If an external SMTP or HTTP server returns verbose authentication or network exception details, it is printed directly to stdout. | `app.py:128` |

---

## 4. Data Integrity Findings

1. **Duplicate Preservation vs Cleansing:**
   - Section 11 states: *"Preserve all source business records. Do not silently remove duplicates."*
   - In `templates/index.html:565`, user records are indexed by row index and stored in `uploadedData`. However, in `services/email_service.py:70`, emails are aggressively deduplicated without linking duplicates back to their original row context.
2. **Column Consistency on Non-Standard Headers:**
   - If an uploaded CSV has columns named `Company` instead of `Business Name`, or `Site` instead of `Website`, `processParsedData` attempts regex matching. However, if a column is unrecognized, it remains in the raw dictionary, but `flatten_lead_record` in `export_service.py` may place it at the very end of the Excel sheet, altering column predictability.

---

## 5. Excel Compatibility Findings

### 5.1 Format A: Original 22+ Column Lead Tracker
- **Status:** **Partially Preserved**.
- **Observation:** `downloadCSV()` maintains all original columns because it operates directly on `uploadedData`. However, when downloading via `downloadExcel()` through `/api/export-excel`, `flatten_lead_record` pops `intelligence` and appends synthetic fields (`Lead Score (0-100)`, `Priority Tier`, `SEO Score`), which modifies the exact layout of the user's original spreadsheet.

### 5.2 Format B: Three-Sheet Lead Intelligence Workbook
- **Status:** **Failed / Non-Compliant**.
- **Deficiencies:**
  - `Sheet 01: Lead Tracker` with the exact 15 columns is absent.
  - `Sheet 02: Website Audit` with the exact 18 columns is absent.
  - `Sheet 03: Business Opportunities` with the exact 10 columns is absent.
  - OpenPyXL freeze panes (`ws.freeze_panes = 'A2'`) and auto-filter configurations (`ws.auto_filter.ref`) are missing.

---

## 6. Scoring Validation

An audit of `services/opportunity_analyzer.py:121-135` revealed the following scoring calculation:

```python
score = 30  # Baseline
if dm_name: score += 20
if email and '@' in email: score += 15
if len(opportunities) >= 3: score += 20
elif len(opportunities) >= 1: score += 10
if any(o["priority"] in ["Critical", "High"] for o in opportunities): score += 15
score = min(100, max(10, score))
```

### Critical Deficiencies:
1. **Arbitrary 100/100 Inflation:** A business with an identified owner (+20), an email (+15), 3 detected gaps (+20), and at least one high-priority gap (+15) starts from 30 and instantly hits 100/100, even if the website has zero SEO issues, perfect mobile usability, and excellent performance.
2. **Missing Dimension Weights:** Section 9 requires configurable scoring weights across 9 distinct dimensions (Website Performance, Technical SEO, Lead Capture, Booking, Chatbot/Voice, Business Relevance, Contact Availability, Decision Maker Availability, Website Accessibility). The current formula ignores performance and accessibility completely.
3. **Non-Standard Priority Labels:** The current code outputs `"High Priority Prospect"`, `"Medium Priority Prospect"`, and `"Standard Prospect"`. The specification strictly requires: `"High Priority"`, `"Medium Priority"`, `"Low Priority"`, and `"Manual Review"`.

---

## 7. Unsupported Claims

The Master Prompt explicitly prohibits unverified, assumed, or speculative marketing assertions:
> *"Never claim that a technical issue directly caused a specific Google ranking loss without supporting evidence."*  
> *"Remove unsupported claims such as guaranteed 25-30% booking conversion improvement."*

The following non-compliant strings were discovered in `services/opportunity_analyzer.py`:

| Line | Category | Non-Compliant Text | Issue |
| :--- | :--- | :--- | :--- |
| **Line 30** | Outreach Hook | `"...setting that up typically lifts local booking conversion by 25-30%."` | **Unsupported conversion claim.** Violates rule against assumed business improvements. |
| **Line 40** | Impact Statement | `"Over 40% of home/business inquiries occur after 6 PM..."` | **Unsupported statistical claim.** Cannot be proven for a specific audited business. |
| **Line 77** | Impact Statement | `"Businesses without automated post-job review collection average 60% fewer monthly 5-star reviews..."` | **Fabricated benchmark.** |
| **Line 80** | Outreach Hook | `"...can systematically push you into the top 3 of Google Maps local pack."` | **Unprovable ranking guarantee.** Violates SEO ethics rules. |
| **Line 105** | Impact Statement | `"Over 65% of local service searches originate on smartphones..."` | **Generic speculative metric.** |

---

## 8. Production Blockers

The following issues prevent this build from meeting production acceptance criteria:

1. **Absence of the 3-Sheet Excel Standard:** Users cannot export the required 3-sheet Lead Intelligence workbook specified in Section 11.
2. **Speculative & Legally Fragile Outreach Copy:** Claims of guaranteed 25-30% conversion or top-3 Google Maps placement must be purged before any outreach is initiated by end users.
3. **SSRF TOCTOU / Rebinding Vulnerability:** Resolving DNS twice in `services/security.py` leaves an exploitable SSRF vulnerability.
4. **Scoring Model Unaligned:** The lead scoring engine does not use the 9 configurable dimensions or the standard priority tiers required by Section 9.

---

## 9. Recommended Fixes

Before deploying or proceeding further, the following corrective actions must be implemented:

1. **Refactor `services/export_service.py`:**
   - Implement three distinct sheets: `Lead Tracker` (15 columns), `Website Audit` (18 columns), and `Business Opportunities` (10 columns).
   - Apply OpenPyXL freeze panes (`freeze_panes = 'A2'`), table auto-filters, and conditional formatting on priority columns.
2. **Create Dedicated `services/lead_scoring.py`:**
   - Implement a transparent 9-dimension scoring matrix with normalized weights totaling 100.
   - Enforce exact priority labels: `High Priority`, `Medium Priority`, `Low Priority`, and `Manual Review`.
3. **Purge Speculative Claims in `services/opportunity_analyzer.py`:**
   - Replace speculative statistics with evidence-grounded statements (e.g., replace *"lifts conversion by 25-30%"* with *"allows clients to schedule directly without waiting for a manual callback"*).
   - Link all opportunity records strictly to the 9-field schema specified in Phase 05.
4. **Implement "Unknown" Status in `services/business_feature_detector.py`:**
   - Differentiate between `Detected`, `Not Detected (No on-page evidence found)`, `Unknown (Off-site/portal suspected)`, and `Scan Failed`.
5. **Harden SSRF Protection in `services/security.py`:**
   - Implement a custom `HTTPAdapter` or socket pool in `requests` that pins and connects directly to the pre-validated IP address, preventing DNS rebinding.
6. **Implement Broken Internal Link Probe in `services/seo_audit.py`:**
   - Safely HEAD-request up to 5-10 internal candidate links to check for HTTP 404/500 responses.
7. **Expand Deterministic Test Suite:**
   - Add mocked HTTP fixtures for `safe_http_get`, DNS resolver mocks for `verify_email_smtp`, and multi-sheet openpyxl validation tests.

---

### Audit Conclusion
**Acceptance Status: CONDITIONAL (Revisions Required)**  
The application has strong core scraping and modular foundations, but Phase 05–08 requirements must be corrected to eliminate speculative claims, implement the 3-sheet Excel export, and resolve the scoring and security findings.

*No application code was modified during this audit, and no deployment actions were executed.*
