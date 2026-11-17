"""
LeadHunter Export Service
Generates clean, standardized exports for B2B lead generation:
  1. Standard 3-Sheet Lead Intelligence Workbook (.xlsx):
     - Sheet 01: Lead Tracker (16 Essential Fields)
     - Sheet 02: Website Audit (15 Essential Fields)
     - Sheet 03: Business Opportunities (7 Essential Fields)
  2. Lead Tracker CSV (.csv):
     - Exactly 16 Essential Lead Tracker Fields
"""

import io
import re
from datetime import datetime, timezone
import pandas as pd
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

# Styles definition
HEADER_FONT = Font(name='Segoe UI', size=11, bold=True, color='FFFFFF')
HEADER_FILL_PRIMARY = PatternFill(start_color='4F46E5', end_color='4F46E5', fill_type='solid') # Indigo 600
HEADER_FILL_AUDIT = PatternFill(start_color='0284C7', end_color='0284C7', fill_type='solid')   # Sky 600
HEADER_FILL_OPP = PatternFill(start_color='D97706', end_color='D97706', fill_type='solid')     # Amber 600
HEADER_ALIGN = Alignment(horizontal='center', vertical='center', wrap_text=True)

DATA_FONT = Font(name='Segoe UI', size=10)
DATA_ALIGN_LEFT = Alignment(horizontal='left', vertical='center')
DATA_ALIGN_CENTER = Alignment(horizontal='center', vertical='center')

THIN_BORDER = Border(
    left=Side(style='thin', color='E2E8F0'),
    right=Side(style='thin', color='E2E8F0'),
    top=Side(style='thin', color='E2E8F0'),
    bottom=Side(style='thin', color='E2E8F0')
)

# Priority fills
FILL_HIGH = PatternFill(start_color='FEF3C7', end_color='FEF3C7', fill_type='solid')     # Amber light
FONT_HIGH = Font(name='Segoe UI', size=10, bold=True, color='92400E')
FILL_MED = PatternFill(start_color='EEF2FF', end_color='EEF2FF', fill_type='solid')      # Indigo light
FONT_MED = Font(name='Segoe UI', size=10, bold=True, color='3730A3')
FILL_LOW = PatternFill(start_color='F1F5F9', end_color='F1F5F9', fill_type='solid')      # Slate light
FONT_LOW = Font(name='Segoe UI', size=10, color='475569')

# 16 Essential Lead Tracker Fields (Sheet 01 & CSV)
LEAD_TRACKER_COLUMNS = [
    "Business Name",
    "Category",
    "City",
    "State",
    "Phone",
    "Website",
    "Google Maps URL",
    "Rating",
    "Reviews",
    "Contact Person",
    "Email",
    "Email Status",
    "Priority",
    "Lead Score",
    "Main Opportunity",
    "Notes"
]

# Backward-compatible alias
SHEET_01_COLUMNS = LEAD_TRACKER_COLUMNS

# 15 Essential Website Audit Fields (Sheet 02)
WEBSITE_AUDIT_COLUMNS = [
    "Business Name",
    "Website",
    "Website Status",
    "Page Title",
    "Meta Description Status",
    "Canonical Status",
    "Indexability / Robots Status",
    "H1 Status",
    "Image Alt Status",
    "Mobile / Viewport Status",
    "HTTPS Status",
    "Performance Status",
    "Key SEO Issues",
    "Technical Issues",
    "Audit Summary"
]

SHEET_02_COLUMNS = WEBSITE_AUDIT_COLUMNS

# 7 Essential Business Opportunity Fields (Sheet 03)
BUSINESS_OPPORTUNITIES_COLUMNS = [
    "Business Name",
    "Opportunity Category",
    "Finding",
    "Evidence",
    "Confidence",
    "Research Status",
    "Recommended Service"
]

SHEET_03_COLUMNS = BUSINESS_OPPORTUNITIES_COLUMNS


def deduplicate_leads(leads_data: list) -> list:
    """
    Deduplicates leads by unique identifier:
    Combination of normalized Business Name and Website/Phone/Google Maps URL.
    """
    seen = set()
    deduped = []
    for item in leads_data:
        lead = dict(item)
        biz = (lead.get("Business Name") or lead.get("Name") or "").strip().lower()
        web = (lead.get("Website") or "").strip().lower()
        phone = re.sub(r'\D', '', str(lead.get("Phone") or lead.get("Phone Number") or ""))
        maps = (lead.get("Google Maps URL") or lead.get("Google Maps Profile") or lead.get("Source URL") or "").strip().lower()

        # Build composite key
        secondary = web or phone or maps or biz
        key = (biz, secondary)
        if key not in seen:
            seen.add(key)
            deduped.append(lead)
    return deduped


def apply_sheet_styling(ws, header_fill, columns):
    """Applies frozen header row, auto-filter, and column width auto-fitting."""
    ws.freeze_panes = 'A2'
    max_col_letter = get_column_letter(len(columns))
    max_row = max(ws.max_row, 1)
    ws.auto_filter.ref = f"A1:{max_col_letter}{max_row}"

    # Style Header Row
    for col_idx in range(1, len(columns) + 1):
        cell = ws.cell(row=1, column=col_idx)
        cell.font = HEADER_FONT
        cell.fill = header_fill
        cell.alignment = HEADER_ALIGN
        cell.border = THIN_BORDER

        # Calculate max string length for column width
        col_letter = get_column_letter(col_idx)
        max_len = len(str(cell.value or ''))
        for row_idx in range(2, max_row + 1):
            val = ws.cell(row=row_idx, column=col_idx).value
            if val is not None:
                max_len = max(max_len, len(str(val)))
        ws.column_dimensions[col_letter].width = min(max(max_len + 3, 14), 48)

    # Style Data Cells
    for row in ws.iter_rows(min_row=2, max_row=max_row, min_col=1, max_col=len(columns)):
        for cell in row:
            if not cell.font or cell.font == Font():
                cell.font = DATA_FONT
            cell.border = THIN_BORDER
            val_str = str(cell.value or '')

            # Hyperlinks
            if val_str.startswith(('http://', 'https://')):
                cell.hyperlink = val_str
                cell.font = Font(name='Segoe UI', size=10, color='2563EB', underline='single')

            # Priority highlights
            if val_str in ["High Priority", "High"]:
                cell.fill = FILL_HIGH
                cell.font = FONT_HIGH
            elif val_str in ["Medium Priority", "Medium"]:
                cell.fill = FILL_MED
                cell.font = FONT_MED
            elif val_str in ["Low Priority", "Low", "Manual Review"]:
                cell.fill = FILL_LOW
                cell.font = FONT_LOW


def clean_contact_person(person_raw: str, business_name: str = "") -> str:
    """Cleans Contact Person to ensure strictly human name and not business name."""
    if not person_raw:
        return ""
    # Strip trailing role markers like (Owner) or (CEO)
    cleaned = re.sub(r'\(.*?\)', '', person_raw).strip()
    if business_name:
        b_clean = re.sub(r'[^a-zA-Z0-9]', '', business_name).lower()
        p_clean = re.sub(r'[^a-zA-Z0-9]', '', cleaned).lower()
        if p_clean and (p_clean == b_clean or b_clean in p_clean):
            return ""
    return cleaned


def normalize_email_status(status_raw: str, email: str = "") -> str:
    """Normalizes email verification status to one of: Verified, MX Only, Unverified, Invalid, Not Found."""
    if not email or "@" not in email:
        return "Not Found"
    s = str(status_raw or "").strip()
    if "SMTP Verified" in s or s == "Verified" or s == "SMTP Valid":
        return "Verified"
    if "Catch-All" in s or "MX Only" in s or "MX Valid" in s:
        return "MX Only"
    if "Invalid" in s:
        return "Invalid"
    if "Not Found" in s:
        return "Not Found"
    return "Unverified"


def normalize_priority(priority_raw: str) -> str:
    """Normalizes priority to: High, Medium, Low, or Manual Review."""
    p = str(priority_raw or "").strip()
    if "High" in p:
        return "High"
    if "Medium" in p:
        return "Medium"
    if "Low" in p:
        return "Low"
    if "Manual" in p:
        return "Manual Review"
    return "Low"


def generate_standard_intelligence_workbook(leads_data: list) -> io.BytesIO:
    """
    Standard Lead Intelligence Workbook (Format B).
    Generates exactly three sheets:
      - Sheet 01: Lead Tracker (16 Essential Fields)
      - Sheet 02: Website Audit (15 Essential Fields)
      - Sheet 03: Business Opportunities (7 Essential Fields)
    Applies deduplication, numeric formatting, and eliminates phantom records.
    """
    wb = Workbook()
    deduped_leads = deduplicate_leads(leads_data)

    # -------------------------------------------------------------
    # Sheet 01: Lead Tracker (16 Essential Fields)
    # -------------------------------------------------------------
    ws_leads = wb.active
    ws_leads.title = "Lead Tracker"
    ws_leads.append(LEAD_TRACKER_COLUMNS)

    for item in deduped_leads:
        lead = dict(item)
        intel = lead.get("intelligence", {}) or {}
        opps = intel.get("opportunities", {}) or {}
        scoring = opps.get("scoring_details", {}) or {}

        biz_name = lead.get("Business Name") or lead.get("Name") or ""
        category = lead.get("Category") or lead.get("Google Category") or "Unknown"
        city = lead.get("City") or "Unknown"
        state = lead.get("State") or "Unknown"
        phone = lead.get("Phone") or lead.get("Phone Number") or ""
        website = lead.get("Website") or ""
        maps_url = lead.get("Google Maps URL") or lead.get("Google Maps Profile") or lead.get("Source URL") or ""

        # Numeric Rating
        rating_raw = lead.get("Rating") if lead.get("Rating") is not None else lead.get("Google Rating")
        rating_val = None
        if rating_raw not in (None, ""):
            try:
                rating_val = float(rating_raw)
            except (ValueError, TypeError):
                rating_val = None

        # Numeric Reviews
        rev_raw = lead.get("Reviews") if lead.get("Reviews") is not None else lead.get("Review Count")
        rev_val = None
        if rev_raw not in (None, ""):
            try:
                rev_val = int(rev_raw)
            except (ValueError, TypeError):
                rev_val = None

        contact = clean_contact_person(lead.get("Contact Person") or lead.get("Decision Maker") or "", biz_name)
        email = lead.get("Email") or lead.get("Contact Email") or ""
        email_status = normalize_email_status(lead.get("Email Status") or lead.get("Email Verification") or "", email)

        priority = normalize_priority(
            lead.get("Priority") or opps.get("priority") or opps.get("priority_tier") or
            scoring.get("priority") or scoring.get("research_priority") or "Low"
        )

        score_raw = lead.get("Lead Score") or opps.get("lead_score") or scoring.get("research_score") or 0
        try:
            lead_score = int(score_raw)
        except (ValueError, TypeError):
            lead_score = 0

        main_opp = lead.get("Main Opportunity") or opps.get("main_gap") or scoring.get("main_identified_gap") or ""
        notes = lead.get("Notes") or scoring.get("priority_reason") or ""

        row_idx = ws_leads.max_row + 1
        ws_leads.append([
            biz_name, category, city, state, phone, website, maps_url,
            rating_val if rating_val is not None else "",
            rev_val if rev_val is not None else "",
            contact, email, email_status, priority, lead_score, main_opp, notes
        ])

        # Cell number formats
        if rating_val is not None:
            r_cell = ws_leads.cell(row=row_idx, column=8)
            r_cell.number_format = '0.0'
            r_cell.alignment = DATA_ALIGN_CENTER

        if rev_val is not None:
            rev_cell = ws_leads.cell(row=row_idx, column=9)
            rev_cell.number_format = '#,##0'
            rev_cell.alignment = DATA_ALIGN_CENTER

        score_cell = ws_leads.cell(row=row_idx, column=14)
        score_cell.number_format = '0'
        score_cell.alignment = DATA_ALIGN_CENTER

    apply_sheet_styling(ws_leads, HEADER_FILL_PRIMARY, LEAD_TRACKER_COLUMNS)

    # -------------------------------------------------------------
    # Sheet 02: Website Audit (15 Essential Fields)
    # -------------------------------------------------------------
    ws_audit = wb.create_sheet(title="Website Audit")
    ws_audit.append(WEBSITE_AUDIT_COLUMNS)

    for item in deduped_leads:
        lead = dict(item)
        intel = lead.get("intelligence", {}) or {}
        seo = intel.get("seo", {}) or {}
        tech = intel.get("technical", {}) or {}
        perf = intel.get("performance", {}) or {}

        biz_name = lead.get("Business Name") or lead.get("Name") or ""
        website = lead.get("Website") or ""

        if not website:
            ws_audit.append([
                biz_name, "", "Not checked", "Not checked", "Not checked",
                "Not checked", "Not checked", "Not checked", "Not checked",
                "Not checked", "Not checked", "Not checked",
                "No website provided", "No website provided", "Audit skipped: domain unavailable."
            ])
            continue

        is_failed = (
            perf.get("audit_status") == "Scan Failed" or
            tech.get("status") == "Scan Failed" or
            seo.get("status") == "Scan Failed"
        )

        if is_failed:
            ws_audit.append([
                biz_name, website, "Crawl failed", "Crawl failed", "Crawl failed",
                "Crawl failed", "Crawl failed", "Crawl failed", "Crawl failed",
                "Crawl failed", "Crawl failed", "Crawl failed",
                "Crawl error or timeout", "Crawl error or timeout",
                "Automated crawler could not reach target website."
            ])
            continue

        # Valid crawl evaluation
        page_title = seo.get("page_title", {}).get("value") or ("Confirmed issue" if not seo.get("page_title") else "Not detected")
        meta_status = "Confirmed issue" if not seo.get("meta_description") or not seo.get("meta_description", {}).get("value") else "Not detected"

        canonical_info = seo.get("canonical", {})
        canonical_status = "Confirmed issue" if canonical_info.get("status") in ["Missing", "Mismatch"] else "Not detected"

        robots_info = seo.get("robots_sitemap", {})
        robots_status = "Confirmed issue" if robots_info.get("robots_txt_status") == "Blocked" or seo.get("indexable") is False else "Not detected"

        h1_info = seo.get("h1", {})
        h1_status = "Confirmed issue" if (not h1_info.get("count") or h1_info.get("count") == 0) else "Not detected"

        img_info = seo.get("images", {})
        alt_status = "Confirmed issue" if img_info.get("missing_alt_count", 0) > 0 else "Not detected"

        mob_info = tech.get("mobile_usability", {})
        mob_status = "Confirmed issue" if (not mob_info.get("has_viewport") or mob_info.get("overflow_risk")) else "Not detected"

        ssl_info = tech.get("ssl_certificate", {})
        https_status = "Confirmed issue" if ssl_info.get("status") in ["Expired", "Plain HTTP", "Invalid"] else "Not detected"

        mob_score = perf.get("mobile_score")
        perf_status = "Confirmed issue" if (mob_score is not None and mob_score < 50) else "Not detected"

        seo_findings = seo.get("findings", [])
        key_seo = "; ".join([f["name"] if isinstance(f, dict) else str(f) for f in seo_findings[:3]]) if seo_findings else "None detected"

        tech_findings = tech.get("findings", [])
        key_tech = "; ".join([f["name"] if isinstance(f, dict) else str(f) for f in tech_findings[:3]]) if tech_findings else "None detected"

        seo_score = seo.get("seo_score", "N/A")
        summary = f"SEO Score: {seo_score}/100. SSL: {ssl_info.get('status', 'Unknown')}. Mobile: {mob_info.get('status', 'Unknown')}."

        ws_audit.append([
            biz_name, website, "Online", page_title, meta_status,
            canonical_status, robots_status, h1_status, alt_status,
            mob_status, https_status, perf_status, key_seo, key_tech, summary
        ])

    apply_sheet_styling(ws_audit, HEADER_FILL_AUDIT, WEBSITE_AUDIT_COLUMNS)

    # -------------------------------------------------------------
    # Sheet 03: Business Opportunities (7 Essential Fields)
    # -------------------------------------------------------------
    ws_opps = wb.create_sheet(title="Business Opportunities")
    ws_opps.append(BUSINESS_OPPORTUNITIES_COLUMNS)

    seen_opps = set()
    for item in deduped_leads:
        lead = dict(item)
        biz_name = lead.get("Business Name") or lead.get("Name") or ""
        intel = lead.get("intelligence", {}) or {}
        opps_data = intel.get("opportunities", {}) or {}
        opp_list = opps_data.get("detected_opportunities", [])

        # Prevent phantom records: if 0 opportunities, emit NO rows for this business!
        if not opp_list:
            continue

        for opp in opp_list:
            cat = opp.get("Opportunity Category", "")
            finding = opp.get("Finding") or opp.get("Related Finding") or ""
            evidence = opp.get("Evidence") or opp.get("Evidence Description") or ""
            confidence = opp.get("Confidence") or opp.get("Confidence Level") or "Medium"
            status = opp.get("Research Status") or "Needs Review"
            service = opp.get("Recommended Service", "")

            # Deduplicate opportunities per business
            opp_key = (biz_name.lower().strip(), cat.lower().strip(), finding.lower().strip())
            if opp_key in seen_opps:
                continue
            seen_opps.add(opp_key)

            ws_opps.append([
                biz_name, cat, finding, evidence, confidence, status, service
            ])

    apply_sheet_styling(ws_opps, HEADER_FILL_OPP, BUSINESS_OPPORTUNITIES_COLUMNS)

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    return output


def generate_lead_tracker_csv(leads_data: list) -> str:
    """
    Generates standardized 16-field Lead Tracker CSV.
    Deduplicates leads and eliminates phantom/legacy fields.
    """
    deduped = deduplicate_leads(leads_data)
    rows = []
    for item in deduped:
        lead = dict(item)
        intel = lead.get("intelligence", {}) or {}
        opps = intel.get("opportunities", {}) or {}
        scoring = opps.get("scoring_details", {}) or {}

        biz_name = lead.get("Business Name") or lead.get("Name") or ""
        category = lead.get("Category") or lead.get("Google Category") or "Unknown"
        city = lead.get("City") or "Unknown"
        state = lead.get("State") or "Unknown"
        phone = lead.get("Phone") or lead.get("Phone Number") or ""
        website = lead.get("Website") or ""
        maps_url = lead.get("Google Maps URL") or lead.get("Google Maps Profile") or lead.get("Source URL") or ""

        rating_raw = lead.get("Rating") if lead.get("Rating") is not None else lead.get("Google Rating")
        rating = f"{float(rating_raw):.1f}" if rating_raw not in (None, "") else ""

        rev_raw = lead.get("Reviews") if lead.get("Reviews") is not None else lead.get("Review Count")
        reviews = str(int(rev_raw)) if rev_raw not in (None, "") else ""

        contact = clean_contact_person(lead.get("Contact Person") or lead.get("Decision Maker") or "", biz_name)
        email = lead.get("Email") or lead.get("Contact Email") or ""
        email_status = normalize_email_status(lead.get("Email Status") or lead.get("Email Verification") or "", email)

        priority = normalize_priority(
            lead.get("Priority") or opps.get("priority") or opps.get("priority_tier") or
            scoring.get("priority") or scoring.get("research_priority") or "Low"
        )

        score_raw = lead.get("Lead Score") or opps.get("lead_score") or scoring.get("research_score") or 0
        try:
            lead_score = int(score_raw)
        except (ValueError, TypeError):
            lead_score = 0

        main_opp = lead.get("Main Opportunity") or opps.get("main_gap") or scoring.get("main_identified_gap") or ""
        notes = lead.get("Notes") or scoring.get("priority_reason") or ""

        rows.append({
            "Business Name": biz_name,
            "Category": category,
            "City": city,
            "State": state,
            "Phone": phone,
            "Website": website,
            "Google Maps URL": maps_url,
            "Rating": rating,
            "Reviews": reviews,
            "Contact Person": contact,
            "Email": email,
            "Email Status": email_status,
            "Priority": priority,
            "Lead Score": lead_score,
            "Main Opportunity": main_opp,
            "Notes": notes
        })

    df = pd.DataFrame(rows, columns=LEAD_TRACKER_COLUMNS)
    return df.to_csv(index=False)


def generate_source_compatible_excel(leads_data: list) -> io.BytesIO:
    """
    Convenience alias returning the standardized workbook.
    Maintained for API endpoint compatibility.
    """
    return generate_standard_intelligence_workbook(leads_data)


def generate_styled_excel(leads_data: list, format_type: str = "standard_3_sheet") -> io.BytesIO:
    """Entry point router for LeadHunter Excel export."""
    return generate_standard_intelligence_workbook(leads_data)
