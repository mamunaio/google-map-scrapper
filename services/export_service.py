"""
LeadHunter Dual-Format Export Service
Provides both:
  Format A: Original Lead Tracker Compatibility (preserves all uploaded columns and duplicates)
  Format B: Standard Lead Intelligence Workbook (strictly 3 sheets with frozen headers, auto-filters & styles)
"""

import io
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

# Format B - Sheet 01 Exact 15 Columns
SHEET_01_COLUMNS = [
    "Business Name", "Google Category", "City", "State", "Google Rating",
    "Review Count", "Phone", "Website", "Google Maps Profile", "Decision Maker",
    "Contact Email", "Email Verification", "Research Priority", "Outreach Status", "Next Action"
]

# Format B - Sheet 02 Exact 18 Columns
SHEET_02_COLUMNS = [
    "Business Name", "Website", "Audit Date", "Website Status", "Mobile Performance",
    "Desktop Performance", "Core Web Vitals", "Technical SEO Findings", "Mobile Usability Findings",
    "Broken Links", "Lead Capture Status", "Booking Status", "Chatbot Status",
    "Voice Agent Status", "CRM Detection", "Review System Detection", "Audit Errors", "Evidence URLs"
]

# Format B - Sheet 03 Exact 10 Columns
SHEET_03_COLUMNS = [
    "Business Name", "Opportunity Category", "Identified Gap", "Evidence",
    "Evidence URL", "Potential Business Impact", "Recommended Service",
    "Confidence Level", "Research Status", "Suggested Next Action"
]

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
        ws.column_dimensions[col_letter].width = min(max(max_len + 3, 13), 48)

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

def generate_standard_intelligence_workbook(leads_data: list) -> io.BytesIO:
    """
    Format B: Standard Lead Intelligence Workbook.
    Generates exactly three sheets: Lead Tracker (15 cols), Website Audit (18 cols), Business Opportunities (10 cols).
    """
    wb = Workbook()
    
    # -------------------------------------------------------------
    # Sheet 01: Lead Tracker (15 Core Columns)
    # -------------------------------------------------------------
    ws_leads = wb.active
    ws_leads.title = "Lead Tracker"
    ws_leads.append(SHEET_01_COLUMNS)

    for item in leads_data:
        lead = dict(item)
        intel = lead.get("intelligence", {}) or {}
        opps = intel.get("opportunities", {}) or {}
        scoring = opps.get("scoring_details", {}) or {}

        biz_name = lead.get("Business Name") or lead.get("Name") or ""
        cat = lead.get("Google Category") or lead.get("Category") or ""
        city = lead.get("City") or ""
        state = lead.get("State") or ""
        rating = lead.get("Google Rating") or lead.get("Rating") or ""
        reviews = lead.get("Review Count") or lead.get("Reviews") or ""
        phone = lead.get("Phone Number") or lead.get("Phone") or ""
        web = lead.get("Website") or ""
        maps = lead.get("Google Maps Profile") or lead.get("Source URL") or ""
        dm = lead.get("Decision Maker") or ""
        email = lead.get("Contact Email") or lead.get("Email") or ""
        ver = lead.get("Email Verification") or "Unverified"
        priority = opps.get("priority_tier") or scoring.get("research_priority") or "Manual Review"
        outreach = lead.get("Outreach Status") or "New Prospect"
        next_action = opps.get("next_action") or scoring.get("suggested_next_action") or "Initial Inspection"

        ws_leads.append([
            biz_name, cat, city, state, rating, reviews, phone, web,
            maps, dm, email, ver, priority, outreach, next_action
        ])

    apply_sheet_styling(ws_leads, HEADER_FILL_PRIMARY, SHEET_01_COLUMNS)

    # -------------------------------------------------------------
    # Sheet 02: Website Audit (18 Columns)
    # -------------------------------------------------------------
    ws_audit = wb.create_sheet(title="Website Audit")
    ws_audit.append(SHEET_02_COLUMNS)
    audit_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    for item in leads_data:
        lead = dict(item)
        intel = lead.get("intelligence", {}) or {}
        seo = intel.get("seo", {}) or {}
        tech = intel.get("technical", {}) or {}
        features = intel.get("features", {}) or {}
        perf = intel.get("performance", {}) or {}

        biz_name = lead.get("Business Name") or lead.get("Name") or ""
        web = lead.get("Website") or ""
        web_status = "Online" if web else "No Website"

        m_perf = perf.get("mobile_score") if perf.get("mobile_score") is not None else "Not Configured"
        d_perf = perf.get("desktop_score") if perf.get("desktop_score") is not None else "Not Configured"

        cwv = perf.get("core_web_vitals", {})
        cwv_str = f"LCP: {cwv.get('largest_contentful_paint', 'N/A')}, CLS: {cwv.get('cumulative_layout_shift', 'N/A')}" if cwv else "N/A"

        seo_findings = seo.get("findings", [])
        seo_str = "; ".join([f["name"] if isinstance(f, dict) else str(f) for f in seo_findings[:3]]) if seo_findings else "SEO Optimized"

        mob_info = tech.get("mobile_usability", {})
        mob_str = mob_info.get("status", "Standard")

        broken_links = seo.get("metrics", {}).get("broken_internal_links", [])
        broken_str = f"{len(broken_links)} broken links" if broken_links else "0"

        lc_status = features.get("lead_capture", {}).get("status", "Unknown")
        booking_status = features.get("booking", {}).get("status", "Unknown")
        chat_status = features.get("chatbot", {}).get("status", "Unknown")
        voice_status = features.get("voice_agent", {}).get("status", "Unknown")
        crm_status = features.get("crm", {}).get("status", "Unknown")
        review_status = features.get("review_management", {}).get("status", "Unknown")

        errors = perf.get("errors") or ""
        errors_str = str(errors) if errors else "None"
        ev_urls = web or ""

        ws_audit.append([
            biz_name, web, audit_date, web_status, m_perf, d_perf, cwv_str,
            seo_str, mob_str, broken_str, lc_status, booking_status, chat_status,
            voice_status, crm_status, review_status, errors_str, ev_urls
        ])

    apply_sheet_styling(ws_audit, HEADER_FILL_AUDIT, SHEET_02_COLUMNS)

    # -------------------------------------------------------------
    # Sheet 03: Business Opportunities (10 Columns)
    # -------------------------------------------------------------
    ws_opps = wb.create_sheet(title="Business Opportunities")
    ws_opps.append(SHEET_03_COLUMNS)

    for item in leads_data:
        lead = dict(item)
        biz_name = lead.get("Business Name") or lead.get("Name") or ""
        intel = lead.get("intelligence", {}) or {}
        opps_data = intel.get("opportunities", {}) or {}
        opp_list = opps_data.get("detected_opportunities", [])

        if opp_list:
            for opp in opp_list:
                ws_opps.append([
                    biz_name,
                    opp.get("Opportunity Category", ""),
                    opp.get("Related Finding", ""),
                    opp.get("Evidence Description", ""),
                    opp.get("Evidence URL", lead.get("Website", "")),
                    opp.get("Potential Business Impact", ""),
                    opp.get("Recommended Service", ""),
                    opp.get("Confidence Level", "Medium"),
                    opp.get("Research Status", "Identified"),
                    opps_data.get("next_action", "Initial Outreach")
                ])
        else:
            # Add entry indicating no critical gaps identified
            ws_opps.append([
                biz_name, "General Optimization", "No Critical Gaps",
                "Website digital infrastructure is up to date.",
                lead.get("Website", ""), "None detected", "Maintenance / Retainer",
                "Low", "Verified", "Monitor periodically"
            ])

    apply_sheet_styling(ws_opps, HEADER_FILL_OPP, SHEET_03_COLUMNS)

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    return output

def generate_source_compatible_excel(leads_data: list) -> io.BytesIO:
    """
    Format A: Original Lead Tracker Compatibility.
    Preserves all uploaded columns, their exact sequence, values, and duplicates.
    Appends enriched fields cleanly without modifying source columns.
    """
    wb = Workbook()
    ws = wb.active
    ws.title = "Enriched Leads"

    if not leads_data:
        output = io.BytesIO()
        wb.save(output)
        output.seek(0)
        return output

    # Build union of columns preserving exact initial order of first row
    first_row = leads_data[0]
    initial_keys = [k for k in first_row.keys() if k != "intelligence"]

    # Candidate enrichment keys to append at the end
    enrichment_keys = [
        "Decision Maker", "Contact Email", "Email Verification", "Facebook", "LinkedIn",
        "Research Priority", "Research Score", "Main Opportunity Gap", "Suggested Next Action"
    ]
    all_columns = list(initial_keys)
    for ek in enrichment_keys:
        if ek not in all_columns:
            all_columns.append(ek)

    ws.append(all_columns)

    for item in leads_data:
        row = dict(item)
        intel = row.get("intelligence", {}) or {}
        opps = intel.get("opportunities", {}) or {}
        scoring = opps.get("scoring_details", {}) or {}

        # Populate enrichment fields
        row_values = []
        for col in all_columns:
            if col in row and row[col] is not None:
                row_values.append(row[col])
            elif col == "Research Priority":
                row_values.append(opps.get("priority_tier") or scoring.get("research_priority") or "Manual Review")
            elif col == "Research Score":
                row_values.append(opps.get("lead_score") or scoring.get("research_score") or "")
            elif col == "Main Opportunity Gap":
                row_values.append(opps.get("main_gap") or scoring.get("main_identified_gap") or "")
            elif col == "Suggested Next Action":
                row_values.append(opps.get("next_action") or scoring.get("suggested_next_action") or "")
            else:
                row_values.append("")
        ws.append(row_values)

    apply_sheet_styling(ws, HEADER_FILL_PRIMARY, all_columns)

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    return output

def generate_styled_excel(leads_data: list, format_type: str = "standard_3_sheet") -> io.BytesIO:
    """Entry point router for Format A vs Format B export."""
    if format_type == "source_compatible":
        return generate_source_compatible_excel(leads_data)
    return generate_standard_intelligence_workbook(leads_data)
