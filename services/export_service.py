"""
LeadHunter Export Service
Generates styled Excel (.xlsx) and CSV files preserving both core contact fields
and newly detected business intelligence, opportunity gaps, and lead priority tiers.
"""

import io
import pandas as pd
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

def flatten_lead_record(lead: dict) -> dict:
    """
    Flattens a lead dictionary (including nested intelligence) into a clean, uniform row for export.
    Preserves original columns if imported from user files.
    """
    row = dict(lead)
    intel = row.pop("intelligence", {}) if isinstance(row.get("intelligence"), dict) else {}

    # Extract summary metrics from intelligence
    if intel:
        opps = intel.get("opportunities", {})
        seo = intel.get("seo", {})
        features = intel.get("features", {})
        tech = intel.get("technical", {})

        row["Lead Score (0-100)"] = opps.get("lead_score", intel.get("lead_score", ""))
        row["Priority Tier"] = opps.get("priority_tier", intel.get("priority_tier", ""))
        row["SEO Score"] = seo.get("seo_score", "")

        # Detected features list
        detected_feats = []
        for k, v in features.items():
            if isinstance(v, dict) and v.get("status") == "Detected":
                cat = v.get("category", k)
                providers = v.get("providers", [])
                prov_str = f" ({', '.join(providers)})" if providers else ""
                detected_feats.append(f"{cat}{prov_str}")
        row["Detected Systems"] = "; ".join(detected_feats) if detected_feats else "None Detected"

        # Opportunities summary
        detected_opps = opps.get("detected_opportunities", [])
        opp_names = [o.get("service") for o in detected_opps if isinstance(o, dict) and o.get("service")]
        row["Opportunity Gaps"] = " | ".join(opp_names) if opp_names else "Optimized"

        # Recommended outreach angle
        hooks = opps.get("outreach_hooks", [])
        row["Recommended Pitch Angle"] = hooks[0] if hooks else ""

        # Mobile & SSL status
        row["Mobile Status"] = tech.get("mobile_usability", {}).get("status", "")
        row["SSL Certificate"] = tech.get("ssl_certificate", {}).get("status", "")

    return row

def generate_styled_excel(leads_data: list, sheet_title: str = "Lead Intelligence") -> io.BytesIO:
    """
    Creates an Excel spreadsheet with styled header ribbons, clean borders,
    and automatic column width adjustments.
    """
    flattened = [flatten_lead_record(l) for l in leads_data]
    df = pd.DataFrame(flattened)

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name=sheet_title, index=False)
        worksheet = writer.sheets[sheet_title]

        header_font = Font(name='Segoe UI', size=11, bold=True, color='FFFFFF')
        header_fill = PatternFill(start_color='4F46E5', end_color='4F46E5', fill_type='solid') # Indigo 600
        header_align = Alignment(horizontal='center', vertical='center', wrap_text=True)

        thin_border = Border(
            left=Side(style='thin', color='E2E8F0'),
            right=Side(style='thin', color='E2E8F0'),
            top=Side(style='thin', color='E2E8F0'),
            bottom=Side(style='thin', color='E2E8F0')
        )

        for col_num, col_name in enumerate(df.columns, 1):
            cell = worksheet.cell(row=1, column=col_num)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = header_align
            cell.border = thin_border

            # Auto-fit column widths
            max_len = max(
                len(str(col_name)),
                df[col_name].astype(str).map(len).max() if not df.empty else 0
            )
            col_letter = get_column_letter(col_num)
            worksheet.column_dimensions[col_letter].width = min(max(max_len + 4, 12), 45)

        for row in worksheet.iter_rows(min_row=2, max_row=len(df)+1, min_col=1, max_col=len(df.columns)):
            for cell in row:
                cell.border = thin_border
                cell.font = Font(name='Segoe UI', size=10)

    output.seek(0)
    return output
