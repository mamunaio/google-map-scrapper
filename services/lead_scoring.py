"""
LeadHunter Dedicated Lead Scoring Engine
Implements a transparent, explainable 9-dimension scoring matrix (0-100)
with configurable weights, no arbitrary baselines, and standardized priority tiers.
"""

# Default weights totaling exactly 100
DEFAULT_SCORING_WEIGHTS = {
    "website_performance": 10,       # Speed, asset weight, TTFB
    "technical_seo": 15,             # Meta tags, headings, canonicals, sitemap
    "lead_capture": 15,              # Form availability, CTAs, click-to-call
    "booking_automation": 15,        # Self-service scheduling gap vs presence
    "chatbot_voice": 10,             # Conversational agent presence vs opportunity
    "business_relevance": 10,        # Local commercial validity & categories
    "contact_availability": 10,      # Direct phone & verified email presence
    "decision_maker_availability": 10,# Owner/CEO identified
    "mobile_ssl_security": 5         # Mobile viewport & valid HTTPS/SSL
}

def calculate_lead_score(
    audit_data: dict,
    weights: dict = None,
    business_name: str = "",
    google_rating: float = None,
    review_count: int = None
) -> dict:
    """
    Computes an explainable research priority score (0-100) across 9 dimensions.
    Returns dimension-level breakdown, priority tier, main identified gap, and suggested next action.
    """
    w = dict(DEFAULT_SCORING_WEIGHTS)
    if weights and isinstance(weights, dict):
        w.update(weights)

    # Validate weight normalization
    total_weights = sum(w.values())
    if total_weights != 100:
        # Normalize weights to exactly 100 if user modified them
        w = {k: (v / total_weights) * 100 for k, v in w.items()}

    dimension_scores = {}
    gaps_identified = []

    # Safe extraction of audit branches
    intel = audit_data.get("intelligence", {}) if isinstance(audit_data, dict) else {}
    seo = intel.get("seo", {})
    tech = intel.get("technical", {})
    features = intel.get("features", {})
    perf = intel.get("performance", {})
    opps = intel.get("opportunities", {})

    email = audit_data.get("Email", "")
    phone = audit_data.get("Phone Number", "")
    dm = audit_data.get("Decision Maker", "")
    website = audit_data.get("Website", "")

    # Dimension 1: Website Performance (10 pts)
    # Evaluates whether the site has performance friction or local asset bloat
    perf_status = perf.get("audit_status", "")
    mobile_score = perf.get("mobile_score")
    if mobile_score is not None:
        # If score is low, opportunity for performance optimization is high
        if mobile_score < 50:
            dim1 = 10.0
            gaps_identified.append(("Website Performance", "Low mobile performance score (<50)"))
        elif mobile_score < 75:
            dim1 = 6.0
            gaps_identified.append(("Website Performance", "Moderate mobile performance score (50-74)"))
        else:
            dim1 = 2.0
    else:
        # Missing PageSpeed API: neutral score without penalty
        local_diag = perf.get("local_diagnostics", {})
        html_size = local_diag.get("html_size_kb", 0)
        dim1 = 8.0 if html_size > 250 else 5.0
    dimension_scores["website_performance"] = round(dim1 * (w["website_performance"] / 10.0), 1)

    # Dimension 2: Technical SEO (15 pts)
    seo_score = seo.get("seo_score")
    if seo_score is not None:
        # Lower SEO score indicates higher service opportunity
        if seo_score < 60:
            dim2 = 10.0
            gaps_identified.append(("Technical SEO", "Critical on-page SEO issues (score < 60)"))
        elif seo_score < 80:
            dim2 = 7.0
            gaps_identified.append(("Technical SEO", "Moderate on-page SEO gaps (score 60-79)"))
        else:
            dim2 = 3.0
    else:
        dim2 = 5.0
    dimension_scores["technical_seo"] = round(dim2 * (w["technical_seo"] / 10.0), 1)

    # Dimension 3: Lead Capture (15 pts)
    lc = features.get("lead_capture", {})
    lc_status = lc.get("status", "")
    if lc_status == "Not Detected":
        dim3 = 10.0
        gaps_identified.append(("Lead Capture", "No contact forms or conversion CTAs identified on scanned pages"))
    elif lc.get("details", {}).get("has_quote_form") is False:
        dim3 = 6.0
        gaps_identified.append(("Lead Capture", "Basic contact form present, but no quote/estimate request workflow"))
    else:
        dim3 = 2.0
    dimension_scores["lead_capture"] = round(dim3 * (w["lead_capture"] / 10.0), 1)

    # Dimension 4: Booking Automation (15 pts)
    booking = features.get("booking", {})
    b_status = booking.get("status", "")
    if b_status == "Not Detected":
        dim4 = 10.0
        gaps_identified.append(("Booking Automation", "No online scheduling or booking integration identified"))
    elif b_status == "Unknown":
        dim4 = 5.0
    else:
        dim4 = 1.0
    dimension_scores["booking_automation"] = round(dim4 * (w["booking_automation"] / 10.0), 1)

    # Dimension 5: Chatbot / Voice Agent (10 pts)
    chat = features.get("chatbot", {})
    voice = features.get("voice_agent", {})
    if chat.get("status") == "Not Detected" and voice.get("status") == "Not Detected":
        dim5 = 10.0
        gaps_identified.append(("AI Automation", "No live chat or conversational bot scripts detected"))
    elif chat.get("status") == "Not Detected":
        dim5 = 6.0
    else:
        dim5 = 1.0
    dimension_scores["chatbot_voice"] = round(dim5 * (w["chatbot_voice"] / 10.0), 1)

    # Dimension 6: Business Relevance & Commercial Activity (10 pts)
    # Verifies the lead is an active commercial operation rather than inactive shell
    if website and (phone or email):
        dim6 = 9.0
    elif website:
        dim6 = 6.0
    else:
        dim6 = 2.0
    dimension_scores["business_relevance"] = round(dim6 * (w["business_relevance"] / 10.0), 1)

    # Dimension 7: Contact Reachability (10 pts)
    dim7 = 0.0
    if email and "@" in email:
        dim7 += 6.0
    if phone:
        dim7 += 4.0
    dimension_scores["contact_availability"] = round(dim7 * (w["contact_availability"] / 10.0), 1)

    # Dimension 8: Decision Maker Availability (10 pts)
    if dm and dm.strip() and dm != "-":
        dim8 = 10.0
    else:
        dim8 = 2.0
        gaps_identified.append(("Executive Outreach", "Decision maker name not yet identified"))
    dimension_scores["decision_maker_availability"] = round(dim8 * (w["decision_maker_availability"] / 10.0), 1)

    # Dimension 9: Mobile Usability & SSL Security (5 pts)
    tech_findings = tech.get("findings", [])
    ssl_status = tech.get("ssl_certificate", {}).get("status", "")
    mob_status = tech.get("mobile_usability", {}).get("status", "")
    dim9 = 0.0
    if ssl_status in ["Expired", "Plain HTTP", "Invalid"]:
        dim9 += 5.0
        gaps_identified.append(("Security", f"SSL certificate issue: {ssl_status}"))
    elif "Poor" in mob_status or "Needs Improvement" in mob_status:
        dim9 += 4.0
        gaps_identified.append(("Mobile Usability", mob_status))
    else:
        dim9 = 1.0
    dimension_scores["mobile_ssl_security"] = round(dim9 * (w["mobile_ssl_security"] / 5.0), 1)

    # Calculate final uncalibrated raw score sum
    raw_total = sum(dimension_scores.values())
    final_score = int(round(min(100, max(0, raw_total))))

    # Prioritization classification according to prompt requirements:
    # High Priority, Medium Priority, Low Priority, Manual Review
    is_failed_audit = not website or perf_status == "Scan Failed"
    
    if is_failed_audit:
        priority_label = "Manual Review"
        action = "Perform manual domain inspection; automated crawler could not reach server."
    elif final_score >= 68:
        priority_label = "High Priority"
        action = "Initiate personalized multi-channel outreach targeting verified decision maker."
    elif final_score >= 45:
        priority_label = "Medium Priority"
        action = "Nurture lead; research missing decision-maker contact details before cold outreach."
    else:
        priority_label = "Low Priority"
        action = "Archive or monitor; business digital infrastructure is largely up to date."

    main_gap = gaps_identified[0][1] if gaps_identified else "No critical opportunity gaps identified."

    return {
        "research_score": final_score,
        "research_priority": priority_label,
        "dimension_scores": dimension_scores,
        "weights_applied": w,
        "main_identified_gap": main_gap,
        "suggested_next_action": action,
        "gaps_count": len(gaps_identified)
    }
