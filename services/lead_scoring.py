"""
LeadHunter Dedicated Lead Scoring Engine
Implements a transparent, explainable 9-dimension scoring matrix (0-100)
with configurable weights, no arbitrary baselines, explicit handling of Unknown /
Scan Failed audit states, and standardized priority tiers.
"""

# Default weights totaling exactly 100
DEFAULT_SCORING_WEIGHTS = {
    "website_performance": 10,        # Speed, asset weight, TTFB
    "technical_seo": 15,              # Meta tags, headings, canonicals, sitemap
    "lead_capture": 15,               # Form availability, CTAs, quote requests
    "booking_automation": 15,         # Self-service scheduling gap vs presence
    "chatbot_voice": 10,              # Conversational agent presence vs opportunity
    "business_relevance": 10,         # Local commercial validity & channels
    "contact_availability": 10,       # Direct phone & verified email presence
    "decision_maker_availability": 10,# Owner/CEO identified
    "mobile_ssl_security": 5          # Mobile viewport & valid HTTPS/SSL
}

DEFAULT_PRIORITY_THRESHOLDS = {
    "high": 68,
    "medium": 40
}

def calculate_lead_score(
    audit_data: dict,
    weights: dict = None,
    business_name: str = "",
    google_rating: float = None,
    review_count: int = None,
    priority_thresholds: dict = None
) -> dict:
    """
    Computes an explainable research priority score (0-100) across 9 dimensions.
    Handles 'Unknown', 'Scan Failed', missing, and incomplete audit data explicitly
    with neutral confidence scoring without inflating scores or fabricating absence.
    Returns dimension-level breakdown, dimension-level explanations, priority tier,
    main identified gap, and suggested next action.
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
    dimension_explanations = {}
    gaps_identified = []

    # Safe extraction of audit branches
    intel = audit_data.get("intelligence", {}) if isinstance(audit_data, dict) else {}
    seo = intel.get("seo", {}) or {}
    tech = intel.get("technical", {}) or {}
    features = intel.get("features", {}) or {}
    perf = intel.get("performance", {}) or {}

    email = audit_data.get("Email", "") or audit_data.get("Contact Email", "")
    phone = audit_data.get("Phone Number", "") or audit_data.get("Phone", "")
    dm = audit_data.get("Decision Maker", "")
    website = audit_data.get("Website", "")

    # -------------------------------------------------------------
    # Dimension 1: Website Performance (Weight: 10 pts)
    # -------------------------------------------------------------
    perf_status = perf.get("audit_status", "")
    mobile_score = perf.get("mobile_score")

    if perf_status == "Scan Failed":
        dim1 = 4.0
        expl1 = "Performance audit failed or server timed out; neutral reduced-confidence score assigned."
    elif mobile_score is not None:
        if mobile_score < 50:
            dim1 = 10.0
            expl1 = f"Low mobile performance score ({mobile_score}/100) indicates significant optimization opportunity."
            gaps_identified.append(("Website Performance", f"Low mobile performance score ({mobile_score}/100)"))
        elif mobile_score < 75:
            dim1 = 6.0
            expl1 = f"Moderate mobile performance score ({mobile_score}/100) shows room for speed improvement."
            gaps_identified.append(("Website Performance", f"Moderate mobile performance score ({mobile_score}/100)"))
        else:
            dim1 = 2.0
            expl1 = f"Strong mobile performance score ({mobile_score}/100); minimal optimization gap."
    else:
        local_diag = perf.get("local_diagnostics", {}) or {}
        html_size = local_diag.get("html_size_kb", 0)
        if html_size > 250:
            dim1 = 7.0
            expl1 = f"Large HTML document payload ({html_size} KB) indicates potential asset optimization opportunity."
            gaps_identified.append(("Website Performance", f"Large HTML payload ({html_size} KB)"))
        elif not perf:
            dim1 = 5.0
            expl1 = "Performance data unavailable; neutral score assigned without penalty."
        else:
            dim1 = 5.0
            expl1 = "Local performance diagnostics show acceptable asset weight; neutral score applied."

    dimension_scores["website_performance"] = round(dim1 * (w["website_performance"] / 10.0), 1)
    dimension_explanations["website_performance"] = expl1

    # -------------------------------------------------------------
    # Dimension 2: Technical SEO (Weight: 15 pts)
    # -------------------------------------------------------------
    seo_score = seo.get("seo_score")
    seo_status = seo.get("status", "")

    if seo_status == "Scan Failed" or not seo:
        dim2 = 5.0
        expl2 = "Technical SEO scan incomplete or unavailable; neutral score assigned without penalty."
    elif seo_score is not None:
        if seo_score < 60:
            dim2 = 10.0
            expl2 = f"Critical on-page technical SEO deficiencies identified (score {seo_score}/100)."
            gaps_identified.append(("Technical SEO", f"Critical on-page SEO issues (score {seo_score}/100)"))
        elif seo_score < 80:
            dim2 = 7.0
            expl2 = f"Moderate on-page SEO gaps identified (score {seo_score}/100)."
            gaps_identified.append(("Technical SEO", f"Moderate on-page SEO gaps (score {seo_score}/100)"))
        else:
            dim2 = 3.0
            expl2 = f"On-page SEO structure is well-optimized (score {seo_score}/100); minimal pitch opportunity."
    else:
        dim2 = 5.0
        expl2 = "Technical SEO score not calculated; neutral score assigned."

    dimension_scores["technical_seo"] = round(dim2 * (w["technical_seo"] / 10.0), 1)
    dimension_explanations["technical_seo"] = expl2

    # -------------------------------------------------------------
    # Dimension 3: Lead Capture (Weight: 15 pts)
    # -------------------------------------------------------------
    lc = features.get("lead_capture", {}) or {}
    lc_status = lc.get("status", "")

    if lc_status == "Scan Failed" or not lc:
        dim3 = 4.0
        expl3 = "Lead capture audit unavailable or failed; neutral confidence score applied."
    elif lc_status == "Unknown":
        dim3 = 5.0
        expl3 = "Lead capture detection was inconclusive; neutral score assigned without assuming absence of forms."
    elif lc_status == "Not Detected":
        dim3 = 10.0
        expl3 = "No contact forms or quote request CTAs detected on scanned pages; confirmed lead capture gap."
        gaps_identified.append(("Lead Capture", "No contact forms or conversion CTAs identified on scanned pages"))
    elif lc_status == "Detected":
        if lc.get("details", {}).get("has_quote_form") is False:
            dim3 = 6.0
            expl3 = "General contact form present, but estimate/quote request workflow is missing."
            gaps_identified.append(("Lead Capture", "Basic contact form present, but no quote/estimate request workflow"))
        else:
            dim3 = 2.0
            expl3 = "Comprehensive inquiry and lead capture forms detected on site."
    else:
        dim3 = 5.0
        expl3 = "Lead capture presence is unconfirmed; neutral score applied."

    dimension_scores["lead_capture"] = round(dim3 * (w["lead_capture"] / 10.0), 1)
    dimension_explanations["lead_capture"] = expl3

    # -------------------------------------------------------------
    # Dimension 4: Booking Automation (Weight: 15 pts)
    # -------------------------------------------------------------
    booking = features.get("booking", {}) or {}
    b_status = booking.get("status", "")

    if b_status == "Scan Failed" or not booking:
        dim4 = 4.0
        expl4 = "Booking system scan unavailable or failed; neutral confidence score applied."
    elif b_status == "Unknown":
        dim4 = 5.0
        expl4 = "Booking system presence is inconclusive; neutral score assigned without assuming absence of service."
    elif b_status == "Not Detected":
        dim4 = 10.0
        expl4 = "No online scheduling or booking integration detected on scanned pages; confirmed automation gap."
        gaps_identified.append(("Booking Automation", "No online scheduling or booking integration identified"))
    elif b_status == "Detected":
        dim4 = 1.0
        expl4 = "Online booking or appointment scheduling integration verified on site."
    else:
        dim4 = 5.0
        expl4 = "Booking system presence is unconfirmed; neutral score applied."

    dimension_scores["booking_automation"] = round(dim4 * (w["booking_automation"] / 10.0), 1)
    dimension_explanations["booking_automation"] = expl4

    # -------------------------------------------------------------
    # Dimension 5: Chatbot / Voice Agent (Weight: 10 pts)
    # -------------------------------------------------------------
    chat = features.get("chatbot", {}) or {}
    voice = features.get("voice_agent", {}) or {}
    chat_status = chat.get("status", "")
    voice_status = voice.get("status", "")

    if (chat_status == "Scan Failed" and voice_status == "Scan Failed") or (not chat and not voice):
        dim5 = 4.0
        expl5 = "Conversational automation scan incomplete; neutral score applied."
    elif chat_status == "Unknown" and voice_status == "Unknown":
        dim5 = 5.0
        expl5 = "Chatbot and voice agent status inconclusive; neutral score assigned without assuming absence."
    elif chat_status == "Not Detected" and voice_status == "Not Detected":
        dim5 = 10.0
        expl5 = "No live chat, chatbot, or AI voice agent scripts detected on scanned pages."
        gaps_identified.append(("AI Automation", "No live chat or conversational bot scripts detected"))
    elif chat_status == "Not Detected":
        dim5 = 6.0
        expl5 = "Conversational chat widget not detected, offering potential 24/7 lead concierge opportunity."
        gaps_identified.append(("AI Automation", "No live chat widget detected on scanned pages"))
    elif chat_status == "Detected" or voice_status == "Detected":
        dim5 = 1.0
        expl5 = "Active live chat or AI conversational tools verified on site."
    else:
        dim5 = 4.0
        expl5 = "Conversational agent presence partially verified or inconclusive; neutral score applied."

    dimension_scores["chatbot_voice"] = round(dim5 * (w["chatbot_voice"] / 10.0), 1)
    dimension_explanations["chatbot_voice"] = expl5

    # -------------------------------------------------------------
    # Dimension 6: Business Relevance & Commercial Activity (Weight: 10 pts)
    # -------------------------------------------------------------
    if website and (phone or email):
        dim6 = 9.0
        expl6 = "Active commercial business with verified online presence and established contact channels."
    elif website:
        dim6 = 6.0
        expl6 = "Active domain verified; primary direct contact points are limited."
    else:
        dim6 = 2.0
        expl6 = "Minimal verifiable digital footprint; lower commercial research priority."

    dimension_scores["business_relevance"] = round(dim6 * (w["business_relevance"] / 10.0), 1)
    dimension_explanations["business_relevance"] = expl6

    # -------------------------------------------------------------
    # Dimension 7: Contact Reachability (Weight: 10 pts)
    # -------------------------------------------------------------
    dim7 = 0.0
    has_email = bool(email and "@" in email)
    has_phone = bool(phone and phone.strip() and phone != "-")

    if has_email and has_phone:
        dim7 = 10.0
        expl7 = "Both verified direct email and telephone number are available for outreach."
    elif has_email:
        dim7 = 6.0
        expl7 = "Verified direct email available; telephone number not identified."
    elif has_phone:
        dim7 = 4.0
        expl7 = "Telephone number available; direct email not identified."
    else:
        dim7 = 0.0
        expl7 = "No direct contact channels available for outreach."

    dimension_scores["contact_availability"] = round(dim7 * (w["contact_availability"] / 10.0), 1)
    dimension_explanations["contact_availability"] = expl7

    # -------------------------------------------------------------
    # Dimension 8: Decision Maker Availability (Weight: 10 pts)
    # -------------------------------------------------------------
    if dm and dm.strip() and dm != "-":
        dim8 = 10.0
        expl8 = f"Identified key decision maker ({dm}) for executive outreach."
    else:
        dim8 = 2.0
        expl8 = "Decision maker name not yet identified; research required."
        gaps_identified.append(("Executive Outreach", "Decision maker name not yet identified"))

    dimension_scores["decision_maker_availability"] = round(dim8 * (w["decision_maker_availability"] / 10.0), 1)
    dimension_explanations["decision_maker_availability"] = expl8

    # -------------------------------------------------------------
    # Dimension 9: Mobile Usability & SSL Security (Weight: 5 pts)
    # -------------------------------------------------------------
    ssl_status = tech.get("ssl_certificate", {}).get("status", "")
    mob_status = tech.get("mobile_usability", {}).get("status", "")
    tech_status = tech.get("status", "")

    if tech_status == "Scan Failed" or not tech:
        dim9 = 2.5
        expl9 = "Security and mobile responsiveness scan incomplete; neutral score applied."
    elif ssl_status in ["Expired", "Plain HTTP", "Invalid"]:
        dim9 = 5.0
        expl9 = f"Critical SSL certificate issue detected ({ssl_status}); immediate security pitch opportunity."
        gaps_identified.append(("Security", f"SSL certificate issue: {ssl_status}"))
    elif "Poor" in mob_status or "Needs Improvement" in mob_status:
        dim9 = 4.0
        expl9 = f"Mobile usability deficiency identified ({mob_status})."
        gaps_identified.append(("Mobile Usability", mob_status))
    elif ssl_status == "Unknown" or mob_status == "Unknown":
        dim9 = 2.5
        expl9 = "SSL or mobile usability inconclusive; neutral score applied."
    else:
        dim9 = 1.0
        expl9 = "Valid SSL certificate and mobile responsive design verified."

    dimension_scores["mobile_ssl_security"] = round(dim9 * (w["mobile_ssl_security"] / 5.0), 1)
    dimension_explanations["mobile_ssl_security"] = expl9

    # -------------------------------------------------------------
    # Score Aggregation & Priority Classification
    # -------------------------------------------------------------
    raw_total = sum(dimension_scores.values())
    final_score = int(round(min(100, max(0, raw_total))))

    is_failed_audit = (
        not website or
        perf_status == "Scan Failed" or
        seo_status == "Scan Failed" or
        (lc_status == "Scan Failed" and b_status == "Scan Failed")
    )

    all_critical_unknown = (
        lc_status in ["Unknown", "Scan Failed", None, ""] and
        b_status in ["Unknown", "Scan Failed", None, ""] and
        chat_status in ["Unknown", "Scan Failed", None, ""]
    )
    is_insufficient_data = (not intel) or (all_critical_unknown and seo_score is None and mobile_score is None)

    high_threshold = (priority_thresholds or {}).get("high", DEFAULT_PRIORITY_THRESHOLDS["high"])
    medium_threshold = (priority_thresholds or {}).get("medium", DEFAULT_PRIORITY_THRESHOLDS["medium"])

    main_gap = gaps_identified[0][1] if gaps_identified else "No critical opportunity gaps identified."

    if is_failed_audit or is_insufficient_data:
        priority_label = "Manual Review"
        priority_short = "Manual Review"
        priority_reason = "Crawler data incomplete or website unreachable; requires manual review."
        action = "Perform manual domain inspection; automated crawler data is incomplete or unreachable."
    elif final_score >= high_threshold:
        priority_label = "High Priority"
        priority_short = "High"
        priority_reason = f"High opportunity score ({final_score}/100) with key gaps in {main_gap}."
        action = "Initiate personalized multi-channel outreach targeting verified decision maker."
    elif final_score >= medium_threshold:
        priority_label = "Medium Priority"
        priority_short = "Medium"
        priority_reason = f"Moderate score ({final_score}/100); several digital infrastructure gaps identified."
        action = "Nurture lead; research missing decision-maker contact details before cold outreach."
    else:
        priority_label = "Low Priority"
        priority_short = "Low"
        priority_reason = f"Low score ({final_score}/100); digital infrastructure is largely up to date."
        action = "Archive or monitor; business digital infrastructure is largely up to date."

    return {
        "research_score": final_score,
        "research_priority": priority_label,
        "priority": priority_short,
        "priority_reason": priority_reason,
        "dimension_scores": dimension_scores,
        "dimension_explanations": dimension_explanations,
        "weights_applied": w,
        "main_identified_gap": main_gap,
        "suggested_next_action": action,
        "gaps_count": len(gaps_identified)
    }
