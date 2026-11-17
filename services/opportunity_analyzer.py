"""
LeadHunter Business Opportunity Analyzer
Generates evidence-backed business opportunities using a strict 9-field schema.
Purges unsupported conversion claims, ranking guarantees, and speculative statistics.
"""

from services.lead_scoring import calculate_lead_score

def analyze_business_opportunities(
    features_result: dict,
    seo_result: dict,
    technical_result: dict,
    decision_maker: str,
    email: str,
    business_name: str = "",
    target_url: str = "",
    scoring_weights: dict = None,
    phone: str = "",
    email_status: str = "",
    performance_result: dict = None
):
    """
    Evaluates detected infrastructure and on-page audits to identify concrete business gaps.
    Returns structured 9-field opportunity records and links to explainable lead scoring.
    """
    opportunities = []
    outreach_hooks = []

    biz = business_name or "your company"
    evidence_url = target_url or "scanned website"

    # Opportunity 0: Lead Capture (Interactive Web Inquiry / Quote Form)
    lead_capture = features_result.get("lead_capture", {})
    lc_status = lead_capture.get("status", "")
    lc_details = lead_capture.get("details", {}) or {}
    if lc_status == "Not Detected":
        opportunities.append({
            "Business Name": biz,
            "Opportunity Category": "Lead Capture",
            "Finding": "No Public Contact or Quote Form Detected",
            "Evidence": "No interactive contact forms, quote request forms, or click-to-call CTAs were detected on scanned pages.",
            "Confidence": "Medium",
            "Research Status": "Needs Review",
            "Recommended Service": "Interactive Lead Capture & Quote Request Form Implementation",
            "Related Finding": "No Public Contact or Quote Form Detected",
            "Evidence URL": evidence_url,
            "Evidence Description": "No interactive contact forms, quote request forms, or click-to-call CTAs were detected on scanned pages.",
            "Potential Business Impact": "No public web inquiry or quote request form was detected on scanned pages; does not determine whether inquiries are handled via phone, external portals, or secondary landing pages.",
            "Confidence Level": "Medium"
        })
    elif lc_status == "Detected":
        has_quote = lc_details.get("has_quote_form", False)
        has_contact = lc_details.get("has_contact_form", False)
        if not has_quote and not has_contact:
            providers_str = ", ".join(lead_capture.get("providers", [])) or "non-form contact links"
            ev_text = f"Only {providers_str} detected on scanned pages; no interactive HTML inquiry or quote form observed."
            opportunities.append({
                "Business Name": biz,
                "Opportunity Category": "Lead Capture",
                "Finding": "No Public Web Inquiry or Quote Form Detected",
                "Evidence": ev_text,
                "Confidence": "Medium",
                "Research Status": "Needs Review",
                "Recommended Service": "Interactive Web Inquiry & Quote Request Form Integration",
                "Related Finding": "No Public Web Inquiry or Quote Form Detected",
                "Evidence URL": evidence_url,
                "Evidence Description": ev_text,
                "Potential Business Impact": "No public HTML inquiry or estimate form was detected on scanned pages; does not determine whether estimates or inquiries are handled via phone dispatch, external portals, or subpages.",
                "Confidence Level": "Medium"
            })
        elif has_contact and not has_quote:
            ev_text = "General contact form detected on scanned pages, but no dedicated quote or estimate request workflow was observed."
            opportunities.append({
                "Business Name": biz,
                "Opportunity Category": "Lead Capture",
                "Finding": "No Dedicated Quote / Estimate Form Detected",
                "Evidence": ev_text,
                "Confidence": "Medium",
                "Research Status": "Needs Review",
                "Recommended Service": "Dedicated Online Estimate & Quote Request Workflow",
                "Related Finding": "No Dedicated Quote / Estimate Form Detected",
                "Evidence URL": evidence_url,
                "Evidence Description": ev_text,
                "Potential Business Impact": "A general contact form is present, but no dedicated quote or estimate request form was detected on scanned pages; does not determine whether quote qualification occurs by phone or external tools.",
                "Confidence Level": "Medium"
            })

    # Opportunity 1: Booking & Self-Service Scheduling
    booking = features_result.get("booking", {})
    b_status = booking.get("status", "")
    if b_status == "Not Detected":
        opportunities.append({
            "Business Name": biz,
            "Opportunity Category": "Workflow Automation",
            "Finding": "No Public Booking Widget Detected",
            "Evidence": "No self-service scheduling scripts or embedded booking widgets (Calendly, Acuity, ServiceTitan, etc.) identified on scanned pages.",
            "Confidence": "Medium",
            "Research Status": "Needs Review",
            "Recommended Service": "Online Booking & Appointment Scheduling Integration",
            "Related Finding": "Missing Online Scheduling Widget",
            "Evidence URL": evidence_url,
            "Evidence Description": "No self-service scheduling scripts or embedded booking widgets (Calendly, Acuity, ServiceTitan, etc.) identified on scanned pages.",
            "Potential Business Impact": "No public self-service booking widget was identified on scanned pages; does not determine whether scheduling is coordinated via external portals, dispatch systems, or direct communication.",
            "Confidence Level": "Medium"
        })
        outreach_hooks.append(
            f"Does {biz} offer direct online self-scheduling for customers, or do you coordinate appointments through another workflow?"
        )

    # Opportunity 2: Conversational Lead Capture / 24/7 Chatbot
    chatbot = features_result.get("chatbot", {})
    if chatbot.get("status") == "Not Detected":
        opportunities.append({
            "Business Name": biz,
            "Opportunity Category": "AI Automation",
            "Finding": "No Public Chatbot Detected",
            "Evidence": "No conversational widget scripts or live chat providers detected in page DOM.",
            "Confidence": "Medium",
            "Research Status": "Needs Review",
            "Recommended Service": "24/7 AI Chatbot & Conversational Lead Capture",
            "Related Finding": "Absence of Live Chat / Chatbot Widget",
            "Evidence URL": evidence_url,
            "Evidence Description": "No conversational widget scripts or live chat providers detected in page DOM.",
            "Potential Business Impact": "No interactive conversational chat provider was detected in the page DOM; does not determine how after-hours web visitor questions or leads are routed internally.",
            "Confidence Level": "Medium"
        })
        outreach_hooks.append(
            f"How does {biz} currently handle after-hours website visitor inquiries—would an interactive conversational assistant be worth exploring?"
        )

    # Opportunity 3: AI Voice Receptionist / Phone Overflow
    voice_agent = features_result.get("voice_agent", {})
    if voice_agent.get("status") == "Not Detected":
        opportunities.append({
            "Business Name": biz,
            "Opportunity Category": "AI Voice Automation",
            "Finding": "No Public AI Phone Integration Detected",
            "Evidence": "No telephony automation or AI voice agent provider markers identified in page assets.",
            "Confidence": "Medium",
            "Research Status": "Needs Review",
            "Recommended Service": "AI Voice Receptionist & Missed Call Follow-Up Automation",
            "Related Finding": "No AI Phone Integration Detected",
            "Evidence URL": evidence_url,
            "Evidence Description": "No telephony automation or AI voice agent provider markers identified in page assets.",
            "Potential Business Impact": "No automated voice assistant or telephony automation markers were identified in public assets; does not determine current call routing, answering service coverage, or office dispatch processes.",
            "Confidence Level": "Medium"
        })

    # Opportunity 4: CRM Integration & Pipeline Tracking
    crm = features_result.get("crm", {})
    if crm.get("status") == "Not Detected":
        opportunities.append({
            "Business Name": biz,
            "Opportunity Category": "CRM Integration",
            "Finding": "No Public CRM Tracker Detected",
            "Evidence": "No embedded forms or analytics trackers from known CRM providers (HubSpot, GoHighLevel, Salesforce, Zoho, etc.) detected on scanned pages.",
            "Confidence": "Medium",
            "Research Status": "Needs Review",
            "Recommended Service": "Centralized CRM Integration & Lead Workflow Automation",
            "Related Finding": "No CRM Tracking or Forms Detected",
            "Evidence URL": evidence_url,
            "Evidence Description": "No embedded forms or analytics trackers from known CRM providers (HubSpot, GoHighLevel, Salesforce, Zoho, etc.) detected on scanned pages.",
            "Potential Business Impact": "No public CRM integration trackers or third-party embed forms were identified on scanned pages; does not determine whether customer records are managed through backend ERP, specialized industry software, or internal databases.",
            "Confidence Level": "Medium"
        })

    # Opportunity 5: Review & Reputation Management Automation
    reviews = features_result.get("review_management", {})
    if reviews.get("status") == "Not Detected":
        opportunities.append({
            "Business Name": biz,
            "Opportunity Category": "Reputation Automation",
            "Finding": "No Public Review Widget Detected",
            "Evidence": "No third-party review widgets (Birdeye, Podium, Trustpilot) or automated review request links identified.",
            "Confidence": "Medium",
            "Research Status": "Needs Review",
            "Recommended Service": "Automated Review Request & Reputation Management System",
            "Related Finding": "Missing Review Widget / Automation",
            "Evidence URL": evidence_url,
            "Evidence Description": "No third-party review widgets (Birdeye, Podium, Trustpilot) or automated review request links identified.",
            "Potential Business Impact": "No third-party review widgets or automated feedback collection badges were detected on public pages; does not determine how customer feedback or testimonial collection is handled after service delivery.",
            "Confidence Level": "Medium"
        })
        outreach_hooks.append(
            f"How does {biz} currently collect and showcase customer reviews—is post-service feedback collection something you're looking to automate?"
        )

    # Opportunity 6: Technical SEO Optimization
    seo_findings = seo_result.get("findings", [])
    high_seo = [f for f in seo_findings if isinstance(f, dict) and f.get("severity") == "High"]
    is_seo_valid = seo_result.get("status") != "Blocked / Inconclusive" and seo_result.get("seo_score") is not None
    if is_seo_valid and (high_seo or seo_result.get("seo_score", 100) < 75):
        primary_issue = high_seo[0]["name"] if high_seo else "On-Page Metadata Gaps"
        evidence_text = high_seo[0]["evidence"] if high_seo else "Page title, meta description, or heading hierarchy lacks optimization."
        opportunities.append({
            "Business Name": biz,
            "Opportunity Category": "Technical SEO",
            "Finding": primary_issue,
            "Evidence": evidence_text,
            "Confidence": "High",
            "Research Status": "Detected",
            "Recommended Service": "Technical SEO Optimization & Structured Data Implementation",
            "Related Finding": primary_issue,
            "Evidence URL": evidence_url,
            "Evidence Description": evidence_text,
            "Potential Business Impact": "Search engine crawlers may receive incomplete metadata, which can affect snippet display in organic search results.",
            "Confidence Level": "High"
        })
        outreach_hooks.append(
            f"Observed that certain technical SEO metadata tags on {biz}'s website ({primary_issue.lower()}) could be refreshed—is technical on-page SEO currently on your radar?"
        )

    # Opportunity 7: Mobile Usability & Responsive Redesign
    mobile_info = technical_result.get("mobile_usability", {})
    is_tech_valid = technical_result.get("status") not in ["Inconclusive", "Blocked / Inconclusive"]
    has_confirmed_viewport_issue = bool(
        mobile_info and (
            mobile_info.get("has_viewport") is False or
            mobile_info.get("fixed_viewport_width") is True or
            mobile_info.get("overflow_risk") is True
        )
    )
    if is_tech_valid and has_confirmed_viewport_issue:
        vp_evidence = (
            "Missing <meta name='viewport'> tag on scanned page."
            if mobile_info.get("has_viewport") is False
            else f"Non-responsive fixed-width viewport configuration detected ({mobile_info.get('viewport_content', '')})."
        )
        opportunities.append({
            "Business Name": biz,
            "Opportunity Category": "Website Development",
            "Finding": "Mobile Viewport / Formatting Issues",
            "Evidence": vp_evidence,
            "Confidence": "High",
            "Research Status": "Detected",
            "Recommended Service": "Mobile-Responsive Layout Optimization",
            "Related Finding": "Mobile Viewport / Formatting Issues",
            "Evidence URL": evidence_url,
            "Evidence Description": vp_evidence,
            "Potential Business Impact": "Mobile devices may scale the page improperly without a responsive device-width viewport configuration.",
            "Confidence Level": "High"
        })
    elif is_tech_valid and mobile_info.get("overflow_warning"):
        warn_evidence = "Inline wide layout container detected in static HTML; visual mobile testing is required to confirm whether external CSS overrides width."
        opportunities.append({
            "Business Name": biz,
            "Opportunity Category": "Website Development",
            "Finding": "Potential Fixed-Width Layout Container (Needs Visual Review)",
            "Evidence": warn_evidence,
            "Confidence": "Low",
            "Research Status": "Needs Review",
            "Recommended Service": "Mobile-Responsive Layout Review",
            "Related Finding": "Inline Fixed-Width Layout Container (Needs Review)",
            "Evidence URL": evidence_url,
            "Evidence Description": warn_evidence,
            "Potential Business Impact": "Inline fixed-width container styles may cause horizontal scrolling on small screens if not overridden by responsive stylesheets.",
            "Confidence Level": "Low"
        })

    # Opportunity 8: SSL Security & HTTPS Enforcement
    ssl_info = technical_result.get("ssl_certificate", {})
    if is_tech_valid and ssl_info.get("status") in ["Expired", "Plain HTTP", "Invalid"]:
        opportunities.append({
            "Business Name": biz,
            "Opportunity Category": "Website Security",
            "Finding": f"SSL Status: {ssl_info.get('status')}",
            "Evidence": ssl_info.get("evidence", "Certificate is expired or plain HTTP is served."),
            "Confidence": "High",
            "Research Status": "Detected",
            "Recommended Service": "SSL Certificate Renewal & HTTPS 301 Enforcement",
            "Related Finding": f"SSL Status: {ssl_info.get('status')}",
            "Evidence URL": evidence_url,
            "Evidence Description": ssl_info.get("evidence", "Certificate is expired or plain HTTP is served."),
            "Potential Business Impact": "Browsers mark unencrypted or expired certificates with visual security warnings to visitors.",
            "Confidence Level": "High"
        })

    # Build container for lead scoring calculation
    scoring_input = {
        "Website": target_url,
        "Email": email,
        "Email Status": email_status,
        "Phone": phone,
        "Decision Maker": decision_maker,
        "intelligence": {
            "seo": seo_result,
            "technical": technical_result,
            "features": features_result,
            "performance": performance_result or {},
            "opportunities": {"detected_opportunities": opportunities}
        }
    }

    scoring = calculate_lead_score(
        audit_data=scoring_input,
        weights=scoring_weights,
        business_name=biz
    )

    # Guarantee Main Opportunity is strictly derived from an actual opportunity record when opportunities exist
    if opportunities:
        detected_opps = [o for o in opportunities if o.get("Research Status") == "Detected"]
        primary_opp = detected_opps[0] if detected_opps else opportunities[0]
        main_gap = primary_opp["Finding"]
        scoring["main_identified_gap"] = main_gap
        if scoring.get("priority") == "High":
            scoring["priority_reason"] = f"High opportunity score ({scoring['research_score']}/100) with key gaps in {main_gap}."
    else:
        main_gap = "No opportunity detected"
        scoring["main_identified_gap"] = main_gap

    return {
        "lead_score": scoring["research_score"],
        "priority": scoring.get("priority", "Manual Review"),
        "priority_tier": scoring["research_priority"],
        "priority_reason": scoring.get("priority_reason", ""),
        "scoring_details": scoring,
        "opportunities_count": len(opportunities),
        "detected_opportunities": opportunities,
        "outreach_hooks": outreach_hooks,
        "main_gap": main_gap,
        "next_action": scoring["suggested_next_action"],
        "summary": f"{len(opportunities)} evidence-backed opportunity gaps identified. Lead Priority: {scoring['research_priority']}."
    }
