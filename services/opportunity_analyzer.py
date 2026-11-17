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
    scoring_weights: dict = None
):
    """
    Evaluates detected infrastructure and on-page audits to identify concrete business gaps.
    Returns structured 9-field opportunity records and links to explainable lead scoring.
    """
    opportunities = []
    outreach_hooks = []

    biz = business_name or "your company"
    evidence_url = target_url or "scanned website"

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
            "Potential Business Impact": "Prospective clients seeking immediate appointment scheduling cannot self-book and must wait for manual callback.",
            "Confidence Level": "Medium"
        })
        outreach_hooks.append(
            f"Noticed {biz}'s website currently requires phone calls or plain emails for appointments—adding self-service online scheduling allows customers to book directly."
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
            "Potential Business Impact": "Inquiries outside standard operating hours may go unanswered if visitors do not wish to leave a static contact form submission.",
            "Confidence Level": "Medium"
        })
        outreach_hooks.append(
            f"Observed that {biz}'s website doesn't have an interactive chat widget—deploying an automated concierge can capture and qualify after-hours inquiries."
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
            "Potential Business Impact": "Inbound callers during field work or peak hours may reach standard voicemail, delaying quote response time.",
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
            "Potential Business Impact": "Inbound leads may require manual copying into spreadsheets, increasing risk of delayed lead follow-ups.",
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
            "Potential Business Impact": "Relying strictly on manual review requests often leads to slower feedback collection compared to automated post-service flows.",
            "Confidence Level": "Medium"
        })
        outreach_hooks.append(
            f"Setting up an automated SMS review collection flow for {biz} can help systematically collect feedback from satisfied clients right after service completion."
        )

    # Opportunity 6: Technical SEO Optimization
    seo_findings = seo_result.get("findings", [])
    high_seo = [f for f in seo_findings if isinstance(f, dict) and f.get("severity") == "High"]
    if high_seo or seo_result.get("seo_score", 100) < 75:
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
            "Potential Business Impact": "Search engine crawlers may fail to index important service keywords, limiting organic search discoverability.",
            "Confidence Level": "High"
        })
        outreach_hooks.append(
            f"Spotted a couple of technical on-page items on {biz}'s website (like {primary_issue.lower()}) that search engines look for when ranking local service queries."
        )

    # Opportunity 7: Mobile Usability & Responsive Redesign
    mobile_info = technical_result.get("mobile_usability", {})
    if not mobile_info.get("has_viewport") or mobile_info.get("overflow_risk"):
        opportunities.append({
            "Business Name": biz,
            "Opportunity Category": "Website Development",
            "Finding": "Mobile Viewport / Formatting Issues",
            "Evidence": "Missing viewport meta tag or fixed pixel widths detected causing horizontal overflow risks on mobile viewports.",
            "Confidence": "High",
            "Research Status": "Detected",
            "Recommended Service": "Mobile-Responsive Layout Optimization",
            "Related Finding": "Mobile Viewport / Formatting Issues",
            "Evidence URL": evidence_url,
            "Evidence Description": "Missing viewport meta tag or fixed pixel widths detected causing horizontal overflow risks on mobile viewports.",
            "Potential Business Impact": "Mobile visitors may experience horizontal scrolling or layout truncation, reducing form submission completion.",
            "Confidence Level": "High"
        })

    # Opportunity 8: SSL Security & HTTPS Enforcement
    ssl_info = technical_result.get("ssl_certificate", {})
    if ssl_info.get("status") in ["Expired", "Plain HTTP", "Invalid"]:
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
            "Potential Business Impact": "Modern browsers mark the website as 'Not Secure', discouraging visitors from entering contact details.",
            "Confidence Level": "High"
        })

    # Build mock container for lead scoring calculation
    scoring_input = {
        "Website": target_url,
        "Email": email,
        "Decision Maker": decision_maker,
        "intelligence": {
            "seo": seo_result,
            "technical": technical_result,
            "features": features_result,
            "performance": {},
            "opportunities": {"detected_opportunities": opportunities}
        }
    }

    scoring = calculate_lead_score(
        audit_data=scoring_input,
        weights=scoring_weights,
        business_name=biz
    )

    return {
        "lead_score": scoring["research_score"],
        "priority_tier": scoring["research_priority"],
        "scoring_details": scoring,
        "opportunities_count": len(opportunities),
        "detected_opportunities": opportunities,
        "outreach_hooks": outreach_hooks,
        "main_gap": scoring["main_identified_gap"],
        "next_action": scoring["suggested_next_action"],
        "summary": f"{len(opportunities)} evidence-backed opportunity gaps identified. Lead Priority: {scoring['research_priority']}."
    }
