"""
LeadHunter Opportunity Analyzer & Lead Prioritization Service
Generates evidence-based B2B service recommendations, lead scoring (0-100),
and tailored outreach angles based on real technical and infrastructure gaps.
Never blanket-recommends services without supporting evidence.
"""

def analyze_business_opportunities(features_result: dict, seo_result: dict, technical_result: dict, decision_maker: str, email: str, business_name: str = ""):
    """
    Evaluates detected infrastructure and on-page audits to identify concrete business gaps.
    """
    opportunities = []
    outreach_hooks = []

    dm_name = decision_maker.split('(')[0].strip() if decision_maker else ""
    first_name = dm_name.split()[0] if dm_name else "Team"
    biz = business_name or "your company"

    # 1. Booking & Scheduling Automation
    booking = features_result.get("booking", {})
    if booking.get("status") == "Not Detected":
        opportunities.append({
            "service": "Online Booking & Appointment Scheduling Automation",
            "category": "Workflow Automation",
            "priority": "High",
            "evidence": "No self-service scheduling widgets (Calendly, Acuity, ServiceTitan, etc.) detected on site.",
            "impact": "Prospective clients who want immediate booking may bounce to competitors who offer instant appointment confirmation.",
            "solution": "Integrate a frictionless, automated scheduling flow synced with your dispatch calendar."
        })
        outreach_hooks.append(f"Notice you don't currently offer instant online scheduling for {biz}—setting that up typically lifts local booking conversion by 25-30%.")

    # 2. 24/7 AI Chatbot & After-Hours Lead Capture
    chatbot = features_result.get("chatbot", {})
    if chatbot.get("status") == "Not Detected":
        opportunities.append({
            "service": "24/7 AI Chatbot & Conversational Lead Capture",
            "category": "AI Automation",
            "priority": "High",
            "evidence": "No live chat or automated chatbot scripts detected on scanned pages.",
            "impact": "Over 40% of home/business inquiries occur after 6 PM; without an automated agent, after-hours leads often go unanswered.",
            "solution": "Deploy an AI concierge trained on your service pricing and FAQ to qualify and capture after-hours leads."
        })
        outreach_hooks.append(f"Most local customers looking for {biz} after 6 PM won't wait until tomorrow morning—an automated 24/7 chat concierge captures those before they call a competitor.")

    # 3. AI Voice Agent Integration
    voice_agent = features_result.get("voice_agent", {})
    if voice_agent.get("status") == "Not Detected":
        opportunities.append({
            "service": "AI Voice Receptionist & Missed Call Follow-Up",
            "category": "AI Voice Automation",
            "priority": "Medium",
            "evidence": "No automated telephone or AI voice agent integrations detected.",
            "impact": "Unanswered inbound phone calls during peak job hours lead to lost revenue.",
            "solution": "Implement an automated AI phone answering assistant to handle overflow, take messages, and book estimates."
        })

    # 4. CRM & Lead-to-Customer Pipeline
    crm = features_result.get("crm", {})
    if crm.get("status") == "Not Detected":
        opportunities.append({
            "service": "Automated CRM & Lead Management Pipeline",
            "category": "CRM Integration",
            "priority": "Medium",
            "evidence": "No centralized CRM tracking or embedded CRM forms found (HubSpot, GoHighLevel, Salesforce, etc.).",
            "impact": "Inquiries received via plain email or forms lack automated multi-touch follow-up and pipeline visibility.",
            "solution": "Set up a unified CRM with automated SMS/email sequences to re-engage past leads and nurture quotes."
        })

    # 5. Review & Reputation Management Automation
    reviews = features_result.get("review_management", {})
    if reviews.get("status") == "Not Detected":
        opportunities.append({
            "service": "Automated Review Generation & Reputation Management",
            "category": "Reputation Automation",
            "priority": "High",
            "evidence": "No review generation widgets or reputation tools (Birdeye, Podium, Trustpilot) detected.",
            "impact": "Businesses without automated post-job review collection average 60% fewer monthly 5-star reviews on Google Maps.",
            "solution": "Automate 1-click SMS/email review requests immediately following job completion."
        })
        outreach_hooks.append("Automating your post-service 5-star Google review requests can systematically push you into the top 3 of Google Maps local pack.")

    # 6. Technical SEO & Organic Visibility
    seo_findings = seo_result.get("findings", [])
    high_seo_issues = [f for f in seo_findings if f.get("severity") == "High"]
    if high_seo_issues or seo_result.get("seo_score", 100) < 75:
        issue_names = [f["name"] for f in high_seo_issues[:2]]
        opportunities.append({
            "service": "Technical SEO & Search Visibility Optimization",
            "category": "Technical SEO",
            "priority": "High" if high_seo_issues else "Medium",
            "evidence": f"Identified on-page SEO gaps: {', '.join(issue_names) if issue_names else 'Sub-optimal metadata and headings'}.",
            "impact": "Search engine crawlers struggle to index and rank pages with missing titles, descriptions, or broken heading hierarchies.",
            "solution": "Resolve metadata gaps, implement LocalBusiness Schema.org JSON-LD, and optimize heading structures."
        })
        outreach_hooks.append(f"Spotted a couple of quick technical fixes on {biz}'s website (like missing schema/metadata) that could give you an immediate boost in local organic rankings.")

    # 7. Mobile Usability & Website Modernization
    mobile_info = technical_result.get("mobile_usability", {})
    if not mobile_info.get("has_viewport") or mobile_info.get("overflow_risk"):
        opportunities.append({
            "service": "Mobile UX Optimization & Responsive Redesign",
            "category": "Website Development",
            "priority": "High",
            "evidence": "Mobile viewport warnings or fixed-width layout overflow detected.",
            "impact": "Over 65% of local service searches originate on smartphones; poor mobile UX immediately turns away customers.",
            "solution": "Modernize the responsive CSS framework with mobile-first viewport scaling and fluid touch targets."
        })

    # 8. SSL Security & Trust
    ssl_info = technical_result.get("ssl_certificate", {})
    if ssl_info.get("status") in ["Expired", "Plain HTTP", "Invalid"]:
        opportunities.append({
            "service": "SSL Security Certificate Installation & HTTPS Enforcement",
            "category": "Website Security",
            "priority": "Critical",
            "evidence": f"SSL Status: {ssl_info.get('status')} - {ssl_info.get('evidence')}",
            "impact": "Browsers display prominent 'Not Secure' warnings to all visitors.",
            "solution": "Deploy an updated SSL certificate and enforce permanent 301 HTTPS redirects."
        })

    # LEAD OPPORTUNITY SCORING (0 - 100)
    # Calculated on:
    # - Concrete high-value gaps (+15 to +20 each)
    # - Reachability: Decision maker identified (+20)
    # - Reachability: Verified email found (+15)
    # - Reachability: Direct phone found (+10)
    score = 30  # Baseline
    if dm_name: score += 20
    if email and '@' in email: score += 15
    if len(opportunities) >= 3: score += 20
    elif len(opportunities) >= 1: score += 10
    if any(o["priority"] in ["Critical", "High"] for o in opportunities): score += 15

    score = min(100, max(10, score))

    if score >= 80:
        priority_tier = "High Priority Prospect"
    elif score >= 60:
        priority_tier = "Medium Priority Prospect"
    else:
        priority_tier = "Standard Prospect"

    return {
        "lead_score": score,
        "priority_tier": priority_tier,
        "opportunities_count": len(opportunities),
        "detected_opportunities": opportunities,
        "outreach_hooks": outreach_hooks,
        "summary": f"{len(opportunities)} high-value opportunity gaps detected with {priority_tier} status."
    }
