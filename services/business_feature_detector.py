"""
LeadHunter Business Feature Detection Engine
Detects digital infrastructure, marketing, and business automation capabilities:
Lead Capture, Booking/Appointment, Chatbot, Voice AI, CRM, Review Management, Analytics.
Strictly distinguishes: Detected, Not Detected, Unknown, Scan Failed.
Never presumes missing DOM evidence confirms absolute business absence of a system.
"""

import re
from bs4 import BeautifulSoup

# EXTENSIBLE SIGNATURE REGISTRY
PROVIDER_SIGNATURES = {
    "booking": [
        {"name": "Calendly", "patterns": [r"calendly\.com", r"assets\.calendly\.com"]},
        {"name": "Acuity Scheduling", "patterns": [r"acuityscheduling\.com", r"embed\.acuityscheduling\.com"]},
        {"name": "Setmore", "patterns": [r"setmore\.com", r"my\.setmore\.com"]},
        {"name": "Square Appointments", "patterns": [r"square\.site/book", r"squareup\.com/appointments"]},
        {"name": "Housecall Pro", "patterns": [r"housecallpro\.com", r"online-booking\.housecallpro\.com"]},
        {"name": "Jobber", "patterns": [r"getjobber\.com", r"clienthub\.getjobber\.com"]},
        {"name": "ServiceTitan", "patterns": [r"servicetitan\.com", r"schedule\.servicetitan\.com"]},
        {"name": "vCita", "patterns": [r"vcita\.com", r"livesite\.vcita\.com"]},
        {"name": "Chili Piper", "patterns": [r"js\.chilipiper\.com", r"chilipiper\.com"]},
        {"name": "HubSpot Meetings", "patterns": [r"meetings\.hubspot\.com"]},
        {"name": "SimplyBook.me", "patterns": [r"simplybook\.me", r"simplybook\.it"]},
        {"name": "Booker", "patterns": [r"booker\.com"]},
        {"name": "Appointlet", "patterns": [r"appointlet\.com"]},
    ],
    "chatbot": [
        {"name": "Intercom", "patterns": [r"widget\.intercom\.io", r"intercomSettings"]},
        {"name": "Drift", "patterns": [r"js\.driftt\.com", r"drift\.load"]},
        {"name": "Tidio", "patterns": [r"code\.tidio\.co", r"tidioChatCode"]},
        {"name": "Zendesk Chat", "patterns": [r"static\.zdassets\.com", r"zopim", r"ekr\.zdassets\.com"]},
        {"name": "LiveChat", "patterns": [r"cdn\.livechatinc\.com", r"__lc\.license"]},
        {"name": "Crisp", "patterns": [r"client\.crisp\.chat", r"\$crisp"]},
        {"name": "Podium Webchat", "patterns": [r"connect\.podium\.com", r"podium-starter"]},
        {"name": "ManyChat", "patterns": [r"manychat\.com", r"widget\.manychat\.com"]},
        {"name": "PureChat", "patterns": [r"purechat\.com"]},
        {"name": "HubSpot Chat", "patterns": [r"js\.usemessages\.com", r"HubSpotConversations"]},
        {"name": "Olark", "patterns": [r"static\.olark\.com", r"olark\.identify"]},
        {"name": "Chaport", "patterns": [r"chaport\.com"]},
        {"name": "Tawk.to", "patterns": [r"embed\.tawk\.to", r"Tawk_API"]},
    ],
    "voice_agent": [
        {"name": "Vapi AI", "patterns": [r"vapi\.ai", r"cdn\.vapi\.ai"]},
        {"name": "Bland AI", "patterns": [r"bland\.ai", r"api\.bland\.ai"]},
        {"name": "Retell AI", "patterns": [r"retellai\.com", r"sdk\.retellai\.com"]},
        {"name": "Air AI", "patterns": [r"air\.ai", r"widgets\.air\.ai"]},
        {"name": "Synthflow AI", "patterns": [r"synthflow\.ai"]},
        {"name": "Phonely", "patterns": [r"phonely\.ai"]},
        {"name": "Dialpad AI", "patterns": [r"dialpad\.com", r"dialpadcdn\.com"]},
        {"name": "RingCentral AI", "patterns": [r"ringcentral\.com"]},
    ],
    "crm": [
        {"name": "HubSpot", "patterns": [r"js\.hs-scripts\.com", r"js\.hsforms\.net", r"hbspt\.forms"]},
        {"name": "GoHighLevel / LeadConnector", "patterns": [r"leadconnectorhq\.com", r"msgsndr\.com", r"api\.leadconnector\.com"]},
        {"name": "Salesforce / Pardot", "patterns": [r"pardot\.com", r"salesforce\.com", r"pi\.pardot\.com"]},
        {"name": "Zoho CRM", "patterns": [r"salesiq\.zoho\.com", r"crm\.zoho\.com", r"zohopublic\.com"]},
        {"name": "ActiveCampaign", "patterns": [r"activehosted\.com", r"trackcmp\.net"]},
        {"name": "Keap / Infusionsoft", "patterns": [r"infusionsoft\.com", r"keap\.com", r"infusionsoft\.app"]},
        {"name": "Pipedrive", "patterns": [r"pipedrivewebforms\.com", r"pipedrive\.com"]},
        {"name": "Marketo", "patterns": [r"munchkin\.marketo\.net", r"marketo\.com"]},
    ],
    "review_management": [
        {"name": "Birdeye", "patterns": [r"birdeye\.com", r"bid\.birdeye\.com"]},
        {"name": "Podium Reviews", "patterns": [r"podium\.com/review", r"review\.podium\.com"]},
        {"name": "Trustpilot", "patterns": [r"widget\.trustpilot\.com", r"trustpilot\.com"]},
        {"name": "Google Reviews Widget (Elfsight)", "patterns": [r"apps\.elfsight\.com", r"elfsight\.com/google-reviews"]},
        {"name": "EmbedSocial", "patterns": [r"embedsocial\.com"]},
        {"name": "GatherUp", "patterns": [r"gatherup\.com"]},
        {"name": "Broadly", "patterns": [r"broadly\.com"]},
        {"name": "NiceJob", "patterns": [r"nicejob\.com", r"cdn\.nicejob\.co"]},
        {"name": "ReviewTrackers", "patterns": [r"reviewtrackers\.com"]},
        {"name": "Yelp Badge", "patterns": [r"yelp\.com/biz_badge", r"dyn\.yelp\.com"]},
    ],
    "analytics": [
        {"name": "Google Analytics 4", "patterns": [r"gtag\(['\"]config['\"],\s*['\"]G-", r"googletagmanager\.com/gtag/js\?id=G-"]},
        {"name": "Google Tag Manager", "patterns": [r"googletagmanager\.com/gtm\.js", r"GTM-[A-Z0-9]+"]},
        {"name": "Meta Pixel (Facebook)", "patterns": [r"connect\.facebook\.net", r"fbq\(['\"]init['\"]"]},
        {"name": "Hotjar", "patterns": [r"static\.hotjar\.com", r"hjid:"]},
        {"name": "TikTok Pixel", "patterns": [r"analytics\.tiktok\.com", r"ttq\.load"]},
        {"name": "Klaviyo", "patterns": [r"static\.klaviyo\.com", r"klaviyo\.js"]},
        {"name": "Mailchimp", "patterns": [r"chimpstatic\.com", r"mailchimp\.com"]},
    ]
}

def detect_signatures_in_html(html_text: str, category_key: str):
    """Matches signatures in HTML, script tags, and embedded links."""
    detected = []
    signatures = PROVIDER_SIGNATURES.get(category_key, [])

    for sig in signatures:
        name = sig["name"]
        for pat in sig["patterns"]:
            if re.search(pat, html_text, re.IGNORECASE):
                if name not in detected:
                    detected.append(name)
                break
    return detected

def detect_lead_capture_mechanisms(soup: BeautifulSoup, html_text: str):
    """
    Detects forms, quote requests, click-to-call links, email links, and CTAs.
    """
    has_contact_form = False
    has_quote_form = False
    has_phone_link = False
    has_email_link = False
    prominent_ctas = []

    # 1. Forms scan
    forms = soup.find_all('form')
    for f in forms:
        f_text = f.get_text().lower()
        inputs = [i.get('name', '').lower() for i in f.find_all(['input', 'textarea', 'select'])]
        action = f.get('action', '').lower()

        is_quote = any(q in f_text or q in action for q in ['quote', 'estimate', 'free estimate', 'get quote', 'request quote', 'proposal'])
        has_contact_fields = any(c in inputs or any(c in i for i in inputs) for c in ['email', 'phone', 'name', 'message', 'tel'])

        if is_quote:
            has_quote_form = True
        if has_contact_fields or len(inputs) >= 2:
            has_contact_form = True

    # 2. Links scan (tel: and mailto:)
    for a in soup.find_all('a', href=True):
        href = a['href'].strip().lower()
        text = a.get_text().strip()

        if href.startswith('tel:'):
            has_phone_link = True
        elif href.startswith('mailto:'):
            has_email_link = True

        cta_keywords = [
            'get free quote', 'request a quote', 'free estimate', 'book online',
            'schedule service', 'call now', 'schedule now', 'free inspection', 'contact us today'
        ]
        text_lower = text.lower()
        if any(kw in text_lower for kw in cta_keywords) and len(text) < 45:
            if text not in prominent_ctas and len(prominent_ctas) < 3:
                prominent_ctas.append(text)

    evidence = []
    if has_quote_form: evidence.append("Online Quote/Estimate Request Form")
    elif has_contact_form: evidence.append("Standard Contact Form")
    if has_phone_link: evidence.append("Click-to-Call Link (tel:)")
    if has_email_link: evidence.append("Direct Mailto Link")
    if prominent_ctas: evidence.append(f"Prominent CTA: \"{prominent_ctas[0]}\"")

    detected = len(evidence) > 0
    return {
        "status": "Detected" if detected else "Not Detected",
        "evidence": evidence,
        "details": {
            "has_contact_form": has_contact_form,
            "has_quote_form": has_quote_form,
            "has_phone_link": has_phone_link,
            "has_email_link": has_email_link,
            "prominent_ctas": prominent_ctas
        }
    }

def detect_business_features(html_text: str):
    """
    Main entry point for Business Feature Detection Engine.
    Inspects HTML and returns structured findings for all 7 feature categories.
    Strictly distinguishes: Detected, Not Detected, Unknown, Scan Failed.
    """
    categories = ["lead_capture", "booking", "chatbot", "voice_agent", "crm", "review_management", "analytics"]

    if not html_text or not isinstance(html_text, str) or len(html_text.strip()) == 0:
        return {
            cat: {
                "category": cat.replace("_", " ").title(),
                "status": "Scan Failed",
                "providers": [],
                "evidence": "No readable HTML content received from server."
            }
            for cat in categories
        }

    try:
        soup = BeautifulSoup(html_text, 'html.parser')
    except Exception:
        return {
            cat: {
                "category": cat.replace("_", " ").title(),
                "status": "Scan Failed",
                "providers": [],
                "evidence": "HTML parser exception occurred during scan."
            }
            for cat in categories
        }

    results = {}

    # 1. Lead Capture
    lead_cap = detect_lead_capture_mechanisms(soup, html_text)
    results["lead_capture"] = {
        "category": "Lead Capture",
        "status": lead_cap["status"],
        "providers": ["On-Page Form / CTA"] if lead_cap["status"] == "Detected" else [],
        "evidence": ", ".join(lead_cap["evidence"]) if lead_cap["evidence"] else "No interactive contact forms or CTAs observed on scanned pages.",
        "details": lead_cap["details"]
    }

    # 2. Booking and Appointment
    booking_providers = detect_signatures_in_html(html_text, "booking")
    has_booking_link = False
    if not booking_providers:
        for a in soup.find_all('a', href=True):
            href_text = (a.get('href', '') + " " + a.get_text()).lower()
            if any(b in href_text for b in ['/schedule', '/book-online', '/booking', 'appointment']):
                booking_providers.append("Internal Booking Link")
                has_booking_link = True
                break

    if booking_providers:
        b_status = "Detected"
        b_ev = f"Identified: {', '.join(booking_providers)}"
    else:
        b_status = "Not Detected"
        b_ev = "No client-facing scheduling widgets or calendar integrations observed on scanned pages (external/off-site booking portal may still exist)."

    results["booking"] = {
        "category": "Booking & Appointment",
        "status": b_status,
        "providers": booking_providers,
        "evidence": b_ev
    }

    # 3. Chatbot
    chat_providers = detect_signatures_in_html(html_text, "chatbot")
    results["chatbot"] = {
        "category": "Live Chat & Chatbot",
        "status": "Detected" if chat_providers else "Not Detected",
        "providers": chat_providers,
        "evidence": f"Identified: {', '.join(chat_providers)}" if chat_providers else "No live chat or conversational bot scripts detected on scanned pages."
    }

    # 4. Voice Agent
    voice_providers = detect_signatures_in_html(html_text, "voice_agent")
    results["voice_agent"] = {
        "category": "AI Voice Agent",
        "status": "Detected" if voice_providers else "Not Detected",
        "providers": voice_providers,
        "evidence": f"Identified: {', '.join(voice_providers)}" if voice_providers else "No AI voice agent scripts or telephony automation integrations observed."
    }

    # 5. CRM & Lead Management
    crm_providers = detect_signatures_in_html(html_text, "crm")
    if crm_providers:
        crm_status = "Detected"
        crm_ev = f"Identified client-side scripts: {', '.join(crm_providers)}"
    else:
        crm_status = "Not Detected"
        crm_ev = "No client-side CRM scripts or embedded forms detected on scanned pages (server-side CRM or off-page pipeline may exist)."

    results["crm"] = {
        "category": "CRM & Pipeline Management",
        "status": crm_status,
        "providers": crm_providers,
        "evidence": crm_ev
    }

    # 6. Review & Reputation Management
    review_providers = detect_signatures_in_html(html_text, "review_management")
    results["review_management"] = {
        "category": "Review Management",
        "status": "Detected" if review_providers else "Not Detected",
        "providers": review_providers,
        "evidence": f"Identified: {', '.join(review_providers)}" if review_providers else "No third-party review widgets or reputation platform integrations observed on scanned pages."
    }

    # 7. Marketing & Analytics
    analytics_providers = detect_signatures_in_html(html_text, "analytics")
    results["analytics"] = {
        "category": "Marketing & Analytics",
        "status": "Detected" if analytics_providers else "Not Detected",
        "providers": analytics_providers,
        "evidence": f"Identified: {', '.join(analytics_providers)}" if analytics_providers else "No Google Analytics, Meta Pixel, or tag managers detected on scanned pages."
    }

    return results
