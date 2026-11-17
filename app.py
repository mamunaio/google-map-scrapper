import time
import random
import re
import json
import smtplib
import html as html_lib
from urllib.parse import urljoin, urlparse, unquote
import pandas as pd
import requests
import dns.resolver
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
from flask import Flask, render_template, request, jsonify
from email_validator import validate_email, EmailNotValidError
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

def get_random_delay():
    return random.uniform(1.5, 3.0)

def decode_cloudflare_email(cf_hash):
    try:
        if not cf_hash: return ""
        key = int(cf_hash[:2], 16)
        email = ""
        for i in range(2, len(cf_hash), 2):
            email += chr(int(cf_hash[i:i+2], 16) ^ key)
        return email
    except Exception:
        return ""

def clean_and_validate_emails(raw_emails, base_url=""):
    base_domain = ""
    if base_url:
        try:
            base_domain = urlparse(base_url).netloc.lower().replace('www.', '')
        except Exception:
            pass

    emails = []
    invalid_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.woff', '.woff2', '.ttf', '.css', '.js', '.mp4', '.pdf', '.zip', '.ico', '.mov', '.avi']
    invalid_keywords = [
        'sentry', 'example.com', 'domain.com', 'wixpress', 'noreply', 'no-reply',
        'wixsite.com', 'wordpress.com', 'cloudflare.com', 'github.com', 'bootstrap',
        'fontawesome', 'mysite.com', 'mywebsite.com', 'yoursite.com', 'sample.com',
        'test@', 'admin@mysite'
    ]

    for em in set(raw_emails):
        if not em or '@' not in em:
            continue
        em_lower = em.lower().strip().rstrip('.,;:)/\\')

        # Skip invalid file extensions
        if any(em_lower.endswith(ext) for ext in invalid_extensions):
            continue

        # Skip dummy / framework placeholder emails
        if any(keyword in em_lower for keyword in invalid_keywords):
            continue

        # Skip junk start characters
        if em_lower.startswith(('%', '20', '3d')) or re.match(r'^\d+@', em_lower):
            continue

        try:
            valid = validate_email(em_lower, check_deliverability=False)
            normalized = valid.normalized
            if normalized not in emails:
                emails.append(normalized)
        except Exception:
            pass

    # Priority sorting:
    # 1. Decision-maker personal prefix (james@, steve@, etc.)
    # 2. Email domain matches website domain
    # 3. Generic business prefixes (info@, contact@, etc.)
    generic_prefixes = ['info@', 'contact@', 'service@', 'sales@', 'admin@', 'support@', 'hello@', 'office@', 'help@', 'inquiry@']
    def email_priority(email):
        e = email.lower()
        domain = e.split('@')[-1]
        matches_site = base_domain and (base_domain in domain or domain in base_domain)
        is_generic = any(e.startswith(pref) for pref in generic_prefixes)
        
        if matches_site and not is_generic:
            return 0  # Best: Decision maker / personal email on site domain!
        elif not is_generic:
            return 1  # Personal email (e.g. gmail/yahoo used by local owner)
        elif matches_site and is_generic:
            return 2  # General company email
        return 3

    emails.sort(key=email_priority)
    return emails

def verify_email_smtp(email):
    """Zero-cost direct SMTP handshake verification without sending an email"""
    if not email or '@' not in email:
        return False, "Invalid"
    domain = email.split('@')[-1].lower()
    
    try:
        answers = sorted(dns.resolver.resolve(domain, 'MX'), key=lambda x: x.preference)
        if not answers:
            return False, "No MX Record"
        mx_host = str(answers[0].exchange).rstrip('.')
    except Exception:
        return False, "No MX Record"

    try:
        server = smtplib.SMTP(mx_host, 25, timeout=6)
        server.helo('verify-engine.org')
        server.mail('check@verify-engine.org')

        # Probe for Catch-All server
        fake_test = f"chk_probe_{random.randint(10000, 99999)}@{domain}"
        code_fake, _ = server.rcpt(fake_test)
        is_catchall = (code_fake == 250)

        # Probe target email
        code_target, _ = server.rcpt(email)
        server.quit()

        if is_catchall:
            return True, "Valid (Catch-All)"
        elif code_target == 250:
            return True, "Valid (SMTP Verified)"
        elif code_target in [550, 551, 552, 553, 554]:
            return False, "Invalid"
        else:
            return True, "MX Valid"
    except Exception:
        return True, "MX Valid"

def generate_email_permutations(full_name, domain):
    """Generates standard B2B email permutations for a Decision Maker"""
    if not full_name or not domain:
        return []
    clean_name = re.sub(r'[^a-zA-Z\s]', '', full_name).strip()
    parts = clean_name.split()
    if not parts:
        return []

    first = parts[0].lower()
    last = parts[-1].lower() if len(parts) > 1 else ""
    domain = domain.lower().replace('www.', '').strip('/')

    perms = [f"{first}@{domain}"]
    if last and last != first:
        perms.extend([
            f"{first}.{last}@{domain}",
            f"{first[0]}{last}@{domain}",
            f"{first}{last[0]}@{domain}",
            f"{first}_{last}@{domain}",
            f"{last}@{domain}"
        ])
    return perms

def extract_name_from_email_prefix(email):
    """Extracts human name if email prefix looks personal (e.g. steve@, james.richmond@)"""
    if not email or '@' not in email:
        return ""
    prefix = email.split('@')[0].lower()
    generic_words = ['info', 'contact', 'support', 'service', 'sales', 'admin', 'office', 'team', 'hello', 'help', 'billing', 'mail', 'inquiry', 'appointment']
    if any(prefix.startswith(gw) for gw in generic_words):
        return ""
    clean_prefix = re.sub(r'[\d_.-]+', ' ', prefix).strip()
    words = [w.capitalize() for w in clean_prefix.split() if len(w) > 1]
    if words and len(words) <= 3:
        return " ".join(words)
    return ""

def find_decision_maker_from_html(html_text):
    """Finds Owner/Founder/CEO name from HTML text and Schema.org JSON-LD"""
    if not html_text:
        return None, None
    try:
        soup = BeautifulSoup(html_text, 'html.parser')

        # 1. Check Schema JSON-LD
        for s in soup.find_all('script', type='application/ld+json'):
            try:
                data = json.loads(s.string or '')
                def search_schema(obj):
                    if isinstance(obj, dict):
                        if obj.get('@type') in ['Person', 'Organization'] and obj.get('founder'):
                            f = obj.get('founder')
                            if isinstance(f, str): return f, "Founder"
                            if isinstance(f, dict) and f.get('name'): return f['name'], "Founder"
                        if obj.get('@type') == 'Person' and obj.get('name') and obj.get('jobTitle'):
                            return obj.get('name'), obj.get('jobTitle')
                        for k, v in obj.items():
                            if k.lower() in ['founder', 'owner', 'ceo', 'president']:
                                if isinstance(v, str): return v, k.title()
                                if isinstance(v, dict) and v.get('name'): return v['name'], v.get('jobTitle', k.title())
                            res = search_schema(v)
                            if res: return res
                    elif isinstance(obj, list):
                        for item in obj:
                            res = search_schema(item)
                            if res: return res
                    return None
                found = search_schema(data)
                if found and found[0]:
                    return found[0].strip(), found[1].strip()
            except Exception:
                pass

        # 2. Text Patterns on page
        text = soup.get_text(separator=' ')
        patterns = [
            r'(?:Owner|Founder|Co-Founder|President|CEO|Principal)\s*[:\-–]?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})',
            r'([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\s*[,-–|]\s*(?:Owner|Founder|Co-Founder|President|CEO|Principal)',
            r'Meet\s+(?:the\s+Owner|our\s+Founder|the\s+Founder)\s*[:\-–]?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})'
        ]
        blacklist = ['Call', 'Contact', 'About', 'Service', 'Home', 'Privacy', 'Terms', 'HVAC', 'Houston', 'Air', 'Heating', 'Conditioning', 'Schedule', 'Read', 'More']
        for pat in patterns:
            matches = re.findall(pat, text)
            for m in matches:
                name_candidate = m.strip()
                parts = name_candidate.split()
                if 1 <= len(parts) <= 3 and not any(bn in name_candidate for bn in blacklist):
                    return name_candidate, "Owner / Decision Maker"
    except Exception:
        pass
    return None, None

def extract_social_and_email(html_text, base_url=""):
    if not html_text:
        return "", "", "", ""

    raw_emails = []

    # 1. Unescape HTML entities
    try:
        clean_html = html_lib.unescape(html_text)
    except Exception:
        clean_html = html_text

    # 2. Decode obfuscations like "name [at] domain.com"
    obf_decoded = re.sub(r'\[at\]|\(at\)|\s+at\s+', '@', clean_html, flags=re.IGNORECASE)
    obf_decoded = re.sub(r'\[dot\]|\(dot\)|\s+dot\s+', '.', obf_decoded, flags=re.IGNORECASE)

    # 3. Regex email search
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}\b'
    raw_emails.extend(re.findall(email_pattern, obf_decoded))

    # 4. Cloudflare email extraction
    cf_hashes = re.findall(r'/email-protection#([a-fA-F0-9]+)', clean_html)
    cf_hashes += re.findall(r'data-cfemail=["\']([a-fA-F0-9]+)["\']', clean_html)
    for cfh in cf_hashes:
        decoded = decode_cloudflare_email(cfh)
        if decoded:
            raw_emails.append(decoded)

    # 5. Parse DOM with BeautifulSoup
    facebook, instagram, linkedin = "", "", ""
    try:
        soup = BeautifulSoup(clean_html, 'html.parser')

        # Mailto: extraction
        for a in soup.find_all('a', href=True):
            href = a['href'].strip()
            if href.lower().startswith('mailto:'):
                clean_mail = href[7:].split('?')[0].split('&')[0].strip()
                clean_mail = unquote(clean_mail)
                if clean_mail:
                    raw_emails.append(clean_mail)
            
            # Social links (excluding framework/theme defaults)
            href_lower = href.lower()
            default_socials = ['/wix', '/wordpress', '/squarespace', '/shopify', 'facebook.com/sharer', 'share.php', 'linkedin.com/share']
            if not any(ds in href_lower for ds in default_socials):
                if 'facebook.com' in href_lower and not facebook:
                    facebook = href
                elif 'instagram.com' in href_lower and not instagram:
                    instagram = href
                elif 'linkedin.com' in href_lower and not linkedin:
                    linkedin = href

        # Schema JSON-LD extraction
        for script in soup.find_all('script', type='application/ld+json'):
            try:
                data = json.loads(script.string or '')
                def search_json(obj):
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            if 'email' in k.lower() and isinstance(v, str):
                                raw_emails.append(v)
                            else:
                                search_json(v)
                    elif isinstance(obj, list):
                        for item in obj:
                            search_json(item)
                search_json(data)
            except Exception:
                pass

        # Meta tags
        for meta in soup.find_all('meta'):
            content = meta.get('content', '')
            if '@' in content and '.' in content:
                raw_emails.extend(re.findall(email_pattern, content))

    except Exception:
        pass

    validated_emails = clean_and_validate_emails(raw_emails, base_url=base_url)
    best_email = validated_emails[0] if validated_emails else ""

    return best_email, facebook, instagram, linkedin

def find_candidate_pages(html_text, base_url):
    """Dynamically finds internal links likely to contain contact info (Contact, About, Team, etc.)"""
    candidate_urls = []
    if not html_text or not base_url:
        return candidate_urls

    try:
        base_domain = urlparse(base_url).netloc.lower().replace('www.', '')
        soup = BeautifulSoup(html_text, 'html.parser')
        keywords = ['contact', 'about', 'reach', 'touch', 'support', 'team', 'leadership', 'location', 'service']

        for a in soup.find_all('a', href=True):
            href = a.get('href', '').strip()
            text = a.get_text().strip().lower()
            if not href or href.startswith(('tel:', 'mailto:', 'javascript:', '#')):
                continue

            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)
            parsed_domain = parsed.netloc.lower().replace('www.', '')

            if parsed_domain == base_domain:
                href_lower = href.lower()
                if any(kw in href_lower or kw in text for kw in keywords):
                    if full_url not in candidate_urls and full_url.rstrip('/') != base_url.rstrip('/'):
                        candidate_urls.append(full_url)

        def page_priority(u):
            u_low = u.lower()
            if 'team' in u_low or 'leadership' in u_low: return 0
            if 'about' in u_low: return 1
            if 'contact' in u_low: return 2
            return 3

        candidate_urls.sort(key=page_priority)
    except Exception:
        pass

    return candidate_urls[:5]

def scrape_website_details_with_playwright(url, existing_fb="", existing_insta="", existing_linkedin=""):
    """Full headless Chrome rendering for JavaScript/Single Page Applications (React, Vue, Wix, Webflow)"""
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, timeout=35000, wait_until='domcontentloaded')
            time.sleep(1.5)

            try:
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                time.sleep(1.5)
            except Exception:
                pass

            html = page.content()
            email, fb, insta, linkedin = extract_social_and_email(html, base_url=url)
            dm_name, dm_role = find_decision_maker_from_html(html)
            fb = fb or existing_fb
            insta = insta or existing_insta
            linkedin = linkedin or existing_linkedin

            if not (email and fb and linkedin):
                candidate_links = find_candidate_pages(html, url)
                if not candidate_links:
                    candidate_links = [url.rstrip('/') + '/about', url.rstrip('/') + '/team', url.rstrip('/') + '/contact', url.rstrip('/') + '/contact-us']

                for curl in candidate_links[:3]:
                    try:
                        page.goto(curl, timeout=20000, wait_until='domcontentloaded')
                        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                        time.sleep(1.0)
                        c_html = page.content()
                        c_email, c_fb, c_insta, c_linkedin = extract_social_and_email(c_html, base_url=url)
                        if not dm_name:
                            dm_name, dm_role = find_decision_maker_from_html(c_html)
                        email = email or c_email
                        fb = fb or c_fb
                        insta = insta or c_insta
                        linkedin = linkedin or c_linkedin
                        if email and fb and linkedin and dm_name:
                            break
                    except Exception:
                        pass

            browser.close()
            return email, fb, insta, linkedin, "", dm_name, dm_role
    except Exception as e:
        print(f"Playwright fallback failed for {url}: {e}")
        return "", existing_fb, existing_insta, existing_linkedin, "", None, None

def scrape_website_details(url, hint_decision_maker=""):
    """Complete Extraction: Emails, Decision Maker, Permutation & SMTP Verification"""
    email, fb, insta, linkedin, about_info = "", "", "", "", ""
    dm_name, dm_role = hint_decision_maker or None, "Owner" if hint_decision_maker else None
    verification_status = "Unverified"
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
    }

    try:
        response = requests.get(url, headers=headers, timeout=12, verify=False)
        if response.status_code in [403, 401, 503, 429]:
            raise Exception(f"Blocked by server (status {response.status_code})")

        email, fb, insta, linkedin = extract_social_and_email(response.text, base_url=url)
        if not dm_name:
            dm_name, dm_role = find_decision_maker_from_html(response.text)

        candidate_pages = find_candidate_pages(response.text, url)
        if not candidate_pages:
            candidate_pages = [url.rstrip('/') + '/about', url.rstrip('/') + '/team', url.rstrip('/') + '/contact', url.rstrip('/') + '/contact-us']

        # Scan candidate pages if anything missing
        if not (email and fb and linkedin and dm_name):
            for curl in candidate_pages:
                try:
                    c_resp = requests.get(curl, headers=headers, timeout=10, verify=False)
                    if c_resp.status_code == 200:
                        c_email, c_fb, c_insta, c_linkedin = extract_social_and_email(c_resp.text, base_url=url)
                        if not dm_name:
                            dm_name, dm_role = find_decision_maker_from_html(c_resp.text)
                        email = email or c_email
                        fb = fb or c_fb
                        insta = insta or c_insta
                        linkedin = linkedin or c_linkedin
                        if email and fb and linkedin and dm_name:
                            break
                except Exception:
                    pass

        for curl in candidate_pages:
            if 'about' in curl.lower():
                about_info = curl
                break

    except Exception as e:
        print(f"Requests encountered issue for {url}: {e}")

    # Fallback to Playwright if email missing or socials missing
    if not email or not (fb or linkedin):
        print(f"Deep scraping via Playwright for {url}...")
        p_email, p_fb, p_insta, p_linkedin, _, p_dm_name, p_dm_role = scrape_website_details_with_playwright(
            url, existing_fb=fb, existing_insta=insta, existing_linkedin=linkedin
        )
        email = email or p_email
        fb = fb or p_fb
        insta = insta or p_insta
        linkedin = linkedin or p_linkedin
        if not dm_name:
            dm_name = p_dm_name
            dm_role = p_dm_role

    # Check if existing found email has a personal name in prefix
    if not dm_name and email:
        extracted_name = extract_name_from_email_prefix(email)
        if extracted_name:
            dm_name = extracted_name
            dm_role = "Business Owner"

    # PERMUTATION & SMTP VERIFICATION ENGINE
    domain = urlparse(url).netloc.lower().replace('www.', '').strip('/')
    
    if dm_name and domain:
        perms = generate_email_permutations(dm_name, domain)
        print(f"Generated permutations for {dm_name}: {perms[:3]}")
        
        # Test permutations with SMTP
        for perm in perms:
            is_valid, v_status = verify_email_smtp(perm)
            if is_valid and "Valid" in v_status:
                email = perm
                verification_status = v_status
                break

    # If no permutation verified, but we found a valid site email, verify that email!
    if email and verification_status == "Unverified":
        _, v_status = verify_email_smtp(email)
        verification_status = v_status

    decision_maker_str = f"{dm_name} ({dm_role})" if dm_name and dm_role else (dm_name or "")

    return email, fb, insta, linkedin, about_info, decision_maker_str, verification_status

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scrape', methods=['POST'])
def scrape_api():
    data = request.json
    url = data.get('url')
    type_ = data.get('type')
    hint_dm = data.get('decision_maker', '')
    
    if not url:
        return jsonify({"error": "URL is required"}), 400
        
    result = {
        "Business Name": "",
        "Phone Number": "",
        "Website": "",
        "Decision Maker": "",
        "Email": "",
        "Email Verification": "Unverified",
        "Facebook": "",
        "Instagram": "",
        "LinkedIn": "",
        "About Page Link": "",
        "Source URL": url
    }
    
    try:
        if type_ == 'maps':
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(url, timeout=60000)
                time.sleep(get_random_delay())
                
                try:
                    name_loc = page.locator('h1.DUwDvf.lfPIob')
                    if name_loc.count() > 0: result["Business Name"] = name_loc.first.inner_text()
                except: pass
                
                try:
                    web_loc = page.locator('a[data-item-id="authority"]')
                    if web_loc.count() > 0: result["Website"] = web_loc.first.get_attribute('href')
                except: pass
                
                try:
                    phone_loc = page.locator('button[data-tooltip*="Copy phone number"]')
                    if phone_loc.count() > 0: result["Phone Number"] = phone_loc.first.inner_text()
                except: pass
                
                browser.close()
                
        elif type_ == 'website':
            result["Website"] = url
            
        # Scrape website for emails/socials/decision makers if website exists
        if result["Website"]:
            email, fb, insta, linkedin, about_info, dm_str, ver_status = scrape_website_details(
                result["Website"], hint_decision_maker=hint_dm
            )
            result["Email"] = email
            result["Decision Maker"] = dm_str
            result["Email Verification"] = ver_status
            result["Facebook"] = fb
            result["Instagram"] = insta
            result["LinkedIn"] = linkedin
            result["About Page Link"] = about_info
            
        return jsonify({"success": True, "data": result})
        
    except Exception as e:
        print(f"API Error: {e}")
        return jsonify({"success": False, "error": str(e), "data": result}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
