"""
LeadHunter Email & Decision Maker Intelligence Service
Provides email extraction, personal name deduction, B2B email permutation,
and rigorous zero-cost DNS/SMTP verification.
"""

import re
import json
import random
import socket
import smtplib
import html as html_lib
from urllib.parse import urlparse, unquote
from bs4 import BeautifulSoup
import dns.resolver
from email_validator import validate_email, EmailNotValidError

GENERIC_PREFIXES = [
    'info', 'contact', 'support', 'service', 'sales', 'admin',
    'office', 'team', 'hello', 'help', 'billing', 'mail', 'inquiry',
    'appointment', 'customercare', 'frontdesk', 'reception', 'feedback', 'general',
    'dispatch', 'estimates', 'estimate', 'quote', 'quotes', 'schedule', 'scheduling',
    'inquiries', 'jobs', 'careers', 'accounting', 'operations', 'marketing', 'orders', 'press'
]

INVALID_EXTENSIONS = [
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.woff', '.woff2',
    '.ttf', '.css', '.js', '.mp4', '.pdf', '.zip', '.ico', '.mov', '.avi'
]

INVALID_KEYWORDS = [
    'sentry', 'example.com', 'domain.com', 'wixpress', 'noreply', 'no-reply',
    'wixsite.com', 'wordpress.com', 'cloudflare.com', 'github.com', 'bootstrap',
    'fontawesome', 'mysite.com', 'mywebsite.com', 'yoursite.com', 'sample.com',
    'test@', 'admin@mysite', 'username@', 'fill@', 'filler@', 'user@', 'demo@',
    'placeholder@', 'yourname@', 'name@', 'admin@', 'domain@', 'godaddy.com',
    'residence.com', 'wix.com', 'squarespace.com', 'weebly.com', 'sentry.io',
    'schema.org', 'gravatar.com', 'w3.org', 'your_email', 'youremail',
    'email_here', 'your-email', 'youremailhere', 'example@',
    'johndoe@', 'john.doe@', 'janedoe@', 'jane.doe@',
    'first.last@', 'firstname.lastname@', 'your.email@', 'your.name@'
]

PUBLIC_EMAIL_DOMAINS = {
    'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'aol.com',
    'icloud.com', 'live.com', 'msn.com', 'att.net', 'sbcglobal.net',
    'comcast.net', 'me.com', 'mac.com', 'mail.com', 'zoho.com',
    'proton.me', 'protonmail.com'
}

PUBLIC_EXAMPLE_LOCAL_PARTS = {
    'jsmith', 'j.smith', 'john.smith', 'johnsmith', 'jane.smith', 'janesmith',
    'johndoe', 'john.doe', 'janedoe', 'jane.doe', 'email', 'sample', 'example'
}

def decode_cloudflare_email(cf_hash: str) -> str:
    """Decodes Cloudflare email obfuscation hex strings."""
    try:
        if not cf_hash or len(cf_hash) < 4:
            return ""
        key = int(cf_hash[:2], 16)
        email_chars = []
        for i in range(2, len(cf_hash), 2):
            email_chars.append(chr(int(cf_hash[i:i+2], 16) ^ key))
        return "".join(email_chars)
    except Exception:
        return ""

def clean_and_validate_emails(raw_emails: list, base_url: str = "", base_domain: str = "") -> list:
    """
    Cleans, deduplicates, and sorts email candidates by relevance and quality.
    Prioritizes decision-maker / named mailboxes on the business domain.
    Rejects suspicious placeholder addresses and unrelated external private domains.
    """
    if not base_domain and base_url:
        try:
            target_url = base_url
            if not target_url.startswith(('http://', 'https://')):
                target_url = 'https://' + target_url
            base_domain = urlparse(target_url).netloc.lower().replace('www.', '').strip()
        except Exception:
            pass
    elif base_domain:
        base_domain = base_domain.lower().replace('www.', '').strip()

    valid_emails = []
    seen = set()

    for em in raw_emails:
        if not em or '@' not in em:
            continue

        em_clean = em.lower().strip().rstrip('.,;:)/\\')
        
        # Check invalid file extensions in email string
        if any(em_clean.endswith(ext) for ext in INVALID_EXTENSIONS):
            continue

        # Check blacklist keywords & placeholders
        if any(kw in em_clean for kw in INVALID_KEYWORDS):
            continue

        # Skip junk prefixes like URL-encoded residue
        if em_clean.startswith(('%', '20', '3d')) or re.match(r'^\d+@', em_clean):
            continue

        try:
            val = validate_email(em_clean, check_deliverability=False)
            norm = val.normalized
            if norm not in seen:
                local_part, em_domain = norm.rsplit('@', 1)
                local_part = local_part.lower()
                em_domain = em_domain.lower()

                # Reject generic dummy/example local parts on public webmail providers (e.g. jsmith@gmail.com)
                is_public_provider = em_domain in PUBLIC_EMAIL_DOMAINS
                if is_public_provider and local_part in PUBLIC_EXAMPLE_LOCAL_PARTS:
                    continue

                # Unrelated domain check: if base_domain is known, require domain match or legitimate public provider
                if base_domain:
                    domain_matches = (
                        base_domain in em_domain or
                        em_domain in base_domain or
                        em_domain.endswith('.' + base_domain) or
                        base_domain.endswith('.' + em_domain)
                    )
                    if not domain_matches and not is_public_provider:
                        # Reject unrelated external private domain (e.g. residence.com, godaddy.com)
                        continue

                seen.add(norm)
                valid_emails.append(norm)
        except EmailNotValidError:
            pass
        except Exception:
            pass

    # Sort by relevance:
    # 0 = Personal named email matching company domain (e.g. james@acme.com)
    # 1 = Personal named email on external domain (e.g. james.acme@gmail.com)
    # 2 = Generic company email matching company domain (e.g. info@acme.com)
    # 3 = Generic email on external domain
    def email_priority_score(e: str):
        domain = e.split('@')[-1]
        prefix = e.split('@')[0]
        matches_domain = base_domain and (base_domain in domain or domain in base_domain)
        is_generic = any(prefix.startswith(gp) for gp in GENERIC_PREFIXES)

        if matches_domain and not is_generic:
            return 0
        elif not is_generic:
            return 1
        elif matches_domain and is_generic:
            return 2
        return 3

    valid_emails.sort(key=email_priority_score)
    return valid_emails

def extract_emails_and_socials(html_text: str, base_url: str = ""):
    """
    Extracts all candidate emails, Facebook, Instagram, and LinkedIn links from HTML.
    """
    if not html_text:
        return "", "", "", "", []

    raw_emails = []

    try:
        clean_html = html_lib.unescape(html_text)
    except Exception:
        clean_html = html_text

    # Exclude HTML form placeholder/value attributes before scanning raw HTML so form examples
    # (e.g. <input placeholder="jsmith@gmail.com">) are never extracted as business emails.
    scan_html = clean_html
    try:
        sanitized_soup = BeautifulSoup(clean_html, 'html.parser')
        for form_el in sanitized_soup.find_all(['input', 'textarea', 'select']):
            for attr in ('placeholder', 'value', 'aria-placeholder', 'data-placeholder'):
                if form_el.has_attr(attr):
                    del form_el[attr]
        scan_html = str(sanitized_soup)
    except Exception:
        scan_html = re.sub(
            r'\b(?:placeholder|value|aria-placeholder|data-placeholder)\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s>]+)',
            '',
            clean_html,
            flags=re.IGNORECASE
        )

    # Decode obfuscated emails like "john [at] domain.com" or "john (at) domain.com"
    obf = re.sub(r'\[at\]|\(at\)|\s+at\s+', '@', scan_html, flags=re.IGNORECASE)
    obf = re.sub(r'\[dot\]|\(dot\)|\s+dot\s+', '.', obf, flags=re.IGNORECASE)

    # Standard regex email scan
    email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}\b'
    raw_emails.extend(re.findall(email_regex, obf))

    # Cloudflare email obfuscation scan
    cf_hashes = re.findall(r'/email-protection#([a-fA-F0-9]+)', clean_html)
    cf_hashes += re.findall(r'data-cfemail=["\']([a-fA-F0-9]+)["\']', clean_html)
    for cfh in cf_hashes:
        dec = decode_cloudflare_email(cfh)
        if dec:
            raw_emails.append(dec)

    facebook, instagram, linkedin = "", "", ""

    try:
        soup = BeautifulSoup(clean_html, 'html.parser')

        # 1. Inspect mailto: and social anchor tags
        for a in soup.find_all('a', href=True):
            href = a['href'].strip()
            href_lower = href.lower()

            if href_lower.startswith('mailto:'):
                clean_mail = href[7:].split('?')[0].split('&')[0].strip()
                clean_mail = unquote(clean_mail)
                if clean_mail:
                    raw_emails.append(clean_mail)

            # Social profile URLs (filtering out share links and template defaults)
            default_shares = ['/wix', '/wordpress', '/squarespace', '/shopify', 'facebook.com/sharer', 'share.php', 'linkedin.com/share', 'intent/tweet']
            if not any(ds in href_lower for ds in default_shares):
                if 'facebook.com' in href_lower and not facebook:
                    facebook = href
                elif 'instagram.com' in href_lower and not instagram:
                    instagram = href
                elif 'linkedin.com' in href_lower and not linkedin:
                    linkedin = href

        # 2. Inspect Schema.org JSON-LD
        for script in soup.find_all('script', type='application/ld+json'):
            try:
                data = json.loads(script.string or '')
                def search_json_emails(obj):
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            if 'email' in k.lower() and isinstance(v, str):
                                raw_emails.append(v)
                            else:
                                search_json_emails(v)
                    elif isinstance(obj, list):
                        for item in obj:
                            search_json_emails(item)
                search_json_emails(data)
            except Exception:
                pass

        # 3. Inspect meta tags
        for meta in soup.find_all('meta'):
            content = meta.get('content', '')
            if '@' in content and '.' in content:
                raw_emails.extend(re.findall(email_regex, content))

    except Exception:
        pass

    validated = clean_and_validate_emails(raw_emails, base_url=base_url)
    best_email = validated[0] if validated else ""
    return best_email, facebook, instagram, linkedin, validated

def extract_name_from_email_prefix(email: str) -> str:
    """Extracts human name if prefix is personal (e.g. james.richmond@... -> James Richmond)."""
    if not email or '@' not in email:
        return ""
    prefix = email.split('@')[0].lower()
    if any(prefix.startswith(gp) for gp in GENERIC_PREFIXES):
        return ""
    clean_prefix = re.sub(r'[\d_.-]+', ' ', prefix).strip()
    words = [w.capitalize() for w in clean_prefix.split() if len(w) > 1]
    if words and 1 <= len(words) <= 3:
        return " ".join(words)
    return ""

def find_decision_maker_from_html(html_text: str, business_name: str = ""):
    """
    Discovers business Owner / Founder / CEO from Schema.org and high-confidence page cues.
    Returns (name, role) or (None, None).
    Strictly verifies that the discovered name is a human name and distinct from the business name.
    """
    if not html_text:
        return None, None

    normalized_biz = re.sub(r'[^a-zA-Z0-9\s]', '', business_name or "").lower().strip()
    biz_words = set(normalized_biz.split()) if normalized_biz else set()

    def is_valid_human_name(name_cand: str) -> bool:
        if not name_cand or not isinstance(name_cand, str):
            return False
        # Allow Latin letters (including accented characters like José), spaces, hyphens, and apostrophes
        clean = re.sub(r"[^A-Za-zÀ-ÖØ-öø-ÿ\s'’\-]", '', name_cand).strip()
        parts = [p for p in clean.split() if p]
        # Require full human name (2 to 4 tokens, e.g. 'Phillip Cody', 'Jose Luis Mondragon')
        if not (2 <= len(parts) <= 4):
            return False
        # Every token must start with an uppercase letter and have >=2 alphabetic chars (except middle initial like 'J.')
        for idx_p, p in enumerate(parts):
            alpha_only = re.sub(r"[^A-Za-zÀ-ÖØ-öø-ÿ]", "", p)
            if not alpha_only:
                return False
            if idx_p in (0, len(parts) - 1) and len(alpha_only) < 2:
                return False
            if not p[0].isupper():
                return False
        # Reject if matches or is contained within business name
        cand_lower = re.sub(r'[^a-z0-9\s]', '', clean.lower()).strip()
        if normalized_biz and (cand_lower == normalized_biz or normalized_biz in cand_lower or cand_lower in normalized_biz):
            return False
        # Reject if significant token overlap with business name industry/brand words
        cand_words = set(cand_lower.split())
        if biz_words and len(cand_words.intersection(biz_words)) >= max(2, len(cand_words)):
            return False
        if biz_words and len(cand_words.intersection(biz_words)) >= max(1, len(cand_words) // 2):
            if any(w in cand_words for w in ['hvac', 'air', 'heating', 'cooling', 'plumbing', 'roofing', 'service', 'company', 'services', 'mechanical', 'energy', 'systems']):
                return False
        blacklist = {
            'call', 'contact', 'about', 'service', 'services', 'home', 'hom', 'homeowner', 'homeowners',
            'privacy', 'terms', 'hvac', 'houston', 'dallas', 'texas', 'austin', 'fort', 'worth',
            'arlington', 'plano', 'irving', 'garland', 'richardson', 'mesquite', 'carrollton', 'coppell', 'rowlett',
            'air', 'heating', 'cooling', 'conditioning', 'schedule', 'read', 'more', 'our', 'business',
            'company', 'plumbing', 'electric', 'electrical', 'contractor', 'contractors', 'emergency',
            'repair', 'installation', 'solutions', 'group', 'team', 'technicians', 'pro', 'pros',
            'experts', 'reviews', 'request', 'quote', 'american', 'national', 'commercial', 'residential',
            'local', 'family', 'premier', 'quality', 'trusted', 'certified', 'licensed', 'master',
            'best', 'top', 'great', 'first', 'star', 'metro', 'north', 'south', 'east', 'west',
            'central', 'dfw', 'comfort', 'energy', 'mechanical', 'customer', 'customers', 'office',
            'management', 'owner', 'founder', 'president', 'ceo', 'principal', 'climate', 'control',
            'systems', 'tech', 'unit', 'units', 'new', 'your', 'the', 'and', 'for', 'with', 'from',
            'that', 'this', 'property', 'building', 'house', 'small', 'large', 'general', 'manager',
            'every', 'each', 'many', 'most', 'some', 'meet', 'visit', 'today', 'now', 'here', 'welcome',
            'proud', 'serving', 'since', 'years', 'experience', 'award', 'winning'
        }
        if any(re.sub(r"[^a-z]", "", w.lower()) in blacklist for w in parts):
            return False
        return True

    try:
        soup = BeautifulSoup(html_text, 'html.parser')

        # 1. Search Schema.org JSON-LD
        for s in soup.find_all('script', type='application/ld+json'):
            try:
                data = json.loads(s.string or '')
                def search_schema_people(obj):
                    if isinstance(obj, dict):
                        # Explicit founder attribute
                        if obj.get('@type') in ['Person', 'Organization'] and obj.get('founder'):
                            f = obj.get('founder')
                            if isinstance(f, str) and is_valid_human_name(f):
                                return f.strip(), "Founder"
                            if isinstance(f, dict) and f.get('name') and is_valid_human_name(f['name']):
                                return f['name'].strip(), "Founder"
                        # Person with job title
                        if obj.get('@type') == 'Person' and obj.get('name') and obj.get('jobTitle'):
                            if is_valid_human_name(obj.get('name')):
                                return obj.get('name').strip(), str(obj.get('jobTitle')).strip()
                        for k, v in obj.items():
                            if k.lower() in ['founder', 'owner', 'ceo', 'president']:
                                if isinstance(v, str) and is_valid_human_name(v):
                                    return v.strip(), k.title()
                                if isinstance(v, dict) and v.get('name') and is_valid_human_name(v.get('name')):
                                    return v['name'].strip(), str(v.get('jobTitle', k.title())).strip()
                            res = search_schema_people(v)
                            if res: return res
                    elif isinstance(obj, list):
                        for item in obj:
                            res = search_schema_people(item)
                            if res: return res
                    return None

                found = search_schema_people(data)
                if found and found[0]:
                    return found[0].strip(), found[1].strip()
            except Exception:
                pass

        # 2. Heuristic text search (explicitly escaped separator classes prevent character-range truncation)
        text = re.sub(r'\s+', ' ', soup.get_text(separator=' '))
        upper_c = r"[A-ZÀ-ÖØ-Þ]"
        lower_c = r"[a-zà-öø-ÿ]"
        name_token = rf"(?:{upper_c}['’]{upper_c}{lower_c}+|{upper_c}{lower_c}+(?:['’\-]{upper_c}{lower_c}+)?)"
        full_name_pat = rf"({name_token}(?:\s+{name_token}){{1,3}})"
        role_pat = r"(?:Owner|Founder|Co-Founder|President|CEO|Principal)"

        patterns = [
            rf"\b{role_pat}(?:\s*[:\-–—]\s*|\s+){full_name_pat}\b",
            rf"\b{full_name_pat}(?:\s*[,\-–—|]\s*|\s+){role_pat}\b",
            rf"\bMeet\s+(?:the\s+Owner|our\s+Founder|the\s+Founder|Owner|Founder)\s*[:\-–—,]?\s*{full_name_pat}\b"
        ]

        for pat in patterns:
            matches = re.findall(pat, text)
            for m in matches:
                candidate = m.strip()
                if is_valid_human_name(candidate):
                    return candidate, "Owner / Decision Maker"

    except Exception:
        pass

    return None, None

def generate_email_permutations(full_name: str, domain: str) -> list:
    """Generates standard corporate B2B email permutations for a Decision Maker."""
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

def verify_email_smtp(email: str, timeout: int = 5):
    """
    Rigorously verifies email deliverability via direct DNS MX lookup and SMTP handshake.
    Standardized status values:
      - 'Verified': Server confirmed recipient with 250 OK and is NOT catch-all
      - 'MX Only': Catch-all server or MX records exist but SMTP handshake timed out/blocked
      - 'Invalid': Domain has no MX or mailbox rejected (550 code)
      - 'Not Found': Missing email or malformed address
      - 'Unverified': Verification inconclusive
    """
    if not email or '@' not in email:
        return False, "Not Found"

    domain = email.split('@')[-1].lower()

    # 1. DNS MX Lookup
    try:
        answers = sorted(dns.resolver.resolve(domain, 'MX'), key=lambda x: x.preference)
        if not answers:
            return False, "Invalid"
        mx_host = str(answers[0].exchange).rstrip('.')
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return False, "Invalid"
    except Exception:
        return False, "Invalid"

    # 2. SMTP Handshake
    try:
        server = smtplib.SMTP(mx_host, 25, timeout=timeout)
        server.helo('verify-engine.org')
        server.mail('check@verify-engine.org')

        # Catch-All test probe with random non-existent mailbox
        random_probe = f"probe_rnd_{random.randint(100000, 999999)}@{domain}"
        code_probe, _ = server.rcpt(random_probe)
        is_catchall = (code_probe == 250)

        # Target recipient probe
        code_target, _ = server.rcpt(email)
        try:
            server.quit()
        except Exception:
            pass

        if is_catchall:
            return True, "MX Only"
        elif code_target == 250:
            return True, "Verified"
        elif code_target in [550, 551, 552, 553, 554]:
            return False, "Invalid"
        else:
            return True, "MX Only"

    except smtplib.SMTPConnectError:
        return True, "MX Only"
    except (socket.timeout, smtplib.SMTPServerDisconnected, OSError):
        # Port 25 may be blocked by local ISP or cloud provider; fallback cleanly to MX Only
        return True, "MX Only"
    except Exception:
        return False, "Unverified"
