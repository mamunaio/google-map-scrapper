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
    'appointment', 'customercare', 'frontdesk', 'reception', 'feedback', 'general'
]

INVALID_EXTENSIONS = [
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.woff', '.woff2',
    '.ttf', '.css', '.js', '.mp4', '.pdf', '.zip', '.ico', '.mov', '.avi'
]

INVALID_KEYWORDS = [
    'sentry', 'example.com', 'domain.com', 'wixpress', 'noreply', 'no-reply',
    'wixsite.com', 'wordpress.com', 'cloudflare.com', 'github.com', 'bootstrap',
    'fontawesome', 'mysite.com', 'mywebsite.com', 'yoursite.com', 'sample.com',
    'test@', 'admin@mysite', 'username@', 'fill@'
]

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

def clean_and_validate_emails(raw_emails: list, base_url: str = "") -> list:
    """
    Cleans, deduplicates, and sorts email candidates by relevance and quality.
    Prioritizes decision-maker / named mailboxes on the business domain.
    """
    base_domain = ""
    if base_url:
        try:
            base_domain = urlparse(base_url).netloc.lower().replace('www.', '')
        except Exception:
            pass

    valid_emails = []
    seen = set()

    for em in raw_emails:
        if not em or '@' not in em:
            continue

        em_clean = em.lower().strip().rstrip('.,;:)/\\')
        
        # Check invalid file extensions in email string
        if any(em_clean.endswith(ext) for ext in INVALID_EXTENSIONS):
            continue

        # Check blacklist keywords
        if any(kw in em_clean for kw in INVALID_KEYWORDS):
            continue

        # Skip junk prefixes like URL-encoded residue
        if em_clean.startswith(('%', '20', '3d')) or re.match(r'^\d+@', em_clean):
            continue

        try:
            val = validate_email(em_clean, check_deliverability=False)
            norm = val.normalized
            if norm not in seen:
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

    # Decode obfuscated emails like "john [at] domain.com" or "john (at) domain.com"
    obf = re.sub(r'\[at\]|\(at\)|\s+at\s+', '@', clean_html, flags=re.IGNORECASE)
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

def find_decision_maker_from_html(html_text: str):
    """
    Discovers business Owner / Founder / CEO from Schema.org and high-confidence page cues.
    Returns (name, role) or (None, None).
    """
    if not html_text:
        return None, None

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
                            if isinstance(f, str): return f, "Founder"
                            if isinstance(f, dict) and f.get('name'): return f['name'], "Founder"
                        # Person with job title
                        if obj.get('@type') == 'Person' and obj.get('name') and obj.get('jobTitle'):
                            return obj.get('name'), obj.get('jobTitle')
                        for k, v in obj.items():
                            if k.lower() in ['founder', 'owner', 'ceo', 'president']:
                                if isinstance(v, str): return v, k.title()
                                if isinstance(v, dict) and v.get('name'): return v['name'], v.get('jobTitle', k.title())
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

        # 2. Heuristic text search
        text = soup.get_text(separator=' ')
        patterns = [
            r'(?:Owner|Founder|Co-Founder|President|CEO|Principal)\s*[:\-–]?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})',
            r'([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\s*[,-–|]\s*(?:Owner|Founder|Co-Founder|President|CEO|Principal)',
            r'Meet\s+(?:the\s+Owner|our\s+Founder|the\s+Founder)\s*[:\-–]?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})'
        ]
        blacklist = ['Call', 'Contact', 'About', 'Service', 'Home', 'Privacy', 'Terms', 'HVAC', 'Houston',
                     'Air', 'Heating', 'Conditioning', 'Schedule', 'Read', 'More', 'Our', 'Business', 'Company']

        for pat in patterns:
            matches = re.findall(pat, text)
            for m in matches:
                candidate = m.strip()
                parts = candidate.split()
                if 1 <= len(parts) <= 3 and not any(b in candidate for b in blacklist):
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
    Distinguishes:
      - 'Valid (SMTP Verified)': Server confirmed recipient with 250 OK and is NOT catch-all
      - 'Valid (Catch-All)': Server accepts all incoming addresses
      - 'Valid (MX Only)': MX records exist, but SMTP handshake timed out or was blocked
      - 'Invalid (Mailbox Not Found)': Server rejected recipient (550 code)
      - 'Invalid (No MX Record)': Domain has no mail exchangers
      - 'Unverified': Invalid format or probe aborted
    """
    if not email or '@' not in email:
        return False, "Invalid"

    domain = email.split('@')[-1].lower()

    # 1. DNS MX Lookup
    try:
        answers = sorted(dns.resolver.resolve(domain, 'MX'), key=lambda x: x.preference)
        if not answers:
            return False, "Invalid (No MX Record)"
        mx_host = str(answers[0].exchange).rstrip('.')
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return False, "Invalid (No MX Record)"
    except Exception:
        return False, "Invalid (No MX Record)"

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
            return True, "Valid (Catch-All)"
        elif code_target == 250:
            return True, "Valid (SMTP Verified)"
        elif code_target in [550, 551, 552, 553, 554]:
            return False, "Invalid (Mailbox Not Found)"
        else:
            return True, "Valid (MX Only)"

    except smtplib.SMTPConnectError:
        return True, "Valid (MX Only)"
    except (socket.timeout, smtplib.SMTPServerDisconnected, OSError):
        # Port 25 may be blocked by local ISP or cloud provider; fallback cleanly to MX Valid
        return True, "Valid (MX Only)"
    except Exception:
        return True, "Valid (MX Only)"
