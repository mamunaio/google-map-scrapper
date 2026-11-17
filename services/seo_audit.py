"""
LeadHunter SEO & Technical Audit Service
Performs on-page SEO analysis, heading hierarchy checks, sitemap/robots discovery,
image alt coverage, structured data validation, and multi-page audits.
"""

from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import re
from services.security import safe_http_get, SecurityError

def audit_page_seo(html_text: str, page_url: str):
    """
    Analyzes an HTML page for core technical SEO and on-page factors.
    Returns structured findings and high-level metrics.
    """
    findings = []
    metrics = {
        "title": "",
        "title_length": 0,
        "meta_description": "",
        "meta_description_length": 0,
        "canonical_url": "",
        "h1_tags": [],
        "h2_count": 0,
        "h3_count": 0,
        "images_total": 0,
        "images_missing_alt": 0,
        "internal_links_count": 0,
        "external_links_count": 0,
        "schema_types": [],
        "has_og_tags": False,
        "is_noindex": False
    }

    if not html_text:
        findings.append({
            "name": "Empty Page Content",
            "severity": "High",
            "affected_url": page_url,
            "evidence": "Received 0 bytes of HTML content.",
            "explanation": "Search engines cannot index or rank pages without readable HTML content.",
            "suggested_improvement": "Ensure the server responds with server-rendered HTML content.",
            "detection_method": "HTTP Response Inspection"
        })
        return {"findings": findings, "metrics": metrics, "seo_score": 0}

    soup = BeautifulSoup(html_text, 'html.parser')
    base_domain = urlparse(page_url).netloc.lower().replace('www.', '')

    # 1. Page Title
    title_tag = soup.find('title')
    title_text = title_tag.get_text().strip() if title_tag else ""
    metrics["title"] = title_text
    metrics["title_length"] = len(title_text)

    if not title_text:
        findings.append({
            "name": "Missing Page Title",
            "severity": "High",
            "affected_url": page_url,
            "evidence": "No <title> tag found in HTML <head>.",
            "explanation": "The title tag is one of the most critical on-page SEO signals and appears as the headline in search engine results.",
            "suggested_improvement": "Add a unique, descriptive <title> tag between 50-60 characters containing primary service and location keywords.",
            "detection_method": "DOM Head Inspection"
        })
    elif len(title_text) < 30:
        findings.append({
            "name": "Short Page Title",
            "severity": "Low",
            "affected_url": page_url,
            "evidence": f"Title is only {len(title_text)} characters ('{title_text}').",
            "explanation": "Short titles often miss opportunities to target relevant customer queries and location terms.",
            "suggested_improvement": "Expand title to 50-60 characters incorporating primary service and city name.",
            "detection_method": "String Length Analysis"
        })
    elif len(title_text) > 65:
        findings.append({
            "name": "Long Page Title (Truncation Risk)",
            "severity": "Low",
            "affected_url": page_url,
            "evidence": f"Title is {len(title_text)} characters ('{title_text[:60]}...').",
            "explanation": "Titles over 60-65 characters are often truncated in Google search result snippets.",
            "suggested_improvement": "Shorten the title to under 60 characters so the entire message is visible in search snippets.",
            "detection_method": "String Length Analysis"
        })

    # 2. Meta Description
    meta_desc = soup.find('meta', attrs={'name': re.compile(r'^description$', re.IGNORECASE)})
    desc_text = meta_desc.get('content', '').strip() if meta_desc else ""
    metrics["meta_description"] = desc_text
    metrics["meta_description_length"] = len(desc_text)

    if not desc_text:
        findings.append({
            "name": "Missing Meta Description",
            "severity": "High",
            "affected_url": page_url,
            "evidence": "No <meta name='description'> found in the document.",
            "explanation": "Search engines use meta descriptions for the snippet summary beneath your title in organic search results.",
            "suggested_improvement": "Add a 140-160 character meta description highlighting key services, local area, and a clear call-to-action.",
            "detection_method": "DOM Head Inspection"
        })
    elif len(desc_text) < 70:
        findings.append({
            "name": "Meta Description Too Short",
            "severity": "Low",
            "affected_url": page_url,
            "evidence": f"Description is only {len(desc_text)} characters.",
            "explanation": "A short meta description may not provide enough context for users evaluating search results.",
            "suggested_improvement": "Expand to 130-160 characters describing benefits, services, and trust factors.",
            "detection_method": "String Length Analysis"
        })
    elif len(desc_text) > 170:
        findings.append({
            "name": "Meta Description Too Long",
            "severity": "Low",
            "affected_url": page_url,
            "evidence": f"Description is {len(desc_text)} characters.",
            "explanation": "Descriptions exceeding 160 characters are typically truncated with an ellipsis on search engine results pages.",
            "suggested_improvement": "Trim the description to 150-160 characters to avoid snippet truncation.",
            "detection_method": "String Length Analysis"
        })

    # 3. H1 Headings
    h1s = [h.get_text().strip() for h in soup.find_all('h1') if h.get_text().strip()]
    metrics["h1_tags"] = h1s
    if len(h1s) == 0:
        findings.append({
            "name": "Missing H1 Heading",
            "severity": "High",
            "affected_url": page_url,
            "evidence": "No <h1> elements with readable text found.",
            "explanation": "The H1 tag serves as the main topic headline of the page for search engine crawlers and screen readers.",
            "suggested_improvement": "Include a single, prominent <h1> tag that accurately summarizes the page topic.",
            "detection_method": "DOM Heading Query"
        })
    elif len(h1s) > 1:
        findings.append({
            "name": "Multiple H1 Headings",
            "severity": "Low",
            "affected_url": page_url,
            "evidence": f"Found {len(h1s)} H1 tags: {h1s[:2]}",
            "explanation": "While search engines can handle multiple H1s, best practice recommends a single main H1 headline per page for clear topical hierarchy.",
            "suggested_improvement": "Maintain one primary H1 for the page topic and use H2/H3 for supporting sections.",
            "detection_method": "DOM Heading Query"
        })

    # 4. Heading Hierarchy (H2 / H3)
    metrics["h2_count"] = len(soup.find_all('h2'))
    metrics["h3_count"] = len(soup.find_all('h3'))

    # 5. Canonical URL
    canonical_tag = soup.find('link', rel=re.compile(r'canonical', re.IGNORECASE))
    if canonical_tag and canonical_tag.get('href'):
        metrics["canonical_url"] = canonical_tag['href'].strip()
    else:
        findings.append({
            "name": "Missing Canonical Tag",
            "severity": "Medium",
            "affected_url": page_url,
            "evidence": "No <link rel='canonical'> specified.",
            "explanation": "Canonical tags tell search engines the preferred URL version, preventing duplicate content dilution between http/https or www/non-www.",
            "suggested_improvement": f"Add <link rel='canonical' href='{page_url}'> to the <head> of the page.",
            "detection_method": "DOM Link Rel Query"
        })

    # 6. Robots Meta (noindex check)
    robots_meta = soup.find('meta', attrs={'name': re.compile(r'robots', re.IGNORECASE)})
    if robots_meta:
        content = robots_meta.get('content', '').lower()
        if 'noindex' in content:
            metrics["is_noindex"] = True
            findings.append({
                "name": "Page Blocked by Noindex Tag",
                "severity": "High",
                "affected_url": page_url,
                "evidence": f"<meta name='robots' content='{content}'>",
                "explanation": "The 'noindex' directive explicitly instructs search engines NOT to index this page.",
                "suggested_improvement": "If this is the main landing page, remove 'noindex' to allow organic search indexing.",
                "detection_method": "Meta Tag Parser"
            })

    # 7. Image Alt Attributes
    images = soup.find_all('img')
    metrics["images_total"] = len(images)
    missing_alt = 0
    for img in images:
        alt = img.get('alt')
        if alt is None or not alt.strip():
            missing_alt += 1
    metrics["images_missing_alt"] = missing_alt

    if len(images) > 0 and missing_alt > 0:
        pct_missing = round((missing_alt / len(images)) * 100)
        if pct_missing > 30:
            findings.append({
                "name": "Images Missing Alt Attributes",
                "severity": "Medium",
                "affected_url": page_url,
                "evidence": f"{missing_alt} of {len(images)} images ({pct_missing}%) lack descriptive alt text.",
                "explanation": "Alt attributes provide accessibility for visually impaired users and allow search engines to understand image context.",
                "suggested_improvement": "Add descriptive, keyword-relevant alt attributes to informative images.",
                "detection_method": "DOM Image Tag Inspection"
            })

    # 8. Schema.org / Structured Data
    schema_types = []
    for s in soup.find_all('script', type='application/ld+json'):
        try:
            import json
            data = json.loads(s.string or '')
            def extract_types(obj):
                if isinstance(obj, dict):
                    t = obj.get('@type')
                    if t:
                        if isinstance(t, list): schema_types.extend(t)
                        else: schema_types.append(t)
                    for v in obj.values(): extract_types(v)
                elif isinstance(obj, list):
                    for i in obj: extract_types(i)
            extract_types(data)
        except Exception:
            pass

    metrics["schema_types"] = list(set(schema_types))
    if not schema_types:
        findings.append({
            "name": "No Schema.org Structured Data Detected",
            "severity": "Medium",
            "affected_url": page_url,
            "evidence": "No JSON-LD Schema.org script found.",
            "explanation": "Schema markup (such as LocalBusiness, Service, Organization) helps search engines parse business details, reviews, and service areas for rich search snippets.",
            "suggested_improvement": "Implement LocalBusiness JSON-LD schema with address, phone, opening hours, and service categories.",
            "detection_method": "JSON-LD Script Parser"
        })

    # 9. Open Graph Meta Tags
    og_title = soup.find('meta', property='og:title')
    og_image = soup.find('meta', property='og:image')
    metrics["has_og_tags"] = bool(og_title or og_image)
    if not (og_title and og_image):
        findings.append({
            "name": "Missing Open Graph Social Metadata",
            "severity": "Low",
            "affected_url": page_url,
            "evidence": "Missing og:title or og:image tags.",
            "explanation": "Open Graph tags control how your links appear when shared across Facebook, LinkedIn, iMessage, and WhatsApp.",
            "suggested_improvement": "Add og:title, og:description, and a high-resolution og:image (1200x630px).",
            "detection_method": "Meta Property Parser"
        })

    # 10. Links count & bounded broken internal link probe
    internal_links = []
    external_links_count = 0
    for a in soup.find_all('a', href=True):
        href = a['href'].strip()
        if href.startswith(('tel:', 'mailto:', 'javascript:', '#')):
            continue
        full_href = urljoin(page_url, href)
        parsed_href = urlparse(full_href)
        if base_domain in parsed_href.netloc.lower():
            clean_link = full_href.split('#')[0]
            if clean_link not in internal_links and clean_link != page_url.rstrip('/'):
                internal_links.append(clean_link)
        else:
            external_links_count += 1

    metrics["internal_links_count"] = len(internal_links)
    metrics["external_links_count"] = external_links_count
    metrics["broken_internal_links"] = []

    # Safe bounded broken internal link probe (max 3 candidate links, 3s timeout)
    for target_link in internal_links[:3]:
        try:
            probe_resp = safe_http_get(target_link, timeout=(2, 3), max_bytes=2048)
            if probe_resp.status_code in [404, 410, 500, 502, 503]:
                metrics["broken_internal_links"].append({
                    "url": target_link,
                    "status_code": probe_resp.status_code
                })
                findings.append({
                    "name": "Broken Internal Link Detected",
                    "severity": "High" if probe_resp.status_code in [404, 410] else "Medium",
                    "affected_url": target_link,
                    "evidence": f"Target link returned HTTP status {probe_resp.status_code}.",
                    "explanation": "Broken internal links cause visitor drop-off and waste search engine crawl budget.",
                    "suggested_improvement": "Fix or remove references to inaccessible internal URLs.",
                    "detection_method": "HTTP Link Probe"
                })
        except Exception:
            pass  # Non-fatal: do not fail audit on probe timeouts

    # Calculate overall SEO Health Score (0-100)
    score = 100
    for f in findings:
        if f["severity"] == "High": score -= 20
        elif f["severity"] == "Medium": score -= 10
        elif f["severity"] == "Low": score -= 5
    score = max(0, min(100, score))

    return {
        "findings": findings,
        "metrics": metrics,
        "seo_score": score
    }

def check_robots_and_sitemap(base_url: str):
    """
    Checks if robots.txt and sitemap.xml exist and are accessible.
    """
    results = {
        "has_robots_txt": False,
        "robots_txt_url": urljoin(base_url, '/robots.txt'),
        "has_sitemap_xml": False,
        "sitemap_url": urljoin(base_url, '/sitemap.xml'),
        "findings": []
    }

    # 1. robots.txt check
    try:
        r_resp = safe_http_get(results["robots_txt_url"], timeout=(3, 6))
        if r_resp.status_code == 200 and 'user-agent' in r_resp.text.lower():
            results["has_robots_txt"] = True
            # Check if sitemap is referenced inside robots.txt
            sitemap_match = re.search(r'Sitemap:\s*(https?://[^\s]+)', r_resp.text, re.IGNORECASE)
            if sitemap_match:
                results["sitemap_url"] = sitemap_match.group(1).strip()
    except Exception:
        pass

    if not results["has_robots_txt"]:
        results["findings"].append({
            "name": "Missing robots.txt File",
            "severity": "Medium",
            "affected_url": results["robots_txt_url"],
            "evidence": "404 or inaccessible at /robots.txt.",
            "explanation": "A robots.txt file guides search engine crawlers on which sections of the site to scan and locates your sitemap.",
            "suggested_improvement": "Create a standard robots.txt file declaring User-agent: * and linking to your XML sitemap.",
            "detection_method": "HTTP File Probe"
        })

    # 2. sitemap.xml check
    try:
        s_resp = safe_http_get(results["sitemap_url"], timeout=(3, 6))
        if s_resp.status_code == 200 and ('<urlset' in s_resp.text or '<sitemapindex' in s_resp.text):
            results["has_sitemap_xml"] = True
    except Exception:
        pass

    if not results["has_sitemap_xml"]:
        results["findings"].append({
            "name": "Missing XML Sitemap",
            "severity": "Medium",
            "affected_url": results["sitemap_url"],
            "evidence": "XML sitemap not found at standard location or inside robots.txt.",
            "explanation": "An XML sitemap helps search engines discover all indexable pages, updates, and service subpages efficiently.",
            "suggested_improvement": "Generate an automated XML sitemap and submit it to Google Search Console.",
            "detection_method": "HTTP File Probe"
        })

    return results
