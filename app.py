import time
import random
import re
import pandas as pd
import requests
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
from flask import Flask, render_template, request, jsonify
from email_validator import validate_email, EmailNotValidError

app = Flask(__name__)

def get_random_delay():
    return random.uniform(2, 4)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_about_page_link(url, headers):
    about_urls = [url.rstrip('/') + '/about', url.rstrip('/') + '/about-us']
    for a_url in about_urls:
        try:
            resp = requests.get(a_url, headers=headers, timeout=10, verify=False)
            if resp.status_code == 200:
                return a_url
        except: pass
    return ""

def extract_social_and_email(html):
    # Strict regex with word boundaries
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}\b'
    raw_emails = list(set(re.findall(email_pattern, html)))
    
    emails = []
    # Comprehensive blacklist
    invalid_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.woff', '.woff2', '.ttf', '.css', '.js', '.mp4', '.pdf']
    invalid_keywords = ['sentry', 'example', 'domain.com', 'wixpress', 'noreply', 'no-reply', 'test', 'yourname', 'email.com', '123', 'sitelink', 'wixsite']
    
    for em in raw_emails:
        em_lower = em.lower()
        
        # Check invalid extensions
        if any(em_lower.endswith(ext) for ext in invalid_extensions):
            continue
            
        # Check invalid keywords
        if any(keyword in em_lower for keyword in invalid_keywords):
            continue
            
        # Check if it starts with % or numbers only, which are usually fake
        if em_lower.startswith('%') or re.match(r'^\d+@', em_lower):
            continue
            
        # Validate email syntax and domain MX records
        try:
            valid = validate_email(em, check_deliverability=True)
            emails.append(valid.normalized)
        except EmailNotValidError:
            pass # Invalid email, skip it
        
    # Sort emails to prioritize generic ones like info@, contact@, admin@
    def email_priority(email):
        e = email.lower()
        if e.startswith('info@') or e.startswith('contact@') or e.startswith('admin@') or e.startswith('sales@') or e.startswith('hello@'):
            return 0
        return 1
        
    emails.sort(key=email_priority)
    
    soup = BeautifulSoup(html, 'html.parser')
    links = [a.get('href') for a in soup.find_all('a', href=True) if a.get('href')]
    
    facebook, instagram, linkedin = "", "", ""
    
    for link in links:
        link_lower = link.lower()
        if 'facebook.com' in link_lower and 'sharer' not in link_lower and 'share.php' not in link_lower and not facebook:
            facebook = link
        elif 'instagram.com' in link_lower and not instagram:
            instagram = link
        elif 'linkedin.com' in link_lower and 'share' not in link_lower and not linkedin:
            linkedin = link
            
    return emails[0] if emails else "", facebook, instagram, linkedin

def scrape_website_details(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=15, verify=False)
        email, fb, insta, linkedin = extract_social_and_email(response.text)
        
        about_info = get_about_page_link(url, headers)
        
        contact_urls = [url.rstrip('/') + '/contact', url.rstrip('/') + '/contact-us']
        for curl in contact_urls:
            if not email or not fb or not insta or not linkedin:
                try:
                    c_resp = requests.get(curl, headers=headers, timeout=15, verify=False)
                    c_email, c_fb, c_insta, c_linkedin = extract_social_and_email(c_resp.text)
                    email = email or c_email
                    fb = fb or c_fb
                    insta = insta or c_insta
                    linkedin = linkedin or c_linkedin
                except: pass
                    
        return email, fb, insta, linkedin, about_info
    except Exception as e:
        print(f"Error on website {url}: {e}")
        return "", "", "", "", ""

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scrape', methods=['POST'])
def scrape_api():
    data = request.json
    url = data.get('url')
    type_ = data.get('type')
    
    if not url:
        return jsonify({"error": "URL is required"}), 400
        
    result = {
        "Business Name": "",
        "Phone Number": "",
        "Website": "",
        "Email": "",
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
            
        # Scrape website for emails/socials if website exists
        if result["Website"]:
            email, fb, insta, linkedin, about_info = scrape_website_details(result["Website"])
            result["Email"] = email
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
