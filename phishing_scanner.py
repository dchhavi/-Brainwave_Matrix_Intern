import re
import requests
from urllib.parse import urlparse
import whois

# Blacklist of suspicious top-level domains (TLDs)
SUSPICIOUS_TLDS = ['.xyz', '.top', '.work', '.click', '.zip', '.gq']

# Basic list of phishing-related keywords
PHISHING_KEYWORDS = ['access', 'security', 'verification', 'support', 'payment', 'shipment']

# Basic list of known phishing domains (for demo purposes, use a real blacklist)
BLACKLISTED_DOMAINS = ['examplephishing.com', 'badwebsite.xyz']

def check_blacklist(domain):
    """Check if the domain is blacklisted."""
    return domain in BLACKLISTED_DOMAINS

def check_suspicious_tld(domain):
    """Check if the domain uses a suspicious top-level domain (TLD)."""
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return True
    return False

def extract_domain(url):
    """Extract the domain from the URL."""
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    return domain

def check_phishing_keywords(content):
    """Check the HTML content for phishing-related keywords."""
    for keyword in PHISHING_KEYWORDS:
        if keyword.lower() in content.lower():
            return True
    return False

def scan_url(url):
    """Scan the URL for potential phishing indicators."""
    domain = extract_domain(url)
    print(f"Scanning URL: {url}")
    print(f"Domain: {domain}")
    
    #0. Check if URL is using HTTP instead of HTTPS
    if url.startswith("http://"):
        return "Warning: Website is using HTTP, which is insecure."
    
    # 1. Check if the domain is in the blacklist
    if check_blacklist(domain):
        return "Warning: Domain is blacklisted."
    
    # 2. Check for suspicious TLDs
    if check_suspicious_tld(domain):
        return "Warning: Suspicious TLD detected."
    
    # 3. Check the HTML content of the page
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            if check_phishing_keywords(response.text):
                return "Warning: Phishing keywords detected in content."
    except requests.exceptions.RequestException:
        return "Error: Unable to retrieve URL content."
    
    # 4. Check domain WHOIS data (e.g., age of domain registration)
    try:
        whois_info = whois.whois(domain)
        if whois_info.creation_date:
            print(f"Domain creation date: {whois_info.creation_date}")
    except Exception as e:
        print(f"Error checking WHOIS: {e}")
    
    return "No phishing indicators found."

# Example usage
url_to_scan = "http://httpforever.com/"
result = scan_url(url_to_scan)
print(result)
