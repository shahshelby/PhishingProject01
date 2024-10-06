import tldextract
import Levenshtein as lv
import requests
import whois
import re
from datetime import datetime

# Set of legitimate domains
legitimate_domains = {'example.com', 'google.com', 'facebook.com'}

# List of known phishing domains (for demonstration)
known_phishing_domains = {'phishingsite.com', 'malicious.com', 'fakefacebook.com'}

# Test URLs for scanning
test_urls = {
    'http://example.co',
    'http://examp1e.com',
    'https://www.google.security-update.com',
    'http://faceb00k.com/login',
    'https://google.com',
    'http://new-phishing-site.xyz',
    'http://legitimate-url.com',
}

# Function to extract domain parts
def extract_domain_parts(url):
    extracted = tldextract.extract(url)
    return extracted.subdomain, extracted.domain, extracted.suffix

# Function to check if the domain is a close match to legitimate domains
def is_misspelled_domain(domain, legitimate_domains, threshold=0.9):
    for legit_domain in legitimate_domains:
        similarity = lv.ratio(domain, legit_domain)
        if similarity >= threshold:
            return False  # It's a legitimate domain
    return True  # No close match found, possibly misspelled

# Function to check for URL length and suspicious characters
def is_suspicious_url(url):
    if len(url) > 75:  # Check for URL length
        return True
    if re.search(r'[!@#$%^&*(),?":{}|<>]', url):  # Check for suspicious characters
        return True
    return False

# Function to check domain age
def is_new_domain(domain):
    try:
        domain_info = whois.whois(domain)
        if domain_info.creation_date:
            age = (datetime.now() - domain_info.creation_date).days
            return age < 30  # Domain is less than 30 days old
    except Exception:
        return True  # If whois fails, treat as a new domain
    return False

# Function to check for phishing URLs
def is_phishing_url(url, legitimate_domains):
    subdomain, domain, suffix = extract_domain_parts(url)

    # Check if it's a known legitimate domain
    if f"{domain}.{suffix}" in legitimate_domains:
        return False
    # Check if it's in known phishing domains
    if f"{domain}.{suffix}" in known_phishing_domains:
        print(f"Known Phishing Site Detected: {url}")
        return True
    # Check for misspelled domain names
    if is_misspelled_domain(domain, legitimate_domains):
        print(f"Potential Phishing Detected (Misspelled): {url}")
        return True
    # Check for suspicious URL characteristics
    if is_suspicious_url(url):
        print(f"Suspicious URL Detected: {url}")
        return True
    # Check for new domain registration
    if is_new_domain(domain):
        print(f"New Domain Detected: {url}")
        return True

    return False

# Main execution block with user input
if __name__ == '__main__':
    # User can enter URLs or use predefined test URLs
    user_input = input("Do you want to enter URLs? (y/n): ")
    if user_input.lower() == 'y':
        urls_to_scan = input("Enter URLs separated by commas: ").split(',')
        urls_to_scan = [url.strip() for url in urls_to_scan]
    else:
        urls_to_scan = test_urls

    # Scan the URLs and provide summary
    phishing_count = 0
    for url in urls_to_scan:
        if is_phishing_url(url, legitimate_domains):
            phishing_count += 1

    print(f"\nScan completed. Total URLs scanned: {len(urls_to_scan)}")
    print(f"Potential phishing URLs detected: {phishing_count}")
