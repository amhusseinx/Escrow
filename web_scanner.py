#!/usr/bin/env python3

"""
Web Application Security Scanner (Ethical Hacking Tool)

Disclaimer: This script is intended for educational purposes only and for use in ethical hacking scenarios
where explicit permission has been granted by the owner of the target system. Unauthorized use of this
script against any system is illegal and unethical. The developer is not responsible for any misuse or damage
caused by this script.
"""

import requests
from urllib.parse import urljoin

def scan_website_basic_check(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print(f"[+] Successfully accessed {url}")
        else:
            print(f"[-] Failed to access {url}. Status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error accessing {url}: {e}")

def xss_scanner(url):
    print(f"[*] Checking for XSS on {url}")
    xss_payloads = [
        "<script>alert(\'XSS\')</script>",
        "<img src=x onerror=alert(\'XSS\')>",
        "\';!--\\\"<XSS>=&{()}"
    ]
    
    for payload in xss_payloads:
        test_url = f"{url}?q={payload}"
        try:
            response = requests.get(test_url)
            if payload in response.text:
                print(f"[!!!] Possible XSS vulnerability found with payload: {payload} at {test_url}")
            else:
                print(f"[+] No XSS found with payload: {payload}")
        except requests.exceptions.RequestException as e:
            print(f"[!] Error checking XSS on {test_url}: {e}")

def sql_injection_scanner(url):
    print(f"[*] Checking for SQL Injection on {url}")
    sql_payloads = [
        "\' OR 1=1 --",
        "\' OR \'1\'=\'1",
        "1\tOR\t1=1"
    ]

    for payload in sql_payloads:
        test_url = f"{url}?id={payload}"
        try:
            response = requests.get(test_url)
            # Simple check for common SQL error messages or specific content
            if "You have an error in your SQL syntax" in response.text or \
               "Warning: mysql_fetch_array()" in response.text or \
               "SQLSTATE" in response.text:
                print(f"[!!!] Possible SQL Injection vulnerability found with payload: {payload} at {test_url}")
            else:
                print(f"[+] No SQL Injection found with payload: {payload}")
        except requests.exceptions.RequestException as e:
            print(f"[!] Error checking SQL Injection on {test_url}: {e}")

def directory_traversal_scanner(url):
    print(f"[*] Checking for Directory Traversal on {url}")
    traversal_payloads = [
        "../etc/passwd",
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "%2e%2e%2fetc%2fpasswd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    ]

    for payload in traversal_payloads:
        test_url = urljoin(url, payload)
        try:
            response = requests.get(test_url)
            # Check for common indicators of successful directory traversal
            if "root:x:0:0:root" in response.text or "daemon:x:1:1:daemon" in response.text:
                print(f"[!!!] Possible Directory Traversal vulnerability found with payload: {payload} at {test_url}")
            else:
                print(f"[+] No Directory Traversal found with payload: {payload}")
        except requests.exceptions.RequestException as e:
            print(f"[!] Error checking Directory Traversal on {test_url}: {e}")

def scan_website(url):
    print(f"[*] Scanning: {url}")
    # Implement various scanning modules here
    scan_website_basic_check(url)
    xss_scanner(url)
    sql_injection_scanner(url)
    directory_traversal_scanner(url)

if __name__ == "__main__":
    target_url = input("Enter the target URL (e.g., http://example.com): ")
    scan_website(target_url)




# Add warnings within the script itself about ethical and legal use.
# This script is for educational and authorized ethical hacking purposes only.
# Do not use it on any system without explicit permission.


