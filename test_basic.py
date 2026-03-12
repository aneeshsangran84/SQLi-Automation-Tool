#!/usr/bin/env python3
"""
test_basic.py - Quick test for Phase 1 (Basic Scanner)

INSTRUCTIONS:
    1. Make sure DVWA is running: docker-compose up -d
    2. Login to DVWA at http://localhost:8080 (admin/password)
    3. Copy your PHPSESSID cookie from the browser
    4. Run: python test_basic.py
"""

from sqli_tool.core.utils import print_banner, parse_cookies
from sqli_tool.modules.basic_scanner import BasicScanner


def main():
    print_banner()

    # === CONFIGURE THESE ===
    target_url = "http://localhost:8080/vulnerabilities/sqli/"

    # Get your PHPSESSID from the browser after logging into DVWA
    # In Chrome: F12 → Application → Cookies → copy PHPSESSID value
    cookie_string = "PHPSESSID=YOUR_SESSION_ID_HERE; security=low"

    # Parse the cookie string into a dict
    cookies = parse_cookies(cookie_string)

    print(f"[*] Target: {target_url}")
    print(f"[*] Cookies: {cookies}\n")

    # Create and run the scanner
    scanner = BasicScanner(url=target_url, cookies=cookies)
    results = scanner.scan()

    # Show vulnerable findings
    print("=" * 60)
    print("FINDINGS SUMMARY")
    print("=" * 60)
    for r in results:
        if r["vulnerable"]:
            print(f"  🔴 {r['header']} → {r['payload']}")


if __name__ == "__main__":
    main()