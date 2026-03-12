"""
utils.py - Helper functions used across the tool

What's going on:
    Utility functions for:
    - Parsing cookie strings into dictionaries
    - Calculating statistical averages
    - Pretty-printing results
    - Parsing URLs
"""

from urllib.parse import urlparse, parse_qs


def parse_cookies(cookie_string):
    """
    Convert a cookie string into a dictionary.

    What's going on:
        Browsers send cookies as: "name1=value1; name2=value2"
        Python's requests library wants: {"name1": "value1", "name2": "value2"}
        This function converts between the two formats.

    Args:
        cookie_string (str): Raw cookie string from browser
            Example: "PHPSESSID=abc123; security=low"

    Returns:
        dict: Parsed cookies
            Example: {"PHPSESSID": "abc123", "security": "low"}
    """
    cookies = {}
    if not cookie_string:
        return cookies

    for pair in cookie_string.split(";"):
        pair = pair.strip()
        if "=" in pair:
            key, value = pair.split("=", 1)  # Split on first '=' only
            cookies[key.strip()] = value.strip()

    return cookies


def calculate_average(values):
    """
    Calculate the arithmetic mean of a list of numbers.

    Used for:
        - Averaging baseline response sizes
        - Averaging baseline response times (for time-based blind)

    Args:
        values (list): List of numbers

    Returns:
        float: The average
    """
    if not values:
        return 0
    return sum(values) / len(values)


def size_differs(baseline_size, test_size, threshold=0.10):
    """
    Check if two sizes differ by more than the threshold percentage.

    What's going on:
        If the baseline response is 5000 bytes and the injected response
        is 5600 bytes, that's a 12% difference — likely a SQLi indicator.

        We use percentage rather than absolute bytes because pages vary wildly.

    Args:
        baseline_size (float): Average normal response size in bytes
        test_size (int): Response size of the injected request
        threshold (float): Minimum % difference to flag (default: 10%)

    Returns:
        bool: True if the sizes differ significantly
    """
    if baseline_size == 0:
        return test_size != 0

    deviation = abs(test_size - baseline_size) / baseline_size
    return deviation > threshold


def print_banner():
    """Print the tool banner."""
    banner = r"""
    ╔══════════════════════════════════════════════════╗
    ║        SQLi Automation Tool v1.0                 ║
    ║        For Authorized Testing Only               ║
    ╚══════════════════════════════════════════════════╝
    """
    print(banner)


def print_result(header, injected_into, payload, baseline_size, injected_size, vulnerable):
    """
    Pretty-print a single test result.

    Args:
        header (str): Which header was injected (e.g., "User-Agent")
        injected_into (str): Description of injection point
        payload (str): The SQLi payload used
        baseline_size (float): Normal response size
        injected_size (int): Response size after injection
        vulnerable (bool): Whether this looks vulnerable
    """
    status = "🔴 VULNERABLE" if vulnerable else "🟢 Safe"
    deviation = 0
    if baseline_size > 0:
        deviation = ((injected_size - baseline_size) / baseline_size) * 100

    print(f"    [{status}]")
    print(f"      Injection Point : {injected_into} → {header}")
    print(f"      Payload         : {payload}")
    print(f"      Baseline Size   : {baseline_size:.0f} bytes")
    print(f"      Injected Size   : {injected_size} bytes")
    print(f"      Size Deviation  : {deviation:+.1f}%")
    print()