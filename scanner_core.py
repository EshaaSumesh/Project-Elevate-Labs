import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import re
import time # For time-based SQLi
from collections import deque

class WebVulnerabilityScanner:
    def __init__(self, target_url, depth=2):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'CyberSecScanner/1.0'}) # Add a user-agent
        self.max_depth = depth
        self.visited_urls = set()
        self.forms = []
        self.results = {
            "headers": [],
            "sqli": [],
            "xss": [],
            "forms": [], # This will now contain SQLi and XSS findings for forms
            "csrf": [],
            "idor": [], # Placeholder for basic IDOR checks
            "sensitive_files": [],
            "logs": []
        }
        self.vulnerability_map = { # Define vulnerability severities
            "Missing Security Header": "Medium",
            "SQL Injection (GET)": "High",
            "SQL Injection (POST)": "High",
            "Cross-Site Scripting (GET)": "High",
            "Cross-Site Scripting (POST)": "High",
            "CSRF Token Missing": "Medium",
            "Possible Directory Listing": "Low",
            "Sensitive File Found": "High",
            "Potential IDOR": "Medium"
        }

    # --------------------------
    # Logging utility
    def log(self, msg, level="INFO"):
        self.results["logs"].append(f"[{level}] {msg}")

    # --------------------------
    # Add a finding to results
    def add_finding(self, vuln_type, url, payload, evidence, severity):
        finding = {
            "type": vuln_type,
            "url": url,
            "payload": payload,
            "evidence": evidence,
            "severity": severity
        }
        if "SQL Injection" in vuln_type:
            self.results["sqli"].append(finding)
        elif "Cross-Site Scripting" in vuln_type:
            self.results["xss"].append(finding)
        elif "Form" in vuln_type: # For form-based SQLi/XSS, categorize under forms
            self.results["forms"].append(finding)
        elif "CSRF" in vuln_type:
            self.results["csrf"].append(finding)
        elif "IDOR" in vuln_type:
            self.results["idor"].append(finding)
        elif "Sensitive File" in vuln_type or "Directory Listing" in vuln_type:
            self.results["sensitive_files"].append(finding)
        elif "Header" in vuln_type:
            self.results["headers"].append(finding)
        self.log(f"[FINDING] {severity} - {vuln_type} at {url} with payload '{payload}' - Evidence: {evidence[:100]}...")


    # --------------------------
    # Crawl website to find links & forms
    def crawl(self, url=None, depth=None):
        if depth is None:
            depth = self.max_depth
        if url is None:
            url = self.target_url

        # Use a deque for BFS-like crawling and manage depth
        queue = deque([(url, depth)])

        while queue:
            current_url, current_depth = queue.popleft()

            if current_url in self.visited_urls or current_depth < 0:
                continue

            try:
                self.log(f"[CRAWL] Visiting {current_url} (Depth: {self.max_depth - current_depth})")
                response = self.session.get(current_url, timeout=15) # Increased timeout
                self.visited_urls.add(current_url)
                soup = BeautifulSoup(response.text, "html.parser")

                # Check for directory listing
                if "Index of /" in response.text and response.status_code == 200:
                    self.add_finding("Possible Directory Listing", current_url, "N/A", "Index of / found", "Low")


                # Collect forms
                for form in soup.find_all("form"):
                    form_details = self.extract_form_details(form, current_url)
                    if form_details:
                        self.forms.append(form_details)
                        self.log(f"[CRAWL] Found form: Action='{form_details['action']}', Method='{form_details['method']}'")

                # Collect links for further crawling
                if current_depth > 0:
                    for link in soup.find_all("a", href=True):
                        next_url = urljoin(current_url, link["href"])
                        # Only crawl links within the target domain and not already visited
                        if urlparse(self.target_url).netloc in urlparse(next_url).netloc and next_url not in self.visited_urls:
                            queue.append((next_url, current_depth - 1))

            except requests.exceptions.Timeout:
                self.log(f"[ERROR] Crawling {current_url} timed out after 15 seconds.", "WARNING")
            except requests.exceptions.ConnectionError:
                self.log(f"[ERROR] Could not connect to {current_url}.", "ERROR")
            except Exception as e:
                self.log(f"[ERROR] Crawling {current_url} failed: {e}", "ERROR")

    # --------------------------
    # Extract form details
    def extract_form_details(self, form, base_url):
        details = {
            "action": urljoin(base_url, form.attrs.get("action", "")),
            "method": form.attrs.get("method", "get").lower(),
            "inputs": []
        }
        for input_tag in form.find_all(["input", "textarea", "select"]): # Include select tags
            name = input_tag.attrs.get("name")
            input_type = input_tag.attrs.get("type", "text")
            value = input_tag.attrs.get("value", "") # Get default value for inputs
            if name:
                details["inputs"].append({"name": name, "type": input_type, "value": value})

        # Check for CSRF token (basic check for hidden inputs named 'csrf' or containing 'token')
        for input_tag in form.find_all("input", type="hidden"):
            name = input_tag.attrs.get("name", "").lower()
            if "csrf" in name or "token" in name:
                details["csrf_token_field"] = input_tag.attrs.get("name")
                details["csrf_token_value"] = input_tag.attrs.get("value")
                break
        return details

    # --------------------------
    # Security headers check
    def check_security_headers(self):
        headers_to_check = {
            "Content-Security-Policy": "Missing Content-Security-Policy can lead to XSS, clickjacking.",
            "X-Frame-Options": "Missing X-Frame-Options can lead to clickjacking.",
            "Strict-Transport-Security": "Missing HSTS can allow downgrade attacks.",
            "X-Content-Type-Options": "Missing X-Content-Type-Options can lead to MIME-sniffing vulnerabilities.",
            "Referrer-Policy": "Missing Referrer-Policy can leak sensitive information in referrer headers."
        }
        try:
            response = self.session.get(self.target_url, timeout=10)
            self.add_finding("Info - HTTP Status", self.target_url, "N/A", f"Status Code: {response.status_code}", "Info")

            for header, description in headers_to_check.items():
                if header not in response.headers:
                    self.add_finding("Missing Security Header", self.target_url, "N/A", f"Header '{header}' is missing. {description}", self.vulnerability_map["Missing Security Header"])
                else:
                    self.log(f"[HEADERS] Header '{header}' is present: {response.headers[header]}", "INFO")
        except requests.exceptions.Timeout:
            self.log(f"[ERROR] Security header check timed out for {self.target_url}", "WARNING")
        except requests.exceptions.ConnectionError:
            self.log(f"[ERROR] Could not connect to {self.target_url} for header check.", "ERROR")
        except Exception as e:
            self.log(f"[ERROR] Security header check failed for {self.target_url}: {e}", "ERROR")

    # --------------------------
    # SQL Injection Test for GET parameters
    def test_sql_injection(self, url):
        sql_error_patterns = [
            r"sql syntax", r"mysql", r"syntax error", r"unclosed quotation",
            r"ORA-\d{5}", r"SQLSTATE", r"PostgreSQL error", r"Warning: pg_query",
            r"Microsoft SQL Native Client", r"ODBC Driver"
        ]
        # Basic payloads + time-based
        sql_payloads = {
            "'": "Single quote",
            "' OR '1'='1": "Always true condition",
            "\" OR \"1\"=\"1": "Always true condition (double quote)",
            "1 AND SLEEP(5)": "Time-based blind (MySQL/PostgreSQL)",
            "1 WAITFOR DELAY '0:0:5'--": "Time-based blind (MSSQL)"
        }

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return

        self.log("[SQLi] Testing URL GET parameters for SQL Injection...")
        for key in params:
            original_value = params[key][0] # Store original value

            for payload, description in sql_payloads.items():
                test_params = params.copy()
                test_params[key] = payload # Apply payload to current parameter

                try:
                    start_time = time.time()
                    response = self.session.get(url, params=test_params, timeout=15) # Increased timeout
                    end_time = time.time()

                    # Error-based detection
                    for pattern in sql_error_patterns:
                        if re.search(pattern, response.text, re.I):
                            self.add_finding("SQL Injection (GET)", url, payload,
                                             f"Parameter '{key}' caused SQL error: '{re.search(pattern, response.text, re.I).group(0)}'",
                                             self.vulnerability_map["SQL Injection (GET)"])
                            return # Found vulnerability for this URL, move to next
                    
                    # Time-based detection
                    if ("SLEEP(5)" in payload or "WAITFOR DELAY" in payload) and (end_time - start_time) >= 4.5:
                         self.add_finding("SQL Injection (GET) - Time-based", url, payload,
                                             f"Parameter '{key}' caused a time delay (approx {round(end_time - start_time, 2)}s)",
                                             self.vulnerability_map["SQL Injection (GET)"])
                         return # Found vulnerability for this URL, move to next


                except requests.exceptions.Timeout:
                    self.log(f"[WARNING] SQLi test for {url} with payload '{payload}' timed out.", "WARNING")
                except requests.exceptions.ConnectionError:
                    self.log(f"[ERROR] Could not connect to {url} during SQLi test.", "ERROR")
                except Exception as e:
                    self.log(f"[ERROR] SQLi test for {url} failed: {e}", "ERROR")
            
            # Reset parameter to original value for next key or next vulnerability test
            params[key] = [original_value]


    # --------------------------
    # XSS Test for GET parameters
    def test_xss(self, url):
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "\" onmouseover=\"alert('XSS')",
            "' onfocus='alert(\"XSS\")",
            "><script>alert(document.cookie)</script>"
        ]
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return

        self.log("[XSS] Testing URL GET parameters for XSS...")
        for key in params:
            original_value = params[key][0] # Store original value
            for payload in xss_payloads:
                test_params = params.copy()
                test_params[key] = payload
                try:
                    response = self.session.get(url, params=test_params, timeout=10)
                    if payload in response.text:
                        self.add_finding("Cross-Site Scripting (GET)", url, payload,
                                         f"Parameter '{key}' reflects payload in response.",
                                         self.vulnerability_map["Cross-Site Scripting (GET)"])
                        return # Found vulnerability for this URL, move to next

                except requests.exceptions.Timeout:
                    self.log(f"[WARNING] XSS test for {url} with payload '{payload}' timed out.", "WARNING")
                except requests.exceptions.ConnectionError:
                    self.log(f"[ERROR] Could not connect to {url} during XSS test.", "ERROR")
                except Exception as e:
                    self.log(f"[ERROR] XSS test for {url} failed: {e}", "ERROR")
            
            # Reset parameter to original value
            params[key] = [original_value]

    # --------------------------
    # Form Testing (SQLi & XSS & CSRF)
    def test_forms(self):
        self.log("[FORMS] Testing forms for SQLi, XSS, and CSRF...")
        sql_error_patterns = [
            r"sql syntax", r"mysql", r"syntax error", r"unclosed quotation",
            r"ORA-\d{5}", r"SQLSTATE", r"PostgreSQL error", r"Warning: pg_query",
            r"Microsoft SQL Native Client", r"ODBC Driver"
        ]
        xss_payload = "<script>alert('XSS')</script>"
        sql_payload = "' OR '1'='1"

        for form in self.forms:
            action = form["action"]
            method = form["method"]
            initial_data = {inp["name"]: inp.get("value", "") or "test_value" for inp in form["inputs"]}
            
            self.log(f"[FORM TEST] Testing form at {action} ({method.upper()})", "INFO")

            # CSRF Test (basic: check for token presence)
            if "csrf_token_field" not in form:
                self.add_finding("CSRF Token Missing", action, "N/A", "No CSRF token field found in form.", self.vulnerability_map["CSRF Token Missing"])
            else:
                self.log(f"[FORM TEST] CSRF token field '{form['csrf_token_field']}' found.", "INFO")

            # SQLi test for each input field
            for input_field in form["inputs"]:
                if input_field["type"] in ["text", "search", "url", "tel", "email", "password", "textarea"]: # Only test text-based inputs
                    test_data = initial_data.copy()
                    test_data[input_field["name"]] = sql_payload

                    try:
                        if method == "post":
                            response = self.session.post(action, data=test_data, timeout=15)
                        else: # GET method for forms
                            response = self.session.get(action, params=test_data, timeout=15)

                        for pattern in sql_error_patterns:
                            if re.search(pattern, response.text, re.I):
                                self.add_finding("SQL Injection (FORM)", action, sql_payload,
                                                 f"Form field '{input_field['name']}' vulnerable to SQLi. Evidence: '{re.search(pattern, response.text, re.I).group(0)}'",
                                                 self.vulnerability_map["SQL Injection (POST)"])
                                break # Move to next form or next vulnerability type for this form
                    except requests.exceptions.Timeout:
                        self.log(f"[WARNING] Form SQLi test for {action} with field '{input_field['name']}' timed out.", "WARNING")
                    except requests.exceptions.ConnectionError:
                        self.log(f"[ERROR] Could not connect to {action} during form SQLi test.", "ERROR")
                    except Exception as e:
                        self.log(f"[ERROR] Form SQLi test failed for {action}: {e}", "ERROR")

            # XSS test for each input field
            for input_field in form["inputs"]:
                if input_field["type"] in ["text", "search", "url", "tel", "email", "password", "textarea"]: # Only test text-based inputs
                    test_data = initial_data.copy()
                    test_data[input_field["name"]] = xss_payload

                    try:
                        if method == "post":
                            response = self.session.post(action, data=test_data, timeout=10)
                        else:
                            response = self.session.get(action, params=test_data, timeout=10)

                        if xss_payload in response.text:
                            self.add_finding("Cross-Site Scripting (FORM)", action, xss_payload,
                                             f"Form field '{input_field['name']}' reflects XSS payload.",
                                             self.vulnerability_map["Cross-Site Scripting (POST)"])
                    except requests.exceptions.Timeout:
                        self.log(f"[WARNING] Form XSS test for {action} with field '{input_field['name']}' timed out.", "WARNING")
                    except requests.exceptions.ConnectionError:
                        self.log(f"[ERROR] Could not connect to {action} during form XSS test.", "ERROR")
                    except Exception as e:
                        self.log(f"[ERROR] Form XSS test failed for {action}: {e}", "ERROR")
    
    # --------------------------
    # Check for sensitive files and common paths
    def check_sensitive_files(self):
        sensitive_paths = [
            "robots.txt", ".env", ".git/config", "backup.zip", "admin/", "phpinfo.php",
            "sitemap.xml", "crossdomain.xml", "server-status"
        ]
        self.log("[FILES] Checking for sensitive files and directories...")
        for path in sensitive_paths:
            full_url = urljoin(self.target_url, path)
            try:
                response = self.session.get(full_url, timeout=5)
                # Check for 200 OK and not a generic 404 page (by content)
                if response.status_code == 200 and "not found" not in response.text.lower():
                    self.add_finding("Sensitive File Found", full_url, "N/A", f"File/directory '{path}' found (Status: {response.status_code}).", "High")
            except requests.exceptions.Timeout:
                self.log(f"[WARNING] Check for sensitive file {full_url} timed out.", "INFO")
            except requests.exceptions.ConnectionError:
                self.log(f"[ERROR] Could not connect to {full_url} for sensitive file check.", "ERROR")
            except Exception as e:
                self.log(f"[ERROR] Sensitive file check for {full_url} failed: {e}", "ERROR")

    # --------------------------
    # Basic IDOR check (conceptual, highly application specific)
    def test_idor_basic(self):
        # This is a very basic, conceptual IDOR check.
        # Real IDOR detection requires understanding application logic (e.g., how user IDs are managed in URLs/APIs).
        # For a practical scanner, this would involve authenticated scanning and
        # attempting to access resources of other users by manipulating IDs.
        self.log("[IDOR] Performing basic IDOR checks (conceptual)...", "INFO")
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)

        # Example: if a URL has an 'id=' parameter, try changing it
        for key, values in params.items():
            if 'id' in key.lower() and values[0].isdigit():
                original_id = int(values[0])
                # Try accessing a different ID, e.g., ID-1 or ID+1
                for test_id in [original_id - 1, original_id + 1]:
                    if test_id > 0: # Ensure ID is positive
                        test_params = params.copy()
                        test_params[key] = str(test_id)
                        test_url = parsed._replace(query=urlencode(test_params, doseq=True)).geturl()
                        try:
                            response = self.session.get(test_url, timeout=10)
                            # This is a very weak check: if the page loads fine and is different from original but doesn't explicitly deny access
                            # A real check would involve comparing content, checking for error messages (e.g., "Access Denied") vs. valid content.
                            if response.status_code == 200 and len(response.text) > 1000: # Heuristic: check if content length is substantial
                                # For a proper IDOR, you'd need to compare this response with an expected "access denied" response
                                # or analyze for sensitive data that shouldn't be accessible.
                                self.log(f"[IDOR] Attempted to change '{key}' from {original_id} to {test_id} at {test_url}. Check manually for IDOR.", "INFO")
                                # For a fully automated IDOR, you'd need to compare content and look for specific indicators of unauthorized access.
                                # This is left as an 'Info' log as automated IDOR is complex.
                                self.add_finding("Potential IDOR", test_url, f"Changed '{key}' from {original_id} to {test_id}", "Heuristic: Page loaded with different ID. Manual verification needed.", "Info")
                        except requests.exceptions.Timeout:
                            self.log(f"[WARNING] IDOR test for {test_url} timed out.", "WARNING")
                        except requests.exceptions.ConnectionError:
                            self.log(f"[ERROR] Could not connect to {test_url} during IDOR test.", "ERROR")
                        except Exception as e:
                            self.log(f"[ERROR] IDOR test for {test_url} failed: {e}", "ERROR")


    # --------------------------
    # Run full scan
    def run(self):
        self.log(f"[START] Scanning {self.target_url}", "INFO")
        
        self.log("Running security header checks...", "INFO")
        self.check_security_headers()
        
        self.log(f"Starting crawling up to depth {self.max_depth}...", "INFO")
        self.crawl()
        
        self.log("Testing GET parameters for SQL Injection...", "INFO")
        self.test_sql_injection(self.target_url)
        
        self.log("Testing GET parameters for XSS...", "INFO")
        self.test_xss(self.target_url)
        
        self.log("Testing forms for vulnerabilities...", "INFO")
        self.test_forms()

        self.log("Checking for sensitive files and directory listings...", "INFO")
        self.check_sensitive_files()

        # self.log("Performing basic IDOR checks...", "INFO")
        # self.test_idor_basic() # This is more conceptual for now, keeping it commented out for basic functionality

        self.log("[DONE] Scan completed.", "INFO")
        return self.results