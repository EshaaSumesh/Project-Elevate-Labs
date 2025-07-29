import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import re
import time
from collections import deque

class WebVulnerabilityScanner:
    def __init__(self, target_url, depth=2):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        # More common User-Agent to avoid immediate blocking
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36'})
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
        self.sql_error_patterns = [ # More robust SQL error patterns
            r"sql syntax", r"mysql", r"syntax error", r"unclosed quotation",
            r"ORA-\d{5}", r"SQLSTATE", r"PostgreSQL error", r"Warning: pg_query",
            r"Microsoft SQL Native Client", r"ODBC Driver", r"Invalid column name",
            r"quoted string not properly terminated", r"numeric value out of range"
        ]
        self.xss_detection_strings = [ # Strings to look for in response that indicate XSS payload execution
            "alert('XSS')", "alert(\"XSS\")", "alert&#x28;&#x27;XSS&#x27;&#x29;", # Encoded variants
            "onerror=alert('XSS')", "onload=alert('XSS')"
        ]


    # --------------------------
    # Logging utility
    def log(self, msg, level="INFO"):
        # Add timestamp to logs for better debugging
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        self.results["logs"].append(f"[{timestamp}][{level}] {msg}")

    # --------------------------
    # Add a finding to results
    def add_finding(self, vuln_type, url, payload, evidence, severity):
        # Fix for f-string backslash error: perform replace outside the f-string expression
        # Or, even better, encode to escape newlines
        sanitized_evidence = evidence[:200].replace('\n', '\\n').replace('\r', '\\r') # Shorten and escape newlines
        
        finding = {
            "type": vuln_type,
            "url": url,
            "payload": payload,
            "evidence": evidence, # Keep full evidence for the report
            "severity": severity
        }
        # Categorize findings correctly based on type
        if "SQL Injection" in vuln_type:
            self.results["sqli"].append(finding)
        elif "Cross-Site Scripting" in vuln_type:
            self.results["xss"].append(finding)
        elif "CSRF" in vuln_type:
            self.results["csrf"].append(finding)
        elif "IDOR" in vuln_type:
            self.results["idor"].append(finding)
        elif "Sensitive File" in vuln_type or "Directory Listing" in vuln_type:
            self.results["sensitive_files"].append(finding)
        elif "Header" in vuln_type:
            self.results["headers"].append(finding)
        # Note: 'forms' category will be populated directly from test_forms, not add_finding
        self.log(f"[FINDING] {severity} - {vuln_type} at {url} with payload '{payload}' - Evidence: {sanitized_evidence}...", "SUCCESS" if severity in ["High", "Medium"] else "INFO")


    # --------------------------
    # Crawl website to find links & forms
    def crawl(self, url=None, depth=None):
        if depth is None:
            depth = self.max_depth
        if url is None:
            url = self.target_url

        queue = deque([(url, depth)])

        while queue:
            current_url, current_depth = queue.popleft()

            # Normalize URL to avoid duplicates with different query string orders
            # Simplified normalization for basic caching. For robust crawling, consider more sophisticated URL canonicalization.
            base_url_no_query = current_url.split('?')[0].split('#')[0]
            
            # Check for visited URL. Use current_url in visited_urls to track full paths.
            # However, for avoiding redundant work in low depth, also check normalized path.
            if current_url in self.visited_urls:
                self.log(f"[CRAWL] Skipping already visited: {current_url}", "DEBUG")
                continue
            
            # Additional check to avoid excessive crawling of similar URLs at low depths
            # This is a heuristic and might skip some valid unique content
            if current_depth < self.max_depth and base_url_no_query in [u.split('?')[0].split('#')[0] for u in self.visited_urls]:
                # We only log this if it was a distinct URL being considered but decided to skip due to base path already visited
                if current_url not in self.visited_urls: 
                    self.log(f"[CRAWL] Skipping normalized (base path already visited): {current_url}", "DEBUG")
                continue

            # Add to visited before making request to prevent race conditions in queue
            self.visited_urls.add(current_url) 

            try:
                self.log(f"[CRAWL] Visiting {current_url} (Depth Remaining: {current_depth})")
                response = self.session.get(current_url, timeout=15)
                

                # Check for directory listing
                # Heuristic: Check common directory listing phrases AND 200 OK
                if response.status_code == 200 and any(phrase in response.text for phrase in ["Index of /", "<title>Index of /", "Directory Listing For"]):
                    self.add_finding("Possible Directory Listing", current_url, "N/A", "Found typical directory listing content.", "Low")


                soup = BeautifulSoup(response.text, "html.parser")

                # Collect forms
                for form in soup.find_all("form"):
                    form_details = self.extract_form_details(form, current_url)
                    if form_details:
                        # Avoid duplicate forms if action/method/inputs are same
                        # A simple comparison of the dicts might suffice
                        if form_details not in self.forms: # This will check if an identical dict exists
                            self.forms.append(form_details)
                            self.log(f"[CRAWL] Found form: Action='{form_details['action']}', Method='{form_details['method']}'", "INFO")

                # Collect links for further crawling
                if current_depth > 0:
                    for link in soup.find_all("a", href=True):
                        next_url = urljoin(current_url, link["href"])
                        # Basic check to stay within target domain
                        parsed_next_url = urlparse(next_url)
                        if urlparse(self.target_url).netloc == parsed_next_url.netloc: # Strict domain check
                            # Avoid crawling logout links or external links (already covered, but reiterate importance)
                            if not any(keyword in next_url.lower() for keyword in ["logout", "exit", "disconnect"]): # Added "disconnect"
                                # Avoid fragment identifiers for crawling purposes unless specific need
                                next_url_cleaned = parsed_next_url._replace(fragment="").geturl()
                                if next_url_cleaned not in self.visited_urls:
                                    queue.append((next_url_cleaned, current_depth - 1))
                                else:
                                    self.log(f"[CRAWL] Skipping already queued/visited (cleaned): {next_url_cleaned}", "DEBUG")
                        else:
                            self.log(f"[CRAWL] Skipping external link: {next_url}", "DEBUG")

            except requests.exceptions.Timeout:
                self.log(f"[ERROR] Crawling {current_url} timed out after 15 seconds.", "WARNING")
            except requests.exceptions.ConnectionError as ce:
                self.log(f"[ERROR] Could not connect to {current_url}: {ce}", "ERROR")
            except requests.exceptions.RequestException as re:
                self.log(f"[ERROR] Request failed for {current_url}: {re}", "ERROR")
            except Exception as e:
                self.log(f"[ERROR] Unexpected error crawling {current_url}: {e}", "ERROR")

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
        details["csrf_token_field"] = None
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
            "Content-Security-Policy": "Missing Content-Security-Policy can lead to XSS, clickjacking, and data injection attacks.",
            "X-Frame-Options": "Missing X-Frame-Options can lead to clickjacking vulnerabilities.",
            "Strict-Transport-Security": "Missing HSTS can allow downgrade attacks and cookie hijacking.",
            "X-Content-Type-Options": "Missing X-Content-Type-Options can lead to MIME-sniffing vulnerabilities.",
            "Referrer-Policy": "Missing Referrer-Policy can leak sensitive information in referrer headers.",
            "Permissions-Policy": "Missing Permissions-Policy allows all features by default, which can be risky.",
            "X-XSS-Protection": "Missing X-XSS-Protection header can allow browsers to perform XSS filtering." # Older, but still useful to check
        }
        try:
            response = self.session.get(self.target_url, timeout=10)
            self.add_finding("Info - HTTP Status", self.target_url, "N/A", f"Initial HTTP Status Code: {response.status_code}", "Info")

            for header, description in headers_to_check.items():
                if header not in response.headers:
                    self.add_finding("Missing Security Header", self.target_url, "N/A", f"Header '{header}' is missing. {description}", self.vulnerability_map["Missing Security Header"])
                else:
                    self.log(f"[HEADERS] Header '{header}' is present: {response.headers[header]}", "INFO")
        except requests.exceptions.Timeout:
            self.log(f"[ERROR] Security header check timed out for {self.target_url}", "WARNING")
        except requests.exceptions.ConnectionError as ce:
            self.log(f"[ERROR] Could not connect to {self.target_url} for header check: {ce}", "ERROR")
        except requests.exceptions.RequestException as re:
            self.log(f"[ERROR] Request failed for {self.target_url} during header check: {re}", "ERROR")
        except Exception as e:
            self.log(f"[ERROR] Unexpected error during security header check for {self.target_url}: {e}", "ERROR")

    # --------------------------
    # Core SQL Injection Test Logic
    def _test_sql_injection_core(self, url, method, data_or_params, input_name, original_value):
        sql_payloads = {
            "'": "Single quote",
            "\"": "Double quote",
            " OR 1=1-- ": "Boolean-based always true (SQL comment)",
            "\" OR 1=1-- ": "Boolean-based always true (double quote, SQL comment)",
            " AND 1=1-- ": "Boolean-based always true for AND",
            " AND 1=2-- ": "Boolean-based always false for AND",
            " UNION SELECT 1,2,3,4,5,6,7,8,9,10-- ": "Union-based (testing column count up to 10)", # Common column counts
            "1 AND SLEEP(5)": "Time-based blind (MySQL/PostgreSQL)",
            "1 WAITFOR DELAY '0:0:5'--": "Time-based blind (MSSQL)"
        }

        self.log(f"[SQLi] Testing '{input_name}' on {url} ({method.upper()})", "DEBUG")

        for payload, description in sql_payloads.items():
            test_data = data_or_params.copy()
            # Ensure we're modifying the value properly, especially for lists from parse_qs
            if isinstance(original_value, list):
                test_data[input_name] = original_value[0] + payload
            else:
                test_data[input_name] = original_value + payload

            response = None
            try:
                start_time = time.time()
                if method == "post":
                    response = self.session.post(url, data=test_data, timeout=15)
                else: # GET method
                    # urlencode is important for GET requests
                    response = self.session.get(url, params=test_data, timeout=15)
                end_time = time.time()

                # Error-based detection
                for pattern in self.sql_error_patterns:
                    if response and re.search(pattern, response.text, re.I):
                        self.add_finding("SQL Injection", url, payload,
                                         f"Input '{input_name}' caused SQL error: '{re.search(pattern, response.text, re.I).group(0)}' via {method.upper()} request.",
                                         self.vulnerability_map[f"SQL Injection ({method.upper()})"])
                        return True # Found vulnerability for this input, move to next input/URL

                # Time-based detection (if payload suggests it)
                if ("SLEEP(5)" in payload or "WAITFOR DELAY" in payload) and (end_time - start_time) >= 4.5:
                    self.add_finding("SQL Injection (Time-based)", url, payload,
                                        f"Input '{input_name}' caused a significant time delay ({round(end_time - start_time, 2)}s) via {method.upper()} request.",
                                        self.vulnerability_map[f"SQL Injection ({method.upper()})"])
                    return True # Found vulnerability

                # Boolean-based detection (if payload suggests it)
                if ("1=1" in payload or "1=2" in payload) and response:
                    # Send a control request (without vulnerability) to compare
                    control_data_true = data_or_params.copy()
                    if isinstance(original_value, list):
                        control_data_true[input_name] = original_value[0] + " AND 1=1-- "
                    else:
                        control_data_true[input_name] = original_value + " AND 1=1-- "
                    
                    control_data_false = data_or_params.copy()
                    if isinstance(original_value, list):
                        control_data_false[input_name] = original_value[0] + " AND 1=2-- "
                    else:
                        control_data_false[input_name] = original_value + " AND 1=2-- "

                    response_true = self.session.request(method, url, data=(control_data_true if method == "post" else None), params=(control_data_true if method == "get" else None), timeout=10)
                    response_false = self.session.request(method, url, data=(control_data_false if method == "post" else None), params=(control_data_false if method == "get" else None), timeout=10)

                    # If responses for true and false conditions are significantly different
                    # This is a strong indicator of boolean blind SQLi
                    if response_true and response_false and response_true.text != response_false.text:
                            self.add_finding("SQL Injection (Boolean-based)", url, payload,
                                                f"Input '{input_name}' shows boolean-based behavior. Response for 'true' differs from 'false' conditions.",
                                                self.vulnerability_map[f"SQL Injection ({method.upper()})"])
                            return True

            except requests.exceptions.Timeout:
                self.log(f"[WARNING] SQLi test for {url} ({input_name}) with payload '{payload}' timed out.", "WARNING")
            except requests.exceptions.ConnectionError as ce:
                self.log(f"[ERROR] Could not connect to {url} during SQLi test: {ce}", "ERROR")
            except requests.exceptions.RequestException as re:
                self.log(f"[ERROR] Request failed for {url} during SQLi test: {re}", "ERROR")
            except Exception as e:
                self.log(f"[ERROR] Unexpected error during SQLi test for {url}: {e}", "ERROR")
        return False # No vulnerability found for this input

    # --------------------------
    # SQL Injection Test for GET parameters
    def test_sql_injection(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query) # parse_qs returns dict with list values

        if not params:
            return

        self.log(f"[SQLi] Testing URL GET parameters for SQL Injection on {url}...", "INFO")
        for key in params:
            # Pass the first value from the list, as it's typically what you modify
            original_value = params[key][0] 
            # Call the core testing logic
            self._test_sql_injection_core(url, "get", params, key, original_value)


    # --------------------------
    # Core XSS Test Logic
    def _test_xss_core(self, url, method, data_or_params, input_name, original_value):
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "\" onmouseover=\"alert('XSS')",
            "' onfocus='alert(\"XSS\")",
            "><script>alert(document.cookie)</script>",
            # HTML encoded versions often found in reflections
            "&#x3C;script&#x3E;alert(&#x27;XSS&#x27;)&#x3C;/script&#x3E;",
            "<img src=x onerror=alert&#x28;&#x27;XSS&#x27;&#x29;>",
            # Double encoded versions sometimes bypass filters
            "%253Cscript%253Ealert(%2527XSS%2527)%253C/script%253E"
        ]
        
        self.log(f"[XSS] Testing '{input_name}' on {url} ({method.upper()})", "DEBUG")

        for payload in xss_payloads:
            test_data = data_or_params.copy()
            if isinstance(original_value, list):
                test_data[input_name] = original_value[0] + payload
            else:
                test_data[input_name] = original_value + payload

            try:
                if method == "post":
                    response = self.session.post(url, data=test_data, timeout=10)
                else: # GET method
                    response = self.session.get(url, params=test_data, timeout=10)
                
                # Check for direct reflection or various encoded reflections
                # Look for the payload itself or its "executed" form
                if payload in response.text or any(detect_str in response.text for detect_str in self.xss_detection_strings):
                    self.add_finding("Cross-Site Scripting", url, payload,
                                    f"Input '{input_name}' reflects XSS payload or its execution string in response via {method.upper()} request.",
                                    self.vulnerability_map[f"Cross-Site Scripting ({method.upper()})"])
                    return True # Found vulnerability for this input
            except requests.exceptions.Timeout:
                self.log(f"[WARNING] XSS test for {url} ({input_name}) with payload '{payload}' timed out.", "WARNING")
            except requests.exceptions.ConnectionError as ce:
                self.log(f"[ERROR] Could not connect to {url} during XSS test: {ce}", "ERROR")
            except requests.exceptions.RequestException as re:
                self.log(f"[ERROR] Request failed for {url} during XSS test: {re}", "ERROR")
            except Exception as e:
                self.log(f"[ERROR] Unexpected error during XSS test for {url}: {e}", "ERROR")
        return False # No vulnerability found for this input

    # --------------------------
    # XSS Test for GET parameters
    def test_xss(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return

        self.log(f"[XSS] Testing URL GET parameters for XSS on {url}...", "INFO")
        for key in params:
            original_value = params[key][0]
            # Call the core testing logic
            self._test_xss_core(url, "get", params, key, original_value)


    # --------------------------
    # Form Testing (SQLi & XSS & CSRF)
    def test_forms(self):
        self.log("[FORMS] Testing forms for SQLi, XSS, and CSRF...", "INFO")

        for form in self.forms:
            action = form["action"]
            method = form["method"]
            
            # CSRF Test (basic: check for token presence)
            if form["csrf_token_field"] is None:
                self.add_finding("CSRF Token Missing", action, "N/A", "No CSRF token field found in form. Consider implementing CSRF protection.", self.vulnerability_map["CSRF Token Missing"])
            else:
                self.log(f"[FORM TEST] CSRF token field '{form['csrf_token_field']}' found in form at {action}.", "INFO")

            # Test each input field in the form
            for input_field in form["inputs"]:
                # Only test text-based inputs that would take payloads
                if input_field["type"] in ["text", "search", "url", "tel", "email", "password", "textarea"]: 
                    
                    # Initial data for the form submission
                    # Use the actual 'value' attribute if present, otherwise default to "test_value"
                    initial_data = {inp["name"]: inp.get("value", "") or "test_value" for inp in form["inputs"]}
                    
                    # SQLi test for this input field
                    # Note: We need to pass the *current state* of initial_data to the core functions
                    # and the *original value* of the specific input being tested
                    if self._test_sql_injection_core(action, method, initial_data, input_field["name"], input_field.get("value", "")):
                        self.log(f"[FORM VULN] SQLi found in form field '{input_field['name']}' at {action}", "HIGH")
                        # Add to form results here since it's a form-specific vuln
                        self.results["forms"].append({
                            "type": "SQL Injection (Form)",
                            "url": action,
                            "payload": "Refer to logs for specific payload",
                            "evidence": f"Field '{input_field['name']}' is vulnerable to SQL Injection.",
                            "severity": "High"
                        })

                    # XSS test for this input field
                    if self._test_xss_core(action, method, initial_data, input_field["name"], input_field.get("value", "")):
                        self.log(f"[FORM VULN] XSS found in form field '{input_field['name']}' at {action}", "HIGH")
                        # Add to form results here
                        self.results["forms"].append({
                            "type": "Cross-Site Scripting (Form)",
                            "url": action,
                            "payload": "Refer to logs for specific payload",
                            "evidence": f"Field '{input_field['name']}' is vulnerable to XSS.",
                            "severity": "High"
                        })


    # --------------------------
    # Check for sensitive files and common paths
    def check_sensitive_files(self):
        sensitive_paths = [
            "robots.txt", ".env", ".git/config", "backup.zip", "admin/", "phpinfo.php",
            "sitemap.xml", "crossdomain.xml", "server-status", ".htaccess", "web.config",
            "config.php", "config.inc", "admin/config.php", "inc/config.php",
            "logs/error.log", "logs/access.log", "debug.log",
            "data.sql", "database.sql", "dump.sql",
            # Common web server configs
            "nginx.conf", "httpd.conf",
            # Application specific files (examples)
            "wp-config.php", # WordPress
            "configuration.php", # Joomla
            "local.xml" # Magento
        ]
        self.log("[FILES] Checking for sensitive files and directories...", "INFO")
        for path in sensitive_paths:
            full_url = urljoin(self.target_url, path)
            try:
                response = self.session.get(full_url, timeout=7) # Increased timeout slightly
                # Check for 200 OK AND not a generic 404 page by looking at common 404 content
                # Also check for common "Forbidden" messages if status is 403
                if response.status_code == 200 and not any(f404_phrase in response.text.lower() for f404_phrase in ["not found", "page not found", "error 404", "does not exist", "no such file or directory"]):
                    self.add_finding("Sensitive File Found", full_url, "N/A", f"File/directory '{path}' found (Status: {response.status_code}).", "High")
                elif response.status_code == 403 and any(f403_phrase in response.text.lower() for f403_phrase in ["forbidden", "access denied"]):
                    self.log(f"[INFO] Access to {full_url} was forbidden (Status: 403).", "INFO")
            except requests.exceptions.Timeout:
                self.log(f"[WARNING] Check for sensitive file {full_url} timed out.", "INFO")
            except requests.exceptions.ConnectionError as ce:
                self.log(f"[ERROR] Could not connect to {full_url} for sensitive file check: {ce}", "ERROR")
            except requests.exceptions.RequestException as re:
                self.log(f"[ERROR] Request failed for {full_url} during sensitive file check: {re}", "ERROR")
            except Exception as e:
                self.log(f"[ERROR] Unexpected error during sensitive file check for {full_url}: {e}", "ERROR")

    # --------------------------
    # Basic IDOR check (conceptual, highly application specific)
    def test_idor_basic(self):
        self.log("[IDOR] Performing basic IDOR checks (conceptual)...", "INFO")
        
        urls_with_numeric_ids = []
        for url in self.visited_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query) # parse_qs returns dict with list values
            for key, values in params.items():
                if 'id' in key.lower() and values and values[0].isdigit():
                    urls_with_numeric_ids.append((url, key, int(values[0])))
                    break # Only consider the first numeric ID parameter found

        for original_url, id_param_key, original_id_value in urls_with_numeric_ids:
            # Try accessing adjacent IDs and potentially a common default ID like '1'
            ids_to_test = set([original_id_value - 1, original_id_value + 1, 1])
            if original_id_value == 1: # If original is 1, no need to test 1 again
                ids_to_test.remove(1)

            for test_id in [id_val for id_val in sorted(list(ids_to_test)) if id_val > 0]:
                parsed = urlparse(original_url)
                params = parse_qs(parsed.query)
                params[id_param_key] = [str(test_id)] # Modify the ID parameter (ensure it's a list)
                test_url = parsed._replace(query=urlencode(params, doseq=True)).geturl()
                
                self.log(f"[IDOR] Attempting IDOR on {original_url} (changing {id_param_key} from {original_id_value} to {test_id})", "DEBUG")

                try:
                    response_original = self.session.get(original_url, timeout=10)
                    response_test = self.session.get(test_url, timeout=10)

                    # Check if status codes are 200 for both, and content is different,
                    # AND the test content doesn't explicitly deny access.
                    if response_original.status_code == 200 and response_test.status_code == 200:
                        if response_original.text != response_test.text and \
                           not any(deny_phrase in response_test.text.lower() for deny_phrase in ["access denied", "unauthorized", "permission denied", "not found", "invalid id"]):
                            self.add_finding("Potential IDOR", test_url, f"Changed '{id_param_key}' from {original_id_value} to {test_id}", "Heuristic: Page loaded with different ID and didn't explicitly deny access/show error. Manual verification needed.", "Medium")
                        else:
                            self.log(f"[IDOR] No IDOR detected for {test_url} (content similar or access denied).", "DEBUG")
                    elif response_test.status_code in [401, 403]:
                        self.log(f"[IDOR] Access explicitly denied for {test_url} (Status: {response_test.status_code}).", "INFO")
                    else:
                        self.log(f"[IDOR] Non-200 status code for {test_url} (Status: {response_test.status_code}).", "DEBUG")


                except requests.exceptions.Timeout:
                    self.log(f"[WARNING] IDOR test for {test_url} timed out.", "WARNING")
                except requests.exceptions.ConnectionError as ce:
                    self.log(f"[ERROR] Could not connect to {test_url} during IDOR test: {ce}", "ERROR")
                except requests.exceptions.RequestException as re:
                    self.log(f"[ERROR] Request failed for {test_url} during IDOR test: {re}", "ERROR")
                except Exception as e:
                    self.log(f"[ERROR] Unexpected error during IDOR test for {test_url}: {e}", "ERROR")


    # --------------------------
    # Run full scan
    def run(self):
        self.log(f"[START] Scanning {self.target_url}", "INFO")
        
        self.log("Running security header checks...", "INFO")
        self.check_security_headers()
        
        self.log(f"Starting crawling up to depth {self.max_depth}...", "INFO")
        self.crawl()
        
        self.log("Testing SQL Injection on all visited URLs with GET parameters...", "INFO")
        for url in list(self.visited_urls): # Iterate over a copy to avoid issues if set changes
            parsed = urlparse(url)
            # Only test URLs with query parameters
            if parsed.query:
                self.test_sql_injection(url)
        
        self.log("Testing XSS on all visited URLs with GET parameters...", "INFO")
        for url in list(self.visited_urls):
            parsed = urlparse(url)
            if parsed.query:
                self.test_xss(url)
        
        self.log("Testing forms for vulnerabilities...", "INFO")
        self.test_forms()

        self.log("Checking for sensitive files and directory listings...", "INFO")
        self.check_sensitive_files()

        self.log("Performing basic IDOR checks...", "INFO")
        self.test_idor_basic() 

        self.log("[DONE] Scan completed.", "INFO")
        return self.results