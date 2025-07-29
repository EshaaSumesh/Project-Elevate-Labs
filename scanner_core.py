import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import re

class WebVulnerabilityScanner:
    def __init__(self, target_url, depth=2):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.max_depth = depth
        self.visited_urls = set()
        self.forms = []
        self.results = {
            "headers": [],
            "sqli": [],
            "xss": [],
            "forms": [],
            "logs": []
        }

    # --------------------------
    # Logging utility
    def log(self, msg):
        self.results["logs"].append(msg)

    # --------------------------
    # Crawl website to find links & forms
    def crawl(self, url=None, depth=None):
        if depth is None:
            depth = self.max_depth
        if depth == 0:
            return
        if url is None:
            url = self.target_url
        if url in self.visited_urls:
            return

        try:
            self.log(f"[CRAWL] Visiting {url}")
            response = self.session.get(url, timeout=10)
            self.visited_urls.add(url)
            soup = BeautifulSoup(response.text, "html.parser")

            # Collect forms
            for form in soup.find_all("form"):
                form_details = self.extract_form_details(form, url)
                self.forms.append(form_details)

            # Collect links
            for link in soup.find_all("a", href=True):
                next_url = urljoin(url, link["href"])
                if self.target_url in next_url and next_url not in self.visited_urls:
                    self.crawl(next_url, depth - 1)

        except Exception as e:
            self.log(f"[ERROR] Crawling {url} failed: {e}")

    # --------------------------
    # Extract form details
    def extract_form_details(self, form, base_url):
        details = {
            "action": urljoin(base_url, form.attrs.get("action", "")),
            "method": form.attrs.get("method", "get").lower(),
            "inputs": []
        }
        for input_tag in form.find_all(["input", "textarea"]):
            name = input_tag.attrs.get("name")
            input_type = input_tag.attrs.get("type", "text")
            if name:
                details["inputs"].append({"name": name, "type": input_type})
        return details

    # --------------------------
    # Security headers check
    def check_security_headers(self):
        headers_to_check = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "Referrer-Policy"
        ]
        try:
            response = self.session.get(self.target_url, timeout=10)
            for header in headers_to_check:
                if header not in response.headers:
                    self.results["headers"].append(f"Missing: {header}")
        except Exception as e:
            self.log(f"[ERROR] Security header check failed: {e}")

    # --------------------------
    # SQL Injection Test
    def test_sql_injection(self, url):
        sql_payloads = ["'", "' OR '1'='1", "\" OR \"1\"=\"1"]
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return

        self.log("[SQLi] Testing for SQL Injection...")
        for key in params:
            for payload in sql_payloads:
                test_params = params.copy()
                test_params[key] = payload
                try:
                    response = self.session.get(url, params=test_params, timeout=10)
                    if re.search(r"(sql syntax|mysql|syntax error|unclosed quotation)", response.text, re.I):
                        vuln_msg = f"Parameter '{key}' vulnerable (payload: {payload})"
                        self.results["sqli"].append(vuln_msg)
                        self.log(f"[SQLi] {vuln_msg}")
                        break
                except Exception as e:
                    self.log(f"[ERROR] SQLi test failed: {e}")

    # --------------------------
    # XSS Test
    def test_xss(self, url):
        payload = "<script>alert('XSS')</script>"
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return

        self.log("[XSS] Testing for XSS...")
        for key in params:
            test_params = params.copy()
            test_params[key] = payload
            try:
                response = self.session.get(url, params=test_params, timeout=10)
                if payload in response.text:
                    vuln_msg = f"Parameter '{key}' vulnerable (payload: {payload})"
                    self.results["xss"].append(vuln_msg)
                    self.log(f"[XSS] {vuln_msg}")
            except Exception as e:
                self.log(f"[ERROR] XSS test failed: {e}")

    # --------------------------
    # Form Testing (SQLi & XSS)
    def test_forms(self):
        self.log("[FORMS] Testing forms for SQLi and XSS...")
        xss_payload = "<script>alert('XSS')</script>"

        for form in self.forms:
            action = form["action"]
            data = {inp["name"]: "test" for inp in form["inputs"]}

            # SQLi test
            for payload in ["'", "' OR '1'='1"]:
                data.update({inp["name"]: payload for inp in form["inputs"]})
                try:
                    if form["method"] == "post":
                        response = self.session.post(action, data=data, timeout=10)
                    else:
                        response = self.session.get(action, params=data, timeout=10)
                    if re.search(r"(sql syntax|mysql|syntax error)", response.text, re.I):
                        msg = f"Form at {action} vulnerable to SQLi"
                        self.results["forms"].append(msg)
                        self.log(f"[SQLi-FORM] {msg}")
                except Exception as e:
                    self.log(f"[ERROR] Form SQLi test failed: {e}")

            # XSS test
            try:
                data.update({inp["name"]: xss_payload for inp in form["inputs"]})
                if form["method"] == "post":
                    response = self.session.post(action, data=data, timeout=10)
                else:
                    response = self.session.get(action, params=data, timeout=10)
                if xss_payload in response.text:
                    msg = f"Form at {action} vulnerable to XSS"
                    self.results["forms"].append(msg)
                    self.log(f"[XSS-FORM] {msg}")
            except Exception as e:
                self.log(f"[ERROR] Form XSS test failed: {e}")

    # --------------------------
    # Run full scan
    def run(self):
        self.log(f"[START] Scanning {self.target_url}")
        self.check_security_headers()
        self.crawl()
        self.test_sql_injection(self.target_url)
        self.test_xss(self.target_url)
        self.test_forms()
        self.log("[DONE] Scan completed.")
        return self.results
