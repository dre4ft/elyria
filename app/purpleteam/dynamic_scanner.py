# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Dynamic Scanner — IAST-style dynamic testing.
Validates static findings against live API endpoints using crafted requests.
"""

import json
import time
from urllib.parse import urljoin
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from core.logging import get_logger

_log = get_logger("purpleteam.dynamic")


def _make_session(timeout=10):
    s = requests.Session()
    retry = Retry(total=0, read=0, connect=0)
    adapter = HTTPAdapter(max_retries=retry, pool_connections=2, pool_maxsize=4, pool_block=True)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.timeout = timeout
    return s


class DynamicScanner:
    def __init__(self, target_endpoint, static_findings=None, auth_config=None):
        self.target = target_endpoint.rstrip("/")
        self.auth = auth_config or {}
        self.static_findings = static_findings or []
        self.session = _make_session()
        self._apply_auth()
        self._validated = {}
        self._logs = []

    def _apply_auth(self):
        headers = self.auth.get("headers", {})
        if headers:
            self.session.headers.update(headers)
        token = self.auth.get("bearer_token")
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"
        basic_user = self.auth.get("basic_user")
        basic_pass = self.auth.get("basic_pass")
        if basic_user and basic_pass:
            self.session.auth = (basic_user, basic_pass)
        proxy = self.auth.get("proxy")
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def _url(self, path="/"):
        return urljoin(self.target, path)

    def _request(self, method, path, **kwargs):
        """Make an HTTP request and log it."""
        url = self._url(path)
        start = time.time()
        try:
            resp = self.session.request(method, url, **kwargs)
            elapsed = int((time.time() - start) * 1000)
            body = resp.text[:2000]
            log_entry = {
                "method": method, "url": url, "path": path,
                "status": resp.status_code, "headers": dict(resp.headers),
                "body_preview": body, "elapsed_ms": elapsed,
            }
            self._logs.append(log_entry)
            return resp, log_entry
        except requests.RequestException as e:
            elapsed = int((time.time() - start) * 1000)
            log_entry = {
                "method": method, "url": url, "path": path,
                "status": 0, "error": str(e), "elapsed_ms": elapsed,
            }
            self._logs.append(log_entry)
            return None, log_entry

    def run(self, scan_id, add_finding_fn, progress_cb=None):
        """Run dynamic validation tests against target endpoint."""
        total = 0

        # Phase 1: Baseline security tests (always run)
        baseline_tests = [
            self._test_security_headers,
            self._test_cors,
            self._test_http_methods,
            self._test_error_disclosure,
            self._test_auth_required,
            self._test_sensitive_data_exposure,
        ]
        for i, test_fn in enumerate(baseline_tests):
            if progress_cb:
                progress_cb(5 + int(i / len(baseline_tests) * 30), f"Baseline: {test_fn.__name__}")
            try:
                total += test_fn(scan_id, add_finding_fn)
            except Exception as e:
                _log.warning(f"Dynamic test {test_fn.__name__} failed: {e}")

        # Phase 2: Validate static findings against live endpoint
        if self.static_findings:
            if progress_cb:
                progress_cb(35, "Validating static findings against target...")
            try:
                validated = self._validate_static_findings(scan_id, add_finding_fn)
                total += validated
            except Exception as e:
                _log.warning(f"Static findings validation failed: {e}")

        # Phase 3: Targeted injection tests
        if progress_cb:
            progress_cb(60, "Running targeted injection tests...")
        targeted_tests = [
            self._test_xss_reflected,
            self._test_sqli_basic,
            self._test_path_traversal,
            self._test_open_redirect,
        ]
        for i, test_fn in enumerate(targeted_tests):
            if progress_cb:
                progress_cb(60 + int(i / len(targeted_tests) * 25), f"Targeted: {test_fn.__name__}")
            try:
                total += test_fn(scan_id, add_finding_fn)
            except Exception as e:
                _log.warning(f"Dynamic test {test_fn.__name__} failed: {e}")

        if progress_cb:
            progress_cb(90, f"Dynamic testing complete ({total} findings)")
        return total

    def _validate_static_findings(self, scan_id, add_finding_fn):
        """Use static findings to target specific endpoints for validation."""
        count = 0
        import re

        # Extract potential endpoints from findings
        endpoints = set()
        for f in self.static_findings:
            file_path = f.get("file_path", "")
            title = f.get("title", "")
            cwe = f.get("cwe_id", "")
            evidence = f.get("evidence", {})
            if isinstance(evidence, str):
                try:
                    evidence = json.loads(evidence)
                except Exception:
                    evidence = {}

            # Extract URL patterns from evidence or title
            for text in [file_path, title, json.dumps(evidence)]:
                for m in re.finditer(r'(?:/[a-zA-Z0-9._~:/?#\[\]@!$&\'()*+,;=%-]+){2,}', text):
                    path = m.group(0)
                    if path.startswith("/") and len(path) > 2:
                        endpoints.add(path[:100])

        # Test each discovered endpoint
        for path in list(endpoints)[:20]:
            resp, log = self._request("GET", path)
            if resp is None:
                continue

            # Check if endpoint is accessible without auth
            if resp.status_code == 200:
                count += self._add(scan_id, add_finding_fn,
                    f"Endpoint accessible without auth: {path}",
                    f"Static analysis identified endpoint {path} which returned 200 OK without authentication.",
                    "medium", "auth_bypass",
                    {"path": path, "status": resp.status_code})

            # Check for error disclosure on discovered endpoints
            body = resp.text.lower()
            error_kw = ["traceback", "exception", "sql", "syntax error", "stack trace",
                       "debug", "internal server error", "at line"]
            if any(kw in body for kw in error_kw):
                count += self._add(scan_id, add_finding_fn,
                    f"Error disclosure on {path}",
                    f"Endpoint {path} returns verbose error information.",
                    "medium", "error_disclosure",
                    {"path": path, "status": resp.status_code})

        return count

    def _add(self, scan_id, add_finding_fn, title, description, severity, category, evidence=None):
        add_finding_fn(
            scan_id=scan_id, title=title, description=description,
            severity=severity, category=f"dynamic_{category}",
            file_path=self.target, evidence=evidence or {},
            finding_part="practices",
        )
        return 1

    # ── Test implementations ──

    def _test_security_headers(self, scan_id, add_finding_fn):
        count = 0
        resp, log = self._request("GET", "/")
        if resp is None:
            return count
        headers = {k.lower(): v for k, v in resp.headers.items()}
        required = {
            "strict-transport-security": ("HSTS missing", "high"),
            "x-content-type-options": ("X-Content-Type-Options missing", "low"),
            "x-frame-options": ("X-Frame-Options missing (clickjacking risk)", "medium"),
            "content-security-policy": ("Content-Security-Policy missing", "medium"),
        }
        for hdr, (desc, sev) in required.items():
            if hdr not in headers:
                count += self._add(scan_id, add_finding_fn, desc,
                    f"Security header '{hdr}' is missing from the response. Target: {self.target}",
                    sev, "security_headers", {"missing_header": hdr})
        return count

    def _test_cors(self, scan_id, add_finding_fn):
        count = 0
        resp, log = self._request("OPTIONS", "/",
            headers={"Origin": "https://evil.com", "Access-Control-Request-Method": "GET"})
        if resp is None:
            return count
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*" or acao == "https://evil.com":
            count += self._add(scan_id, add_finding_fn, "Overly permissive CORS",
                f"CORS allows cross-origin requests from '{acao}'. Target: {self.target}",
                "high" if acao == "*" else "medium", "cors",
                {"origin_sent": "https://evil.com", "allowed_origin": acao})
        return count

    def _test_http_methods(self, scan_id, add_finding_fn):
        methods = ["OPTIONS", "TRACE", "PUT", "DELETE", "PATCH"]
        count = 0
        for method in methods:
            resp, log = self._request(method, "/")
            if resp and resp.status_code < 400:
                count += self._add(scan_id, add_finding_fn,
                    f"Dangerous HTTP method allowed: {method}",
                    f"Method {method} returned {resp.status_code} on {self.target}/",
                    "low", "http_methods", {"method": method, "status": resp.status_code})
        return count

    def _test_error_disclosure(self, scan_id, add_finding_fn):
        count = 0
        # Request a non-existent path to trigger error
        resp, log = self._request("GET", "/__elyria_test_nonexistent__")
        if resp is None:
            return count
        body = resp.text.lower()
        error_indicators = ["traceback", "stack trace", "exception", "sql error", "syntax error",
                           "db error", "database error", "debug mode", "at line", "in file"]
        for indicator in error_indicators:
            if indicator in body:
                count += self._add(scan_id, add_finding_fn, "Verbose error disclosure",
                    f"Response for non-existent path reveals internal information: '{indicator}' detected.",
                    "medium", "error_disclosure",
                    {"path": "/__elyria_test_nonexistent__", "indicator": indicator})
                break
        # Check for debug info in headers
        server = resp.headers.get("Server", "")
        x_powered = resp.headers.get("X-Powered-By", "")
        if server and any(v in server.lower() for v in ["php", "apache", "tomcat", "jetty"]):
            count += self._add(scan_id, add_finding_fn, "Server header reveals technology",
                f"Server header '{server}' exposes technology stack.",
                "info", "error_disclosure", {"server_header": server})
        if x_powered:
            count += self._add(scan_id, add_finding_fn, "X-Powered-By header present",
                f"X-Powered-By: {x_powered} reveals technology details.",
                "info", "error_disclosure", {"x_powered_by": x_powered})
        return count

    def _test_auth_required(self, scan_id, add_finding_fn):
        count = 0
        # Try common sensitive paths without auth
        sensitive = ["/admin", "/api/admin", "/actuator", "/actuator/health",
                     "/swagger-ui.html", "/api-docs", "/graphql",
                     "/.env", "/config", "/debug"]
        for path in sensitive:
            resp, log = self._request("GET", path)
            if resp and resp.status_code == 200:
                count += self._add(scan_id, add_finding_fn,
                    f"Sensitive endpoint accessible: {path}",
                    f"Path {path} returned 200 OK without authentication on {self.target}",
                    "high", "auth", {"path": path, "status": resp.status_code})
        return count

    def _test_sensitive_data_exposure(self, scan_id, add_finding_fn):
        count = 0
        sensitive_patterns = [
            (r'password["\s:=]+["\']?[^"\'\s,}]{3,}', "Password in response"),
            (r'(?:aws_access_key|aws_secret|AKIA[A-Z0-9]{16})', "AWS credential exposed"),
            (r'(?:-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----)', "Private key exposed"),
            (r'(?:eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})', "JWT token in response"),
        ]
        import re
        resp, log = self._request("GET", "/")
        if resp:
            for pattern, desc in sensitive_patterns:
                if re.search(pattern, resp.text):
                    count += self._add(scan_id, add_finding_fn, desc,
                        f"Sensitive data pattern detected in response body from {self.target}/",
                        "critical", "data_exposure", {"pattern": desc})
                    break
        return count

    def _test_xss_reflected(self, scan_id, add_finding_fn):
        import re
        count = 0
        payload = "<elyriaXSS>test</elyriaXSS>"
        # Try common query param names
        params = ["q", "search", "query", "id", "name", "page", "redirect", "url", "return"]
        for param in params:
            resp, log = self._request("GET", f"/?{param}={requests.utils.quote(payload)}")
            if resp and "<elyriaxss>" in resp.text.lower():
                count += self._add(scan_id, add_finding_fn,
                    f"Reflected XSS via parameter '{param}'",
                    f"Parameter '{param}' reflects unencoded input on {self.target}/",
                    "high", "xss", {"parameter": param, "payload": payload})
                break
        return count

    def _test_sqli_basic(self, scan_id, add_finding_fn):
        count = 0
        payloads = [("' OR '1'='1", "SQL error", "sql"), ("' OR 1=1--", "syntax error", "sql")]
        params = ["id", "user_id", "product_id", "order_id"]
        for param in params:
            for payload, err_type, _ in payloads:
                resp, log = self._request("GET", f"/?{param}={requests.utils.quote(payload)}")
                if resp:
                    body = resp.text.lower()
                    if any(e in body for e in ["sql", "mysql", "sqlite", "postgresql", "ora-", "syntax error"]):
                        count += self._add(scan_id, add_finding_fn,
                            f"Possible SQL Injection via '{param}'",
                            f"SQL error keywords detected when injecting parameter '{param}' on {self.target}/",
                            "critical", "sqli", {"parameter": param, "payload": payload})
                        break
        return count

    def _test_path_traversal(self, scan_id, add_finding_fn):
        count = 0
        payloads = [
            ("../../../etc/passwd", "root:"),
            ("....//....//....//etc/passwd", "root:"),
            ("..\\..\\..\\windows\\win.ini", "[fonts]"),
        ]
        params = ["file", "path", "filename", "template", "page", "include"]
        for param in params:
            for payload, indicator in payloads:
                resp, log = self._request("GET", f"/?{param}={requests.utils.quote(payload)}")
                if resp and indicator.lower() in resp.text.lower():
                    count += self._add(scan_id, add_finding_fn,
                        f"Path Traversal via '{param}'",
                        f"Path traversal payload returned system file content on {self.target}/",
                        "critical", "path_traversal", {"parameter": param, "payload": payload})
                    break
        return count

    def _test_open_redirect(self, scan_id, add_finding_fn):
        count = 0
        evil = "https://evil.com"
        params = ["redirect", "url", "next", "return", "redirect_uri", "callback", "continue"]
        for param in params:
            resp, log = self._request("GET", f"/?{param}={requests.utils.quote(evil)}", allow_redirects=False)
            if resp and resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if evil in location:
                    count += self._add(scan_id, add_finding_fn,
                        f"Open Redirect via '{param}'",
                        f"Parameter '{param}' can redirect to arbitrary URL on {self.target}/",
                        "medium", "open_redirect",
                        {"parameter": param, "redirect_target": evil, "location": location})
        return count

    def get_logs(self):
        return self._logs
