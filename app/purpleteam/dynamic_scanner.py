# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Dynamic IAST Scanner -- controller-driven interactive testing.

Uses detected REST controllers + call graph to perform targeted testing:
  1. Endpoint probing -- test every discovered endpoint
  2. Auth bypass -- check if endpoints are accessible without auth
  3. BOLA/IDOR -- swap resource IDs between users
  4. Injection -- targeted payloads based on param names and types
  5. Static validation -- verify static findings on the live target
  6. Sink exploitation -- use call graph sinks to craft precise attack vectors
"""

import json
import re
import time
from urllib.parse import urljoin, quote
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
    def __init__(self, target_endpoint, static_findings=None, auth_config=None,
                 controllers=None, call_graph=None):
        self.target = target_endpoint.rstrip("/")
        self.auth = auth_config or {}
        self.static_findings = static_findings or []
        self.controllers = controllers or []
        self.call_graph = call_graph or {}
        self.session = _make_session()
        self._apply_auth()
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
        total = 0
        has_controllers = bool(self.controllers)
        step = 0

        if progress_cb:
            progress_cb(0, "Dynamic IAST: probing endpoints...")

        # ── Phase 1: Controller-driven endpoint probing ──
        if has_controllers:
            total += self._probe_controllers(scan_id, add_finding_fn, progress_cb, step_base=0, step_range=40)
        else:
            # Fallback: baseline security tests
            total += self._run_baseline_tests(scan_id, add_finding_fn)

        # ── Phase 2: Auth bypass testing on controller endpoints ──
        if has_controllers:
            total += self._test_auth_bypass(scan_id, add_finding_fn, progress_cb, step_base=40, step_range=15)

        # ── Phase 3: BOLA/IDOR testing ──
        if has_controllers:
            total += self._test_bola(scan_id, add_finding_fn, progress_cb, step_base=55, step_range=15)

        # ── Phase 4: Validate static findings against target ──
        if self.static_findings:
            if progress_cb:
                progress_cb(70, "Validating static findings...")
            total += self._validate_static_findings(scan_id, add_finding_fn)

        # ── Phase 5: Sink-driven injection testing ──
        sinks = self.call_graph.get('sinks', [])
        if sinks:
            if progress_cb:
                progress_cb(75, "Testing sink-driven injections...")
            total += self._test_sinks(scan_id, add_finding_fn, sinks)

        # ── Phase 6: Response diffing ──
        if has_controllers:
            if progress_cb:
                progress_cb(85, "Response diffing...")
            total += self._test_response_diffing(scan_id, add_finding_fn)

        # ── Phase 7: Race condition testing ──
        if has_controllers:
            if progress_cb:
                progress_cb(92, "Race condition testing...")
            total += self._test_race_conditions(scan_id, add_finding_fn)

        if progress_cb:
            progress_cb(100, f"Dynamic IAST: {total} findings")
        return total

    # ═══════════════════════════════════════════════════════════════
    # Phase 1: Controller-driven probing
    # ═══════════════════════════════════════════════════════════════

    def _probe_controllers(self, scan_id, add_finding_fn, progress_cb, step_base, step_range):
        import hashlib
        controllers = self.controllers[:50]  # cap
        count = 0
        seen_hashes = {}  # body_hash → count, for SPA dedup
        for i, ctrl in enumerate(controllers):
            method = ctrl.get('method', 'GET')
            path = ctrl.get('path', '/')
            params = ctrl.get('params', [])

            # Replace path params with test values
            test_path = path
            for p in params:
                test_path = test_path.replace(f'{{{p}}}', '1').replace(f':{p}', '1')

            # Skip OPTIONS/HEAD/PATCH for initial probing
            if method in ('OPTIONS', 'HEAD', 'PATCH'):
                continue

            resp, _ = self._request(method, test_path, allow_redirects=False)
            if resp is None:
                continue

            pct = step_base + int(i / max(1, len(controllers)) * step_range)
            if progress_cb and i % 5 == 0:
                progress_cb(pct, f"Probing: {method} {test_path} [{resp.status_code}]")

            handler = ctrl.get('handler', '')
            file = ctrl.get('file', '')

            # 401/403 → endpoint exists, auth protected (expected)
            # 200 → endpoint accessible
            # 404 → endpoint may not exist or path is wrong
            # 500 → potential vulnerability (error triggered)
            if resp.status_code == 200:
                # Dedup: if multiple endpoints return identical HTML (SPA), report once
                body_hash = hashlib.md5(resp.text[:500].encode()).hexdigest()
                seen_hashes[body_hash] = seen_hashes.get(body_hash, 0) + 1
                if seen_hashes[body_hash] > 3:
                    continue  # skip -- same SPA page served for many routes

                # Check if it should require auth
                auth_gates = self.call_graph.get('auth_gates', [])
                ctrl_auth = next((g for g in auth_gates
                                 if g.get('controller', {}).get('handler') == handler), None)
                if ctrl_auth and ctrl_auth.get('type') != 'none':
                    count += self._add(scan_id, add_finding_fn,
                        f"Auth bypass: {method} {path}",
                        f"Controller endpoint {method} {path} (handler: {handler}) returned 200 without authentication. Auth gate: {ctrl_auth.get('type')}",
                        "high", "auth_bypass",
                        {"method": method, "path": path, "handler": handler, "file": file})

            if resp.status_code == 500:
                body_snippet = resp.text[:200]
                count += self._add(scan_id, add_finding_fn,
                    f"Server error on {method} {path}",
                    f"Endpoint {method} {path} triggered HTTP 500. Response: {body_snippet}",
                    "medium", "error_trigger",
                    {"method": method, "path": path, "response": body_snippet})

            # Check for verbose error info in 4xx/5xx responses
            if resp.status_code >= 400:
                body_lower = resp.text.lower()[:500]
                error_kw = ['traceback', 'exception', 'syntax error', 'stack trace',
                           'at line', 'in /', 'sql', 'postgresql', 'mysql']
                matched = [kw for kw in error_kw if kw in body_lower]
                if matched:
                    count += self._add(scan_id, add_finding_fn,
                        f"Error disclosure on {method} {path}",
                        f"Response for {method} {path} reveals: {', '.join(matched)}",
                        "medium", "error_disclosure",
                        {"method": method, "path": path, "indicators": matched})

        return count

    # ═══════════════════════════════════════════════════════════════
    # Phase 2: Auth bypass testing
    # ═══════════════════════════════════════════════════════════════

    def _test_auth_bypass(self, scan_id, add_finding_fn, progress_cb, step_base, step_range):
        count = 0
        # Create an unauthenticated session
        unauth = _make_session()
        controllers = self.controllers[:30]

        for i, ctrl in enumerate(controllers):
            method = ctrl.get('method', 'GET')
            path = ctrl.get('path', '/')
            for p in ctrl.get('params', []):
                path = path.replace(f'{{{p}}}', '1').replace(f':{p}', '1')

            if method in ('OPTIONS', 'HEAD'):
                continue

            url = self._url(path)
            try:
                resp = unauth.request(method, url, timeout=10, allow_redirects=False)
                if resp.status_code == 200:
                    handler = ctrl.get('handler', '')
                    count += self._add(scan_id, add_finding_fn,
                        f"[Auth Bypass] {method} {path} accessible without auth",
                        f"Controller {handler} at {method} {path} served 200 OK without any authentication headers.",
                        "high", "auth_bypass",
                        {"method": method, "path": path, "handler": handler})
                elif resp.status_code == 401:
                    # Check for auth bypass via header manipulation
                    for bypass_header, bypass_val in [
                        ("X-Forwarded-For", "127.0.0.1"),
                        ("X-Real-IP", "127.0.0.1"),
                        ("X-Forwarded-Host", "127.0.0.1"),
                        ("X-Original-URL", path),
                        ("X-Rewrite-URL", path),
                        ("X-HTTP-Method-Override", "GET"),
                    ]:
                        try:
                            r2 = unauth.request(method, url, timeout=10,
                                               headers={bypass_header: bypass_val},
                                               allow_redirects=False)
                            if r2.status_code == 200:
                                count += self._add(scan_id, add_finding_fn,
                                    f"[Auth Bypass] Header injection: {bypass_header}",
                                    f"{method} {path} returns 200 when injecting header {bypass_header}: {bypass_val}",
                                    "critical", "auth_bypass_header",
                                    {"method": method, "path": path, "header": bypass_header})
                                break
                        except Exception:
                            pass
            except Exception:
                pass

        return count

    # ═══════════════════════════════════════════════════════════════
    # Phase 3: BOLA/IDOR testing
    # ═══════════════════════════════════════════════════════════════

    def _test_bola(self, scan_id, add_finding_fn, progress_cb, step_base, step_range):
        count = 0
        # Find endpoints with resource IDs in path
        id_patterns = [r'/\{?id\}?', r'/\{?(\w+_id)\}?', r'/\{?(\w+Id)\}?']
        id_endpoints = []
        for ctrl in self.controllers:
            path = ctrl.get('path', '')
            if any(re.search(p, path) for p in id_patterns):
                id_endpoints.append(ctrl)

        if not id_endpoints:
            return 0

        # First, request with the legitimate ID to get a baseline
        for i, ctrl in enumerate(id_endpoints[:15]):
            method = ctrl.get('method', 'GET')
            if method not in ('GET', 'PUT', 'PATCH', 'DELETE'):
                continue
            path = ctrl.get('path', '/')

            # Replace ID params: first with legit value, then with another's
            legit_path = path
            for p in ctrl.get('params', []):
                legit_path = legit_path.replace(f'{{{p}}}', '1').replace(f':{p}', '1')

            # Test with different IDs that might belong to other resources
            for test_id in ['0', '-1', '999999', 'admin', 'null']:
                test_path = legit_path
                for p in ctrl.get('params', []):
                    test_path = test_path.replace(f'{{{p}}}', test_id).replace(f':{p}', test_id)

                if test_path == legit_path:
                    continue

                resp, _ = self._request(method, test_path, allow_redirects=False)
                if resp is None:
                    continue

                # If we get 200 for a different ID, potential IDOR
                if resp.status_code == 200 and method == 'GET':
                    body_len = len(resp.text)
                    if body_len > 50:  # got real data
                        count += self._add(scan_id, add_finding_fn,
                            f"[IDOR] {method} {path} with ID={test_id} returns data",
                            f"Resource {method} {path} returns 200 with body ({body_len} bytes) for foreign ID '{test_id}'. Possible IDOR vulnerability.",
                            "high", "bola_idor",
                            {"method": method, "path": path, "test_id": test_id,
                             "handler": ctrl.get('handler', ''),
                             "response_len": body_len})
                        break

        return count

    # ═══════════════════════════════════════════════════════════════
    # Phase 4: Validate static findings
    # ═══════════════════════════════════════════════════════════════

    def _validate_static_findings(self, scan_id, add_finding_fn):
        import hashlib
        count = 0
        endpoints = set()
        seen_hashes = set()

        for f in self.static_findings:
            file_path = f.get("file_path", "")
            title = f.get("title", "")
            evidence = f.get("evidence", {})
            if isinstance(evidence, str):
                try:
                    evidence = json.loads(evidence)
                except Exception:
                    evidence = {}

            # Extract paths from findings
            for text in [file_path, title, json.dumps(evidence)]:
                for m in re.finditer(r'(?:/[a-zA-Z0-9._~:/?#\[\]@!$&\'()*+,;=%-]+){2,}', text):
                    eid = m.group(0)[:100]
                    if eid.startswith("/") and len(eid) > 2:
                        endpoints.add(eid)

            # Also try to extract paths from controller patterns in the finding
            if 'controller' in title.lower() or 'handler' in title.lower():
                for m in re.finditer(r'(?:GET|POST|PUT|DELETE|PATCH)\s+(/\S+)', title, re.IGNORECASE):
                    endpoints.add(m.group(1))

        for path in list(endpoints)[:20]:
            resp, _ = self._request("GET", path)
            if resp is None:
                continue

            if resp.status_code == 200:
                # Dedup SPA pages
                bh = hashlib.md5(resp.text[:500].encode()).hexdigest()
                if bh in seen_hashes:
                    continue
                seen_hashes.add(bh)
                count += self._add(scan_id, add_finding_fn,
                    f"Static finding validated: GET {path} accessible",
                    f"Endpoint {path} from static analysis returned 200 OK.",
                    "medium", "static_validated",
                    {"path": path, "status": resp.status_code})

            # Check for error disclosure matching CWE findings
            if resp.status_code >= 400:
                body_lower = resp.text[:500].lower()
                error_kw = ['traceback', 'exception', 'sql', 'syntax error',
                           'stack trace', 'debug', 'internal server error']
                if any(kw in body_lower for kw in error_kw):
                    count += self._add(scan_id, add_finding_fn,
                        f"Confirmed error disclosure on {path}",
                        f"Endpoint {path} confirmed to leak error information.",
                        "medium", "static_confirmed_error",
                        {"path": path})

        return count

    # ═══════════════════════════════════════════════════════════════
    # Phase 5: Sink-driven injection testing
    # ═══════════════════════════════════════════════════════════════

    def _test_sinks(self, scan_id, add_finding_fn, sinks):
        count = 0
        test_map = {
            'sql_injection': self._test_sqli_on_endpoints,
            'command_injection': self._test_cmdi_on_endpoints,
            'path_traversal': self._test_path_traversal_on_endpoints,
            'deserialization': self._test_deser_on_endpoints,
            'open_redirect': self._test_redirect_on_endpoints,
            'code_injection': self._test_code_inj_on_endpoints,
        }

        tested = set()
        for sink_type, test_fn in test_map.items():
            if any(s['type'] == sink_type for s in sinks):
                if sink_type not in tested:
                    tested.add(sink_type)
                    count += test_fn(scan_id, add_finding_fn)

        return count

    def _test_sqli_on_endpoints(self, scan_id, add_finding_fn):
        count = 0
        payloads = ["' OR '1'='1", "'; SELECT 1--", "1' AND '1'='1"]
        error_kw = ['sql', 'mysql', 'sqlite', 'postgresql', 'ora-', 'syntax error',
                    'odbc', 'driver', 'db2', 'sql server']

        for ctrl in self.controllers[:20]:
            method = ctrl.get('method', 'GET')
            if method not in ('GET', 'POST'):
                continue
            path = ctrl.get('path', '/')

            for p in ctrl.get('params', []):
                path = path.replace(f'{{{p}}}', '1').replace(f':{p}', '1')

            for payload in payloads:
                test_path = f"{path}?id={quote(payload)}"
                resp, _ = self._request(method, test_path)
                if resp and any(kw in resp.text[:500].lower() for kw in error_kw):
                    count += self._add(scan_id, add_finding_fn,
                        f"[SQLi] Potential injection on {method} {path}",
                        f"SQL error keywords detected when injecting '{payload}' on {path}",
                        "critical", "sqli_targeted",
                        {"method": method, "path": path, "payload": payload})
                    break
        return count

    def _test_cmdi_on_endpoints(self, scan_id, add_finding_fn):
        count = 0
        payloads = [";id", "|id", "`id`", "$(id)"]
        error_kw = ['uid=', 'gid=', 'groups=']

        for ctrl in self.controllers[:15]:
            method = ctrl.get('method', 'GET')
            path = ctrl.get('path', '/')
            for p in ctrl.get('params', []):
                path = path.replace(f'{{{p}}}', '1').replace(f':{p}', '1')

            for payload in payloads:
                test_path = f"{path}?cmd={quote(payload)}"
                resp, _ = self._request(method, test_path)
                if resp and any(kw in resp.text[:500].lower() for kw in error_kw):
                    count += self._add(scan_id, add_finding_fn,
                        f"[CMDi] Potential injection on {method} {path}",
                        f"Command execution output detected on {path}",
                        "critical", "cmdi_targeted",
                        {"method": method, "path": path, "payload": payload})
                    break
        return count

    def _test_path_traversal_on_endpoints(self, scan_id, add_finding_fn):
        count = 0
        payloads = ["../../../etc/passwd", "....//....//....//etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"]
        indicators = ['root:', 'daemon:', 'nobody:']

        for ctrl in self.controllers[:15]:
            method = ctrl.get('method', 'GET')
            path = ctrl.get('path', '/')
            for p in ctrl.get('params', []):
                path = path.replace(f'{{{p}}}', '1').replace(f':{p}', '1')

            for payload in payloads:
                test_path = f"{path}?file={quote(payload)}"
                resp, _ = self._request(method, test_path)
                if resp and any(ind in resp.text[:500].lower() for ind in indicators):
                    count += self._add(scan_id, add_finding_fn,
                        f"[Path Traversal] {method} {path}",
                        f"System file content retrieved via {path}",
                        "critical", "path_traversal_targeted",
                        {"method": method, "path": path, "payload": payload})
                    break
        return count

    def _test_deser_on_endpoints(self, scan_id, add_finding_fn):
        return 0  # Deserialization testing requires more context -- handled by AI phase

    def _test_redirect_on_endpoints(self, scan_id, add_finding_fn):
        count = 0
        evil = "https://evil.com"
        redirect_params = ['redirect', 'url', 'next', 'return', 'redirect_uri', 'callback']

        for ctrl in self.controllers[:20]:
            path = ctrl.get('path', '/')
            for param in redirect_params:
                test_path = f"{path}?{param}={quote(evil)}"
                resp, _ = self._request('GET', test_path, allow_redirects=False)
                if resp and resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get('Location', '')
                    if evil in location:
                        count += self._add(scan_id, add_finding_fn,
                            f"[Open Redirect] Via {param} on {path}",
                            f"Parameter {param} redirects to arbitrary URL on {path}",
                            "medium", "open_redirect_targeted",
                            {"path": path, "param": param, "location": location})
        return count

    def _test_code_inj_on_endpoints(self, scan_id, add_finding_fn):
        return 0  # Code injection testing requires more context -- handled by AI phase

    # ═══════════════════════════════════════════════════════════════
    # Fallback: baseline tests (when no controllers detected)
    # ═══════════════════════════════════════════════════════════════

    def _run_baseline_tests(self, scan_id, add_finding_fn):
        count = 0
        tests = [self._test_security_headers, self._test_cors,
                 self._test_error_disclosure, self._test_sensitive_paths]
        for test_fn in tests:
            try:
                count += test_fn(scan_id, add_finding_fn)
            except Exception as e:
                _log.warning(f"Baseline test {test_fn.__name__} failed: {e}")
        return count

    def _test_security_headers(self, scan_id, add_finding_fn):
        count = 0
        resp, _ = self._request("GET", "/")
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
                    f"Security header '{hdr}' missing from {self.target}",
                    sev, "security_headers", {"missing_header": hdr})
        return count

    def _test_cors(self, scan_id, add_finding_fn):
        count = 0
        resp, _ = self._request("OPTIONS", "/",
            headers={"Origin": "https://evil.com", "Access-Control-Request-Method": "GET"})
        if resp is None:
            return count
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*" or acao == "https://evil.com":
            count += self._add(scan_id, add_finding_fn, "Overly permissive CORS",
                f"CORS allows '{acao}'. Target: {self.target}",
                "high" if acao == "*" else "medium", "cors",
                {"origin_sent": "https://evil.com", "allowed_origin": acao})
        return count

    def _test_error_disclosure(self, scan_id, add_finding_fn):
        count = 0
        resp, _ = self._request("GET", "/__elyria_test_nonexistent__")
        if resp is None:
            return count
        body = resp.text.lower()
        error_kw = ['traceback', 'stack trace', 'exception', 'sql error',
                   'debug mode', 'at line', 'in file']
        if any(kw in body for kw in error_kw):
            count += self._add(scan_id, add_finding_fn, "Verbose error disclosure",
                "Non-existent path triggers verbose error details.",
                "medium", "error_disclosure",
                {"path": "/__elyria_test_nonexistent__"})
        return count

    def _test_sensitive_paths(self, scan_id, add_finding_fn):
        count = 0
        sensitive = ["/admin", "/api/admin", "/actuator", "/actuator/health",
                     "/swagger-ui.html", "/api-docs", "/graphql",
                     "/.env", "/config", "/debug"]
        for path in sensitive:
            resp, _ = self._request("GET", path)
            if resp and resp.status_code == 200:
                count += self._add(scan_id, add_finding_fn,
                    f"Sensitive path accessible: {path}",
                    f"Path {path} returned 200 without auth on {self.target}",
                    "high", "sensitive_path", {"path": path})
        return count

    # ═══════════════════════════════════════════════════════════════
    # Helpers
    # ═══════════════════════════════════════════════════════════════

    def _add(self, scan_id, add_finding_fn, title, description, severity, category, evidence=None):
        add_finding_fn(
            scan_id=scan_id, title=title, description=description,
            severity=severity, category=f"dynamic_{category}",
            file_path=self.target, evidence=evidence or {},
            finding_part="practices",
        )
        return 1

    # ═══════════════════════════════════════════════════════════════
    # Phase 6: Response diffing
    # ═══════════════════════════════════════════════════════════════

    def _test_response_diffing(self, scan_id, add_finding_fn):
        """Compare normal vs attack responses to detect subtle anomalies."""
        count = 0
        import hashlib

        for ctrl in self.controllers[:10]:
            method = ctrl.get('method', 'GET')
            if method not in ('GET', 'POST'):
                continue
            path = ctrl.get('path', '/')
            for p in ctrl.get('params', []):
                path = path.replace(f'{{{p}}}', '1').replace(f':{p}', '1')

            # Baseline request (normal)
            baseline, _ = self._request(method, path)
            if baseline is None:
                continue

            baseline_hash = hashlib.md5(baseline.text.encode()).hexdigest()
            baseline_len = len(baseline.text)
            baseline_status = baseline.status_code

            # Attack request with SQLi payload
            attack_paths = [
                f"{path}?id='OR'1'='1",
                f"{path}?id=1%27%20OR%20%271%27%3D%271",
            ]
            if method == 'POST':
                attack_paths = [path]

            for attack_path in attack_paths[:2]:
                attack_kwargs = {}
                if method == 'POST':
                    attack_kwargs = {'json': {"id": "' OR '1'='1"}}
                else:
                    attack_kwargs = {}

                attack, _ = self._request(method, attack_path, **attack_kwargs)
                if attack is None:
                    continue

                attack_hash = hashlib.md5(attack.text.encode()).hexdigest()
                attack_len = len(attack.text)

                # Diff analysis
                if (attack_status := attack.status_code) != baseline_status:
                    # Status changed -- potential SQL error or different response
                    if attack_status == 500:
                        count += self._add(scan_id, add_finding_fn,
                            f"[Diff] Status change on {method} {path}: {baseline_status} → {attack_status}",
                            f"Attack payload on {method} {path} caused HTTP {attack_status} (was {baseline_status}). Possible injection vulnerability.",
                            "high", "diff_status_change",
                            {"method": method, "path": path, "baseline_status": baseline_status,
                             "attack_status": attack_status})

                elif attack_len != baseline_len and attack_hash != baseline_hash:
                    # Same status but different content -- might indicate SQL error injection
                    len_diff = abs(attack_len - baseline_len)
                    if len_diff > 100:
                        body_keywords = ['sql', 'error', 'exception', 'syntax', 'mysql', 'sqlite',
                                        'postgresql', 'odbc', 'ora-', 'warning']
                        attack_body = attack.text.lower()[:1000]
                        matched = [kw for kw in body_keywords if kw in attack_body]
                        if matched:
                            count += self._add(scan_id, add_finding_fn,
                                f"[Diff] Anomalous response on {method} {path}",
                                f"Response differs by {len_diff} bytes and contains: {', '.join(matched)}. Possible data leak via injection.",
                                "medium", "diff_anomaly",
                                {"method": method, "path": path, "len_diff": len_diff,
                                 "indicators": matched})

        return count

    # ═══════════════════════════════════════════════════════════════
    # Phase 7: Race condition / TOCTOU testing
    # ═══════════════════════════════════════════════════════════════

    def _test_race_conditions(self, scan_id, add_finding_fn):
        """Send concurrent requests to detect race conditions."""
        import concurrent.futures
        count = 0

        # Find endpoints that modify state (POST, PUT, PATCH, DELETE)
        stateful = [c for c in self.controllers
                   if c.get('method') in ('POST', 'PUT', 'PATCH', 'DELETE')][:5]

        if not stateful:
            return 0

        def send_race(path, method, body, idx):
            try:
                s = self._session()
                s.timeout = 5
                if method in ('POST', 'PUT', 'PATCH'):
                    return s.request(method, self._url(path), json=body, timeout=5)
                else:
                    return s.request(method, self._url(path), timeout=5)
            except Exception:
                return None

        for ctrl in stateful:
            path = ctrl.get('path', '/')
            for p in ctrl.get('params', []):
                path = path.replace(f'{{{p}}}', '1').replace(f':{p}', '1')
            method = ctrl.get('method', 'POST')

            # Send 5 concurrent identical requests
            body = {"value": "racetest", "amount": 1} if method != 'DELETE' else {}
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(send_race, path, method, body, i) for i in range(5)]
                results = []
                for f in concurrent.futures.as_completed(futures):
                    try:
                        results.append(f.result())
                    except Exception:
                        pass

            # Analyze results
            statuses = [r.status_code for r in results if r is not None]
            bodies = [r.text[:100] for r in results if r is not None]

            if len(statuses) >= 3:
                # If all succeeded, potential race condition (e.g., coupon code, rate limit)
                successes = sum(1 for s in statuses if s in (200, 201))
                if successes >= 3 and method in ('POST', 'PUT'):
                    # Check if responses are identical (should all return unique IDs if idempotent)
                    unique_bodies = len(set(bodies))
                    if unique_bodies == 1 and len(bodies) >= 3:
                        count += self._add(scan_id, add_finding_fn,
                            f"[Race] Potential race condition: {method} {path}",
                            f"All 5 concurrent {method} requests to {path} succeeded with identical responses. Possible race condition (duplicate resource creation, coupon reuse, etc.).",
                            "high", "race_condition",
                            {"method": method, "path": path, "concurrent": 5,
                             "successes": successes, "unique_responses": unique_bodies})
                    elif unique_bodies >= 4:
                        count += self._add(scan_id, add_finding_fn,
                            f"[Race] Rate limit bypass: {method} {path}",
                            f"All 5 concurrent requests succeeded without rate limiting. Possible brute-force or DoS vector.",
                            "medium", "race_rate_limit",
                            {"method": method, "path": path, "successes": successes})

        return count

    def get_logs(self):
        return self._logs
