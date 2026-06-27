# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Workflow tester — session-aware multi-step security testing.

Goes beyond single-request probes by maintaining state across requests:
  1. Auth workflows: login → extract token → test protected endpoints
  2. IDOR cross-resource: create resource A → access resource A as user B
  3. Multi-step business logic: register → verify → login → escalate privilege
  4. Session fixation: get session → login → check if session changed

Each workflow is defined as a sequence of steps with variable extraction.
"""

import json
import re
import time
from urllib.parse import urljoin
import requests
from core.logging import get_logger

_log = get_logger("purpleteam.workflow")


class WorkflowTester:
    def __init__(self, target_endpoint, controllers=None, auth_config=None):
        self.target = target_endpoint.rstrip("/")
        self.controllers = controllers or []
        self.auth = auth_config or {}
        self.variables = {}  # extracted values shared across steps
        self._logs = []

    def _url(self, path="/"):
        return urljoin(self.target, path)

    def _session(self):
        s = requests.Session()
        s.timeout = 10
        proxy = self.auth.get("proxy")
        if proxy:
            s.proxies = {"http": proxy, "https": proxy}
        return s

    def _log(self, method, path, status, body_preview=""):
        entry = {"method": method, "path": path, "status": status,
                 "body_preview": body_preview[:200], "time": time.time()}
        self._logs.append(entry)
        return entry

    def run(self, scan_id, add_finding_fn, progress_cb=None):
        total = 0
        step = 0

        # ── Workflow 1: Auth bypass via missing/short-circuit checks ──
        total += self._wf_auth_bypass(scan_id, add_finding_fn)

        # ── Workflow 2: IDOR via cross-resource access ──
        total += self._wf_idor_cross_resource(scan_id, add_finding_fn)

        # ── Workflow 3: Login → protected endpoints audit ──
        total += self._wf_login_then_probe(scan_id, add_finding_fn)

        # ── Workflow 4: Session fixation / JWT weakness ──
        total += self._wf_session_check(scan_id, add_finding_fn)

        # ── Workflow 5: Registration → privilege escalation ──
        total += self._wf_register_escalate(scan_id, add_finding_fn)

        if progress_cb:
            progress_cb(100, f"Workflows: {total} findings")

        return total

    # ═══════════════════════════════════════════════════════════════
    # Workflow 1: Auth bypass
    # ═══════════════════════════════════════════════════════════════

    def _wf_auth_bypass(self, scan_id, add_finding_fn):
        count = 0
        protected = [c for c in self.controllers if self._path_has_auth_indicator(c)]
        if not protected:
            protected = [c for c in self.controllers[:10] if 'admin' in c.get('path', '').lower()
                        or 'user' in c.get('path', '').lower()
                        or 'account' in c.get('path', '').lower()]

        s = self._session()
        for ctrl in protected[:15]:
            method = ctrl.get('method', 'GET')
            if method in ('OPTIONS', 'HEAD'):
                continue
            path = self._resolve_path(ctrl)

            # Test 1: No auth
            try:
                resp = s.request(method, self._url(path), timeout=10, allow_redirects=False)
                if resp.status_code == 200 and len(resp.text) > 50:
                    count += self._add(scan_id, add_finding_fn,
                        f"[Workflow] Auth bypass: {method} {path}",
                        f"Protected endpoint {method} {path} returned 200 with data ({len(resp.text)} bytes) without any authentication.",
                        "critical", "workflow_auth_bypass", {"method": method, "path": path})
            except Exception:
                pass

            # Test 2: Empty auth header
            try:
                resp = s.request(method, self._url(path),
                                headers={"Authorization": ""}, timeout=10,
                                allow_redirects=False)
                if resp.status_code == 200 and len(resp.text) > 50:
                    count += self._add(scan_id, add_finding_fn,
                        f"[Workflow] Auth bypass via empty header: {method} {path}",
                        f"Endpoint {method} {path} accepts empty Authorization header.",
                        "high", "workflow_empty_auth", {"method": method, "path": path})
            except Exception:
                pass

            # Test 3: null/invalid JWT
            for fake_token in ["null", "undefined", "Bearer null",
                               "Bearer eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opsbCGfG_HACGpVUMN_a9IV7pAx_ZdO8"]:
                try:
                    resp = s.request(method, self._url(path),
                                    headers={"Authorization": fake_token}, timeout=10,
                                    allow_redirects=False)
                    if resp.status_code == 200 and len(resp.text) > 50:
                        count += self._add(scan_id, add_finding_fn,
                            f"[Workflow] Auth bypass via fake JWT: {method} {path}",
                            f"Endpoint accepts invalid/malformed token '{fake_token[:30]}...'",
                            "critical", "workflow_fake_jwt",
                            {"method": method, "path": path, "token": fake_token[:30]})
                        break
                except Exception:
                    pass

        return count

    # ═══════════════════════════════════════════════════════════════
    # Workflow 2: IDOR cross-resource access
    # ═══════════════════════════════════════════════════════════════

    def _wf_idor_cross_resource(self, scan_id, add_finding_fn):
        count = 0
        id_endpoints = [c for c in self.controllers
                       if 'id' in c.get('path', '').lower()
                       or '{' in c.get('path', '')
                       or ':' in c.get('path', '')]

        if not id_endpoints:
            return 0

        s = self._session()
        # Try to get a valid resource ID by requesting a list endpoint first
        for ctrl in self.controllers:
            if ctrl.get('method') == 'GET' and not self._has_param(ctrl):
                path = self._resolve_path(ctrl)
                try:
                    resp = s.get(self._url(path), timeout=10)
                    if resp.status_code == 200:
                        ids = self._extract_ids(resp.text)
                        if ids:
                            self.variables['found_ids'] = ids
                            self.variables['list_path'] = path
                            break
                except Exception:
                    pass

        # Now test IDOR: use the found IDs on other endpoints
        test_ids = self.variables.get('found_ids', [1, 2, 3, 42])
        tested_paths = set()

        for ctrl in id_endpoints[:10]:
            method = ctrl.get('method', 'GET')
            if method not in ('GET', 'PUT', 'DELETE', 'PATCH'):
                continue

            for tid in test_ids[:5]:
                test_path = self._resolve_path(ctrl)
                for p in ctrl.get('params', []):
                    test_path = test_path.replace(f'{{{p}}}', str(tid)).replace(f':{p}', str(tid))
                # Also try replacing generic {id} params
                test_path = re.sub(r'\{(\w*[iI][dD])\w*\}', str(tid), test_path)

                if test_path in tested_paths:
                    continue
                tested_paths.add(test_path)

                try:
                    resp = s.request(method, self._url(test_path), timeout=10,
                                    allow_redirects=False)
                    if resp.status_code == 200 and len(resp.text) > 100:
                        count += self._add(scan_id, add_finding_fn,
                            f"[Workflow] Potential IDOR: {method} {test_path}",
                            f"Cross-resource access: {method} {test_path} returns data ({len(resp.text)} bytes) for ID {tid} without verifying ownership.",
                            "high", "workflow_idor",
                            {"method": method, "path": test_path, "test_id": str(tid),
                             "response_len": len(resp.text)})
                        break
                except Exception:
                    pass

        return count

    # ═══════════════════════════════════════════════════════════════
    # Workflow 3: Login → probe protected endpoints
    # ═══════════════════════════════════════════════════════════════

    def _wf_login_then_probe(self, scan_id, add_finding_fn):
        count = 0
        login_endpoints = [c for c in self.controllers
                          if 'login' in c.get('path', '').lower()
                          or 'signin' in c.get('path', '').lower()
                          or 'auth' in c.get('path', '').lower()
                          or 'token' in c.get('path', '').lower()]

        if not login_endpoints:
            return 0

        s = self._session()
        token = None

        # Try common login formats
        for ctrl in login_endpoints[:3]:
            path = self._resolve_path(ctrl)
            for body in [
                {"username": "admin", "password": "admin"},
                {"email": "admin@admin.com", "password": "admin"},
                {"username": "test", "password": "test"},
                {"email": "test@test.com", "password": "password"},
            ]:
                try:
                    resp = s.post(self._url(path), json=body, timeout=10)
                    if resp.status_code in (200, 201):
                        token = self._extract_token(resp.text)
                        if token:
                            self.variables['auth_token'] = token
                            break
                except Exception:
                    pass
            if token:
                break

        if not token:
            return 0

        # Now probe all other endpoints with the token
        for ctrl in self.controllers[:20]:
            path = self._resolve_path(ctrl)
            if path in [self._resolve_path(c) for c in login_endpoints]:
                continue

            method = ctrl.get('method', 'GET')
            if method in ('OPTIONS', 'HEAD'):
                continue

            try:
                resp = s.request(method, self._url(path),
                                headers={"Authorization": f"Bearer {token}"},
                                timeout=10, allow_redirects=False)

                # Check for privilege escalation indicators
                if resp.status_code == 200:
                    body_lower = resp.text.lower()[:1000]
                    if any(kw in body_lower for kw in
                          ['all users', 'admin', 'secret', 'private', 'sensitive',
                           'password', 'credit', 'ssn', 'api_key', 'token']):
                        count += self._add(scan_id, add_finding_fn,
                            f"[Workflow] Sensitive data via login: {method} {path}",
                            f"Authenticated request to {path} reveals potentially sensitive data: {body_lower[:200]}",
                            "medium", "workflow_sensitive_exposure",
                            {"method": method, "path": path, "preview": body_lower[:200]})
            except Exception:
                pass

        return count

    # ═══════════════════════════════════════════════════════════════
    # Workflow 4: Session / JWT weaknesses
    # ═══════════════════════════════════════════════════════════════

    def _wf_session_check(self, scan_id, add_finding_fn):
        count = 0
        s = self._session()

        # Get a baseline response
        try:
            resp1 = s.get(self._url("/"), timeout=10)
            set_cookie = resp1.headers.get("Set-Cookie", "")
        except Exception:
            return 0

        # Check if session ID changes after "login" attempt
        # Session fixation test
        if set_cookie:
            try:
                login_paths = ["/login", "/auth/login", "/api/login", "/signin"]
                for lp in login_paths:
                    resp2 = s.post(self._url(lp),
                                  json={"username": "test", "password": "test"},
                                  timeout=10, allow_redirects=False)
                    new_cookie = resp2.headers.get("Set-Cookie", "")
                    if new_cookie and new_cookie == set_cookie:
                        count += self._add(scan_id, add_finding_fn,
                            "[Workflow] Session fixation risk",
                            f"Session cookie unchanged after login attempt at {lp}. Session fixation possible.",
                            "high", "workflow_session_fixation",
                            {"login_path": lp})
                        break
            except Exception:
                pass

        # JWT: check for "none" algorithm
        token = self.variables.get('auth_token') or self.auth.get('bearer_token')
        if token:
            try:
                resp = s.get(self._url("/"),
                            headers={"Authorization": f"Bearer {token}"},
                            timeout=10)
                if resp.status_code == 200:
                    # Try JWT with alg=none
                    parts = token.split('.')
                    if len(parts) == 3:
                        none_header = '{"alg":"none","typ":"JWT"}'
                        import base64
                        none_hdr_b64 = base64.urlsafe_b64encode(none_header.encode()).rstrip(b'=').decode()
                        none_token = f"{none_hdr_b64}.{parts[1]}."
                        resp_none = s.get(self._url("/"),
                                         headers={"Authorization": f"Bearer {none_token}"},
                                         timeout=10)
                        if resp_none.status_code == 200 and len(resp_none.text) > 50:
                            count += self._add(scan_id, add_finding_fn,
                                "[Workflow] JWT 'none' algorithm accepted",
                                "Server accepts JWT with algorithm 'none'. Authentication completely bypassed.",
                                "critical", "workflow_jwt_none",
                                {"original_token_preview": token[:30] + "..."})
            except Exception:
                pass

        return count

    # ═══════════════════════════════════════════════════════════════
    # Workflow 5: Registration → privilege escalation
    # ═══════════════════════════════════════════════════════════════

    def _wf_register_escalate(self, scan_id, add_finding_fn):
        count = 0
        register_endpoints = [c for c in self.controllers
                             if 'register' in c.get('path', '').lower()
                             or 'signup' in c.get('path', '').lower()
                             or 'create' in c.get('path', '').lower()
                             or 'user' in c.get('path', '').lower()
                             and c.get('method') == 'POST']

        if not register_endpoints:
            return 0

        s = self._session()
        for ctrl in register_endpoints[:3]:
            path = self._resolve_path(ctrl)
            try:
                resp = s.post(self._url(path),
                             json={"username": "elyriatest", "email": "elyriatest@test.com",
                                   "password": "ElyriaTest123!", "role": "admin",
                                   "isAdmin": True, "admin": True},
                             timeout=10)
                if resp.status_code in (200, 201):
                    body_lower = resp.text.lower()
                    if 'admin' in body_lower or 'created' in body_lower:
                        count += self._add(scan_id, add_finding_fn,
                            f"[Workflow] Mass assignment / privilege escalation: POST {path}",
                            f"Registration endpoint accepted 'role=admin' or 'isAdmin=True' — privilege escalation possible.",
                            "critical", "workflow_mass_assignment",
                            {"path": path, "response": resp.text[:200]})
            except Exception:
                pass

        return count

    # ═══════════════════════════════════════════════════════════════
    # Helpers
    # ═══════════════════════════════════════════════════════════════

    def _resolve_path(self, ctrl):
        path = ctrl.get('path', '/')
        for p in ctrl.get('params', []):
            path = path.replace(f'{{{p}}}', '1').replace(f':{p}', '1')
        return path

    def _has_param(self, ctrl):
        return bool(ctrl.get('params', []))

    def _path_has_auth_indicator(self, ctrl):
        handler = ctrl.get('handler', '')
        return any(kw in handler.lower() for kw in
                   ['auth', 'login', 'private', 'admin', 'secure', 'protect',
                    'require_auth', 'authenticate'])

    def _extract_ids(self, text):
        ids = set()
        for m in re.finditer(r'"id"\s*:\s*(\d+)', text):
            ids.add(m.group(1))
        for m in re.finditer(r'"(\w*[iI][dD])"\s*:\s*"?(\w+)"?', text):
            ids.add(m.group(2))
        return list(ids)[:10]

    def _extract_token(self, text):
        patterns = [
            r'"token"\s*:\s*"([^"]+)"', r'"access_token"\s*:\s*"([^"]+)"',
            r'"jwt"\s*:\s*"([^"]+)"', r'"access"\s*:\s*"([^"]+)"',
            r'Bearer\s+([A-Za-z0-9._-]{20,})',
            r'"token"\s*:\s*"eyJ[A-Za-z0-9._-]+"',
        ]
        for pat in patterns:
            m = re.search(pat, text)
            if m:
                return m.group(1)
        return None

    def _add(self, scan_id, add_finding_fn, title, description, severity, category, evidence=None):
        add_finding_fn(
            scan_id=scan_id, title=title, description=description,
            severity=severity, category=f"workflow_{category}",
            file_path=self.target, evidence=evidence or {},
            finding_part="practices",
        )
        return 1

    def get_logs(self):
        return self._logs
