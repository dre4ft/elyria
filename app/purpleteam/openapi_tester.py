# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
OpenAPI-driven test generation — uses API specifications to generate
precise, schema-aware security tests.

When an OpenAPI spec is provided, this module:
  1. Parses the spec to extract all endpoints with full parameter schemas
  2. Generates boundary-value tests for each parameter type
  3. Tests parameter constraints (min/max, pattern, enum)
  4. Tests type confusion (string where int expected, array where object expected)
  5. Tests missing required parameters
  6. Tests auth on endpoints marked as secured
"""

import json
import re
import time
from urllib.parse import urljoin, quote
import requests
from core.logging import get_logger

_log = get_logger("purpleteam.openapi")


class OpenAPITester:
    def __init__(self, target_endpoint, openapi_spec=None, openapi_url="", auth_config=None):
        self.target = target_endpoint.rstrip("/")
        self.auth = auth_config or {}
        self._spec = None
        self._spec_url = openapi_url
        self._logs = []

        if openapi_spec:
            self._spec = openapi_spec if isinstance(openapi_spec, dict) else json.loads(openapi_spec)
        elif openapi_url:
            self._load_spec()

    def _load_spec(self):
        try:
            resp = requests.get(self._spec_url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    # Some APIs return an array — wrap into a minimal spec dict
                    self._spec = {"paths": _paths_from_list(data), "openapi": "3.0"}
                elif isinstance(data, dict):
                    self._spec = data
                else:
                    _log.warning(f"OpenAPI spec is not dict or list: {type(data)}")
        except Exception as e:
            _log.warning(f"Failed to load OpenAPI spec: {e}")

    def _url(self, path="/"):
        return urljoin(self.target, path)

    def _session(self):
        s = requests.Session()
        s.timeout = 10
        proxy = self.auth.get("proxy")
        if proxy:
            s.proxies = {"http": proxy, "https": proxy}
        token = self.auth.get("bearer_token")
        if token:
            s.headers["Authorization"] = f"Bearer {token}"
        return s

    def run(self, scan_id, add_finding_fn, progress_cb=None):
        if not self._spec:
            return 0

        total = 0
        paths = self._extract_paths()
        if not paths:
            return 0

        total += self._test_parameter_injection(scan_id, add_finding_fn, paths)
        total += self._test_type_confusion(scan_id, add_finding_fn, paths)
        total += self._test_constraint_violation(scan_id, add_finding_fn, paths)
        total += self._test_missing_required_params(scan_id, add_finding_fn, paths)
        total += self._test_auth_on_secured_endpoints(scan_id, add_finding_fn, paths)

        return total

    def _extract_paths(self) -> list[dict]:
        """Extract all endpoints from OpenAPI spec (dict or list)."""
        spec = self._spec
        if not spec:
            return []
        if isinstance(spec, list):
            return _endpoints_from_list(spec)
        if isinstance(spec, dict):
            spec_paths = spec.get('paths', {})
            return _endpoints_from_paths(spec_paths)
        return []
        """Extract all endpoints from OpenAPI spec."""
        endpoints = []
        spec_paths = self._spec.get('paths', {})
        for path, methods in spec_paths.items():
            if not isinstance(methods, dict):
                continue
            for method, details in methods.items():
                if method.upper() in ('OPTIONS', 'HEAD'):
                    continue
                params = details.get('parameters', [])
                req_body = details.get('requestBody', {})
                security = details.get('security', [])
                endpoints.append({
                    'method': method.upper(),
                    'path': path,
                    'params': params,
                    'request_body': req_body,
                    'security': security,
                    'operation_id': details.get('operationId', ''),
                })
        return endpoints

    def _test_parameter_injection(self, scan_id, add_finding_fn, endpoints):
        """Inject malicious payloads based on parameter schema types."""
        count = 0
        payloads = {
            'string': ["' OR '1'='1", "<script>alert(1)</script>", "../../../etc/passwd",
                       "${7*7}", "{{7*7}}", "1' OR 1=1--"],
            'integer': [-1, 0, 2147483648, -999999999, None],
            'number': [-1.0, 0.0, 1e308, None],
            'boolean': ["true", "false", 1, 0, "yes"],
            'array': [[], [1], ["' OR 1=1--"]],
            'object': [{}, {"__proto__": {"admin": True}}, {"$gt": ""}],
        }

        s = self._session()
        for ep in endpoints[:30]:
            method = ep['method']
            path = self._resolve_path_params(ep)

            for param_def in ep.get('params', [])[:5]:
                param_name = param_def.get('name', '')
                param_type = param_def.get('schema', {}).get('type', 'string') if isinstance(param_def.get('schema'), dict) else 'string'
                param_in = param_def.get('in', 'query')

                for payload in payloads.get(param_type, payloads['string'])[:3]:
                    if payload is None:
                        continue
                    try:
                        if param_in == 'query':
                            resp = s.request(method, self._url(path),
                                           params={param_name: payload}, timeout=10)
                        elif param_in == 'path':
                            test_path = path.replace(f'{{{param_name}}}', str(payload))
                            resp = s.request(method, self._url(test_path), timeout=10)
                        elif param_in == 'header':
                            resp = s.request(method, self._url(path),
                                           headers={param_name: str(payload)}, timeout=10)
                        else:
                            continue

                        # Check for error leakage or unexpected responses
                        if resp.status_code == 500:
                            body = resp.text[:300]
                            count += self._add(scan_id, add_finding_fn,
                                f"[OpenAPI] Injection: {method} {path} param={param_name}",
                                f"Parameter '{param_name}' ({param_type}) with payload '{str(payload)[:50]}' caused 500 error. Body: {body}",
                                "high", "openapi_injection",
                                {"method": method, "path": path, "param": param_name,
                                 "type": param_type, "payload": str(payload)[:100]})
                            break
                    except Exception:
                        pass

        return count

    def _test_type_confusion(self, scan_id, add_finding_fn, endpoints):
        """Test what happens when wrong types are sent."""
        count = 0
        s = self._session()

        for ep in endpoints[:20]:
            method = ep['method']
            if method not in ('POST', 'PUT', 'PATCH'):
                continue

            req_body = ep.get('request_body', {})
            if not req_body:
                continue

            content = req_body.get('content', {})
            json_schema = content.get('application/json', {}).get('schema', {})
            if not json_schema:
                continue

            props = json_schema.get('properties', {})
            if not props:
                continue

            path = self._resolve_path_params(ep)

            # Try sending string where number expected, array where object, etc.
            for prop_name, prop_schema in props.items():
                prop_type = prop_schema.get('type', 'string')
                confusion = {
                    'integer': ["not_a_number", [1, 2, 3], {"key": "val"}, True],
                    'number': ["NaN", "Infinity", [1, 2], {"$gt": 1}, True],
                    'string': [999999, [1, 2, 3], {"nested": True}, None],
                    'boolean': ["maybe", 42, [True, False], {"admin": True}],
                    'array': ["not_array", 123, {"key": "val"}, True],
                    'object': ["not_object", 123, [1, 2, 3], True],
                }.get(prop_type, ["__proto__", 999, [1], {"$gt": ""}])

                for confused_val in confusion[:2]:
                    body = {prop_name: confused_val}
                    for other in list(props.keys())[:2]:
                        if other != prop_name:
                            body[other] = _dummy_for(props.get(other, {}).get('type', 'string'))

                    try:
                        resp = s.request(method, self._url(path), json=body, timeout=10)
                        if resp.status_code == 500:
                            count += self._add(scan_id, add_finding_fn,
                                f"[OpenAPI] Type confusion: {method} {path}.{prop_name}",
                                f"Property '{prop_name}' expects {prop_type} but accepts {type(confused_val).__name__}. 500 error suggests no validation.",
                                "medium", "openapi_type_confusion",
                                {"method": method, "path": path, "property": prop_name,
                                 "expected": prop_type, "sent": str(confused_val)[:50]})
                            break
                    except Exception:
                        pass

        return count

    def _test_constraint_violation(self, scan_id, add_finding_fn, endpoints):
        """Test min/max length, pattern, enum constraints."""
        count = 0
        s = self._session()

        constraint_tests = {
            'minLength': lambda v: 'x' * max(0, v - 1),
            'maxLength': lambda v: 'x' * (v + 10),
            'minimum': lambda v: v - 1,
            'maximum': lambda v: v + 1,
            'pattern': lambda v: '!!!INVALID_PATTERN_VALUE!!!',
        }

        for ep in endpoints[:15]:
            method = ep['method']
            if method not in ('POST', 'PUT', 'PATCH'):
                continue

            req_body = ep.get('request_body', {})
            content = req_body.get('content', {})
            json_schema = content.get('application/json', {}).get('schema', {})
            props = json_schema.get('properties', {})

            for param_def in ep.get('params', [])[:5] + [
                {'name': k, 'in': 'body', **v} for k, v in props.items()
            ]:
                schema = param_def if isinstance(param_def, dict) else {}
                param_name = schema.get('name', '')
                param_in = schema.get('in', 'query')

                for constraint, gen in constraint_tests.items():
                    value = schema.get(constraint)
                    if value is not None and isinstance(value, (int, float)):
                        try:
                            path = self._resolve_path_params(ep)
                            bad_val = gen(value)
                            resp = s.request(method, self._url(path),
                                           params={param_name: bad_val} if param_in == 'query' else {},
                                           json={param_name: bad_val} if param_in == 'body' else {},
                                           timeout=10)
                            if resp.status_code == 500:
                                count += self._add(scan_id, add_finding_fn,
                                    f"[OpenAPI] Constraint violation: {method} {path} {param_name}",
                                    f"Parameter '{param_name}' ({constraint}={value}) not enforced. Invalid value '{bad_val}' caused 500.",
                                    "medium", "openapi_constraint",
                                    {"method": method, "path": path, "param": param_name,
                                     "constraint": constraint, "expected": value, "sent": bad_val})
                                break
                        except Exception:
                            pass

        return count

    def _test_missing_required_params(self, scan_id, add_finding_fn, endpoints):
        """Omit required parameters and check for proper error handling."""
        count = 0
        s = self._session()

        for ep in endpoints[:20]:
            method = ep['method']
            path = self._resolve_path_params(ep)

            # Find required params
            required_params = [p for p in ep.get('params', [])
                              if p.get('required', False)]

            if required_params and method == 'GET':
                try:
                    resp = s.get(self._url(path), timeout=10)
                    if resp.status_code == 200:
                        count += self._add(scan_id, add_finding_fn,
                            f"[OpenAPI] Missing required params: {method} {path}",
                            f"Required parameters ({', '.join(p['name'] for p in required_params)}) omitted but endpoint returned 200.",
                            "low", "openapi_missing_required",
                            {"method": method, "path": path, "required": [p['name'] for p in required_params]})
                except Exception:
                    pass

            # For POST/PUT, omit required body fields
            req_body = ep.get('request_body', {})
            content = req_body.get('content', {})
            json_schema = content.get('application/json', {}).get('schema', {})
            required_fields = json_schema.get('required', [])
            if required_fields and method in ('POST', 'PUT', 'PATCH'):
                try:
                    resp = s.request(method, self._url(path), json={}, timeout=10)
                    if resp.status_code in (200, 201):
                        count += self._add(scan_id, add_finding_fn,
                            f"[OpenAPI] Missing required body: {method} {path}",
                            f"Required fields {required_fields} were omitted but server accepted the request ({resp.status_code}).",
                            "high", "openapi_missing_body",
                            {"method": method, "path": path, "required": required_fields})
                except Exception:
                    pass

        return count

    def _test_auth_on_secured_endpoints(self, scan_id, add_finding_fn, endpoints):
        """Verify that endpoints marked with security actually require auth."""
        count = 0
        secured = [ep for ep in endpoints if ep.get('security') and len(ep['security']) > 0]
        if not secured:
            return 0

        unauth = requests.Session()
        unauth.timeout = 10

        for ep in secured[:15]:
            method = ep['method']
            path = self._resolve_path_params(ep)
            try:
                resp = unauth.request(method, self._url(path), timeout=10, allow_redirects=False)
                if resp.status_code == 200 and len(resp.text) > 50:
                    count += self._add(scan_id, add_finding_fn,
                        f"[OpenAPI] Missing auth: {method} {path}",
                        f"Endpoint marked with security={ep['security']} but returns 200 without auth.",
                        "critical", "openapi_missing_auth",
                        {"method": method, "path": path, "security": ep['security']})
            except Exception:
                pass

        return count

    def _resolve_path_params(self, ep):
        path = ep.get('path', '/')
        for p in ep.get('params', []):
            pname = p.get('name', '')
            ptype = (p.get('schema', {}) or {}).get('type', 'string') if isinstance(p.get('schema'), dict) else 'string'
            dummy = _dummy_for(ptype)
            path = path.replace(f'{{{pname}}}', str(dummy))
        return path

    def _add(self, scan_id, add_finding_fn, title, description, severity, category, evidence=None):
        add_finding_fn(
            scan_id=scan_id, title=title, description=description,
            severity=severity, category=f"openapi_{category}",
            file_path=self.target, evidence=evidence or {},
            finding_part="practices",
        )
        return 1

    def get_logs(self):
        return self._logs


def _paths_from_list(data: list) -> dict:
    """Convert an OpenAPI endpoint array into a minimal paths dict."""
    paths = {}
    for item in data:
        if isinstance(item, dict):
            path = item.get('path', item.get('url', ''))
            method = item.get('method', 'GET').lower()
            if path:
                paths.setdefault(path, {})[method] = item
    return paths


def _endpoints_from_list(data: list) -> list[dict]:
    """Extract endpoints from an array format."""
    endpoints = []
    for item in data:
        if isinstance(item, dict):
            path = item.get('path', item.get('url', ''))
            method = item.get('method', 'GET')
            endpoints.append({
                'method': method.upper(),
                'path': path,
                'params': item.get('parameters', item.get('params', [])),
                'request_body': item.get('requestBody', item.get('body', {})),
                'security': item.get('security', []),
                'operation_id': item.get('operationId', ''),
            })
    return endpoints


def _endpoints_from_paths(paths: dict) -> list[dict]:
    """Extract endpoints from standard OpenAPI paths dict."""
    endpoints = []
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, details in methods.items():
            if method.upper() in ('OPTIONS', 'HEAD', 'PARAMETERS', 'SERVERS'):
                continue
            params = details.get('parameters', [])
            req_body = details.get('requestBody', {})
            security = details.get('security', [])
            endpoints.append({
                'method': method.upper(),
                'path': path,
                'params': params,
                'request_body': req_body,
                'security': security,
                'operation_id': details.get('operationId', ''),
            })
    return endpoints


def _dummy_for(ptype):
    return {'string': 'test', 'integer': 1, 'number': 1.0,
            'boolean': True, 'array': [], 'object': {}}.get(ptype, 'test')
