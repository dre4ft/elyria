# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Intelligent attack payload generation based on schema types and parameter names.
Used by the deterministic scanner to craft targeted, context-aware attack probes.
"""

import json
import re


# ═══════════════════════════════════════════════════════════════
# Parameter name → attack vectors
# ═══════════════════════════════════════════════════════════════

_ID_PARAM_NAMES = {
    "id", "userid", "user_id", "accountid", "account_id", "customerid", "customer_id",
    "orderid", "order_id", "productid", "product_id", "uuid", "guid", "key",
    "token", "sessionid", "session_id", "profileid", "profile_id",
}

_AUTH_PARAM_NAMES = {
    "token", "accesstoken", "access_token", "apikey", "api_key", "secret",
    "password", "passwd", "pwd", "authorization", "auth", "jwt",
}

_PRICE_PARAM_NAMES = {
    "price", "amount", "total", "subtotal", "cost", "value", "fee", "charge",
    "balance", "credit", "debit", "payment", "discount", "coupon", "tax",
}

_QUANTITY_PARAM_NAMES = {
    "quantity", "qty", "count", "limit", "size", "page", "offset", "number",
    "stock", "inventory",
}


# ═══════════════════════════════════════════════════════════════
# Payload generation by schema type
# ═══════════════════════════════════════════════════════════════

def _is_id_param(name):
    clean = re.sub(r'[^a-z0-9]', '', str(name).lower())
    return clean in _ID_PARAM_NAMES

def _is_price_param(name):
    clean = re.sub(r'[^a-z0-9]', '', str(name).lower())
    return clean in _PRICE_PARAM_NAMES

def _is_quantity_param(name):
    clean = re.sub(r'[^a-z0-9]', '', str(name).lower())
    return clean in _QUANTITY_PARAM_NAMES


def generate_attack_values(param_name, schema_type="string", param_in="query"):
    """Generate attack payloads for a parameter based on its name, type, and location.

    Returns a list of {value, description, severity_impact} dicts.
    """
    name = str(param_name).lower()
    stype = str(schema_type).lower()
    payloads = []

    # ── ID parameters ──
    if _is_id_param(name):
        payloads += [
            {"value": "0", "desc": "Zero ID", "impact": "medium"},
            {"value": "-1", "desc": "Negative ID", "impact": "medium"},
            {"value": "null", "desc": "Null ID", "impact": "low"},
            {"value": "1 OR 1=1", "desc": "SQL injection in ID", "impact": "high"},
            {"value": "../../../etc/passwd", "desc": "Path traversal in ID", "impact": "high"},
            {"value": "*", "desc": "Wildcard ID", "impact": "medium"},
            {"value": "admin", "desc": "Privileged username as ID", "impact": "high"},
        ]

    # ── Price/amount parameters ──
    if _is_price_param(name):
        payloads += [
            {"value": "-1", "desc": "Negative price", "impact": "high"},
            {"value": "0", "desc": "Zero price", "impact": "high"},
            {"value": "0.01", "desc": "Micro-transaction", "impact": "medium"},
            {"value": "999999999", "desc": "Massive price overflow", "impact": "medium"},
            {"value": "-999999", "desc": "Massive negative price", "impact": "high"},
        ]

    # ── Quantity parameters ──
    if _is_quantity_param(name):
        payloads += [
            {"value": "-1", "desc": "Negative quantity", "impact": "high"},
            {"value": "0", "desc": "Zero quantity", "impact": "medium"},
            {"value": "99999", "desc": "Massive quantity (stock overflow)", "impact": "medium"},
            {"value": "-99999", "desc": "Massive negative quantity", "impact": "high"},
        ]

    # ── Type-based payloads ──
    if stype in ("integer", "number", "float", "int"):
        payloads += [
            {"value": "0", "desc": "Zero value", "impact": "low"},
            {"value": "-1", "desc": "Negative value", "impact": "medium"},
            {"value": "NaN", "desc": "NaN injection", "impact": "low"},
            {"value": "Infinity", "desc": "Infinity injection", "impact": "low"},
        ]

    elif stype in ("string", "str", "text"):
        payloads += [
            {"value": "", "desc": "Empty string", "impact": "low"},
            {"value": "null", "desc": "Null as string", "impact": "low"},
            {"value": "A" * 5000, "desc": "Long string (buffer overflow)", "impact": "medium"},
            {"value": "'; DROP TABLE users; --", "desc": "SQL injection probe", "impact": "critical"},
            {"value": "<script>alert(1)</script>", "desc": "XSS probe", "impact": "medium"},
            {"value": "${7*7}", "desc": "Template injection probe", "impact": "high"},
            {"value": "../../../etc/passwd", "desc": "Path traversal", "impact": "high"},
            {"value": "\\u0000", "desc": "Null byte injection", "impact": "medium"},
        ]

    elif stype in ("boolean", "bool"):
        payloads += [
            {"value": "1", "desc": "Integer 1 for boolean", "impact": "low"},
            {"value": "0", "desc": "Integer 0 for boolean", "impact": "low"},
            {"value": "yes", "desc": "String 'yes' for boolean", "impact": "low"},
            {"value": "\"true\"", "desc": "JSON string true", "impact": "low"},
        ]

    elif stype in ("array", "list"):
        payloads += [
            {"value": "null", "desc": "Null instead of array", "impact": "low"},
            {"value": "{}", "desc": "Object instead of array", "impact": "low"},
            {"value": "\"string\"", "desc": "String instead of array", "impact": "low"},
            {"value": "[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20]", "desc": "Large array", "impact": "low"},
        ]

    # ── Auth-related parameters ──
    if re.sub(r'[^a-z0-9]', '', name) in _AUTH_PARAM_NAMES:
        payloads += [
            {"value": "", "desc": "Empty auth token", "impact": "high"},
            {"value": "Bearer invalid", "desc": "Invalid bearer token", "impact": "medium"},
            {"value": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.", "desc": "JWT with alg=none", "impact": "critical"},
        ]

    return payloads[:8]  # cap at 8 payloads per param to keep scan time reasonable


def fuzz_request_body(body_schema, openapi_spec=None):
    """Generate fuzzed variants of a request body based on its JSON schema.

    Returns list of {body, description} dicts.
    """
    variants = []
    if not body_schema:
        return variants

    props = body_schema.get("properties", {})
    if not props:
        return variants

    # For each property, generate a modified body with one fuzzed value
    for prop_name, prop_schema in props.items():
        prop_type = prop_schema.get("type", "string")
        payloads = generate_attack_values(prop_name, prop_type)
        for p in payloads[:2]:  # limit to 2 variants per property
            try:
                # Build a minimal body with just this property fuzzed
                body = {}
                for pn, ps in props.items():
                    if pn == prop_name:
                        # Try to parse the value as JSON (for numbers, bools, etc.)
                        try:
                            body[pn] = json.loads(str(p["value"]))
                        except (json.JSONDecodeError, ValueError):
                            body[pn] = str(p["value"])
                    else:
                        # Use type-appropriate defaults for other fields
                        pt = ps.get("type", "string")
                        if pt in ("integer", "number"):
                            body[pn] = 1
                        elif pt == "boolean":
                            body[pn] = True
                        elif pt == "array":
                            body[pn] = []
                        elif pt == "object":
                            body[pn] = {}
                        else:
                            body[pn] = "test"
                variants.append({
                    "body": json.dumps(body),
                    "description": f"Fuzzed '{prop_name}': {p['desc']}",
                    "severity_impact": p["impact"],
                })
            except Exception:
                pass

    # Also test: empty body, malformed JSON
    variants.append({"body": "", "description": "Empty body", "severity_impact": "low"})
    variants.append({"body": "{invalid", "description": "Malformed JSON body", "severity_impact": "low"})

    return variants


def extract_params_from_schema(openapi_spec, path, method):
    """Extract and classify parameters from an OpenAPI path+method."""
    params = {"path": [], "query": [], "header": [], "body_props": {}}

    if not openapi_spec:
        return params

    path_item = openapi_spec.get("paths", {}).get(path, {})
    operation = path_item.get(method.lower(), {}) if path_item else {}

    for p in operation.get("parameters", []):
        loc = p.get("in", "query")
        info = {
            "name": p.get("name", ""),
            "type": p.get("schema", {}).get("type", "string"),
            "required": p.get("required", False),
        }
        if loc in params:
            params[loc].append(info)

    # Body schema
    body = operation.get("requestBody", {})
    json_body = body.get("content", {}).get("application/json", {})
    if json_body:
        params["body_props"] = json_body.get("schema", {})

    return params


def id_cross_reference(id_list, schema_params):
    """Cross-reference ID list keys with schema parameter names.

    Returns {id_key: [matching_param_names]} for smart BOLA testing.
    """
    matches = {}
    if not id_list or not schema_params:
        return matches

    all_params = [p["name"] for loc in ("path", "query", "header") for p in schema_params.get(loc, [])]

    for id_key in id_list:
        # Try to match id_key with parameter names
        key_lower = str(id_key).lower()
        matched = []
        for pname in all_params:
            pname_clean = str(pname).lower()
            if key_lower == pname_clean:
                matched.append(pname)
        if matched:
            matches[id_key] = matched

    return matches
