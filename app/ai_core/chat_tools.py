# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""Chat assistant tools — API client scope only.

Slash commands force a tool. The LLM can also call them autonomously.
"""

import json as _json
import re

from request_manager.request_api import _make_request


# ── Slash → tool mapping ───────────────────────────────────────────────
SLASH_TOOLS = {
    "/explain": "explain_response",
    "/scan":    "quick_scan",
    "/diff":    "diff_responses",
    "/code":    "generate_code",
}


def is_slash_command(message: str) -> str | None:
    """If message starts with a whitelisted slash command, return the tool name.

    Only exact whitelist matches trigger injection. No tool name is ever
    derived from user input — SLASH_TOOLS is the sole gate.

    Matches are case-insensitive and require a word boundary after the command:
      /scan  → quick_scan
      /SCAN  → quick_scan
      /scanning → None (no word boundary)
      /xss   → None (not whitelisted)
    """
    msg = message.strip()
    msg_lower = msg.lower()
    for prefix, tool_name in SLASH_TOOLS.items():
        prefix_lower = prefix.lower()
        if msg_lower.startswith(prefix_lower):
            after = msg[len(prefix):]
            if after == "" or after[0] in (" ", "\n", "\t", ":", "?"):
                return tool_name
    return None


def get_slash_prompt(tool_name: str, user_message: str) -> str:
    return (
        f"The user invoked /{tool_name}. You MUST call `{tool_name}` at least once in your response. "
        f"You may also call other tools (send_request, get_users_last_five_requests, etc.) to gather context before or after, "
        f"but you cannot skip `{tool_name}`. "
        f"Stay within the scope of an API client assistant. "
        f"User request: {user_message}"
    )


# ── Tool definitions ───────────────────────────────────────────────────
def get_chat_tools():
    return [
        {
            "type": "function",
            "function": {
                "name": "explain_response",
                "description": "Analyze an HTTP response. Explain status codes, identify error causes (SQL errors, stack traces, auth issues), detect the API framework, and suggest fixes.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "status_code": {"type": "integer", "description": "HTTP status code"},
                        "method": {"type": "string", "description": "HTTP method used"},
                        "url": {"type": "string", "description": "Request URL"},
                        "response_body": {"type": "string", "description": "Response body (first 2000 chars)"},
                        "response_headers": {"type": "string", "description": "Response headers as JSON string"},
                    },
                    "required": ["status_code", "response_body"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "quick_scan",
                "description": "Run a quick security probe on an endpoint. Tests SQLi, XSS, path traversal, template injection, and checks if the endpoint is accessible without authentication. Returns raw probe results — the AI interprets them.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Full URL to probe"},
                        "method": {"type": "string", "description": "HTTP method (GET, POST, ...)"},
                        "headers": {"type": "string", "description": "Request headers as JSON (optional)"},
                        "body": {"type": "string", "description": "Request body (optional)"},
                    },
                    "required": ["url", "method"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "diff_responses",
                "description": "Compare two HTTP response bodies structurally. Identifies key differences in JSON keys and values. Useful for confirming BOLA/IDOR — if user A and user B see different data with the same structure, cross-user access is likely.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "body_a": {"type": "string", "description": "First response body"},
                        "body_b": {"type": "string", "description": "Second response body"},
                        "label_a": {"type": "string", "description": "Label for first (e.g. 'User A')"},
                        "label_b": {"type": "string", "description": "Label for second (e.g. 'User B')"},
                    },
                    "required": ["body_a", "body_b"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "generate_code",
                "description": "Generate HTTP client code from a request specification. Outputs Python, JavaScript, or Go code using the standard HTTP library of each language.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "method": {"type": "string", "description": "HTTP method"},
                        "url": {"type": "string", "description": "Full URL"},
                        "headers": {"type": "string", "description": "Headers as JSON (optional)"},
                        "body": {"type": "string", "description": "Request body (optional)"},
                        "language": {"type": "string", "description": "Target: python, javascript, go"},
                    },
                    "required": ["method", "url"],
                },
            },
        },
    ]


# ── Tool dispatcher ────────────────────────────────────────────────────
def handle_chat_tool(tool_name: str, parameters: dict) -> str:
    handlers = {
        "explain_response": _explain,
        "quick_scan": _scan,
        "diff_responses": _diff,
        "generate_code": _code,
    }
    handler = handlers.get(tool_name)
    if handler:
        return _json.dumps(handler(parameters), ensure_ascii=False)
    return _json.dumps({"error": f"Unknown tool: {tool_name}"})


# ── Implementations ────────────────────────────────────────────────────
def _explain(params: dict) -> dict:
    status = params.get("status_code", 0)
    body = str(params.get("response_body", ""))[:2000]
    headers_str = params.get("response_headers", "{}")
    try:
        headers = _json.loads(headers_str) if isinstance(headers_str, str) else headers_str
    except Exception:
        headers = {}

    diagnostics = []
    if status == 401:
        www_auth = str(headers.get("WWW-Authenticate", ""))
        if "bearer" in www_auth.lower():
            diagnostics.append("Bearer token expected")
        elif "basic" in www_auth.lower():
            diagnostics.append("Basic auth expected")
    elif status == 403:
        diagnostics.append("Access denied — insufficient permissions")
    elif status == 429:
        diagnostics.append("Rate limited — slow down requests")
    elif status >= 500:
        diagnostics.append("Server error — check if body contains a stack trace")

    lower = body.lower()
    if "sql" in lower or "syntax error" in lower:
        diagnostics.append("Possible SQL error exposed — information disclosure (CWE-209)")
    if "stacktrace" in lower or "traceback" in lower:
        diagnostics.append("Stack trace exposed — information disclosure (CWE-209)")
    if "exception" in lower:
        diagnostics.append("Exception details exposed")

    return {
        "status_code": status,
        "method": params.get("method", "GET"),
        "url": params.get("url", ""),
        "content_type": headers.get("Content-Type", headers.get("content-type", "unknown")),
        "server": headers.get("Server", headers.get("X-Powered-By", "unknown")),
        "body_preview": body[:1500],
        "diagnostics": diagnostics or ["No obvious issues detected"],
    }


def _scan(params: dict) -> dict:
    url = params.get("url", "")
    method = params.get("method", "GET").upper()
    headers_str = params.get("headers", "{}")
    req_body = params.get("body", "")
    try:
        headers = _json.loads(headers_str) if isinstance(headers_str, str) else headers_str
    except Exception:
        headers = {}

    findings = []
    probes = [
        ("' OR '1'='1", "SQL injection probe"),
        ("../../../etc/passwd", "Path traversal probe"),
        ("<script>alert(1)</script>", "XSS probe"),
        ("${7*7}", "Template injection probe"),
    ]
    indicators = ["exception", "stacktrace", "sql", "syntax error", "traceback", "warning:", "error:"]

    for payload, desc in probes:
        try:
            if method == "GET":
                sep = "&" if "?" in url else "?"
                probe_url = f"{url}{sep}q={payload}"
                resp = _make_request("GET", probe_url, headers=headers)
            else:
                resp = _make_request(method, url, headers=headers, body=payload)
            body_lower = str(resp.get("body", "")).lower()
            found = [i for i in indicators if i in body_lower]
            if found:
                findings.append({"payload": desc, "status": resp.get("status_code", 0), "indicators": found})
        except Exception as e:
            findings.append({"payload": desc, "error": str(e)[:120]})

    # No-auth check
    try:
        anon = _make_request(method, url)
        if anon.get("status_code") == 200:
            findings.append({"payload": "No authentication", "status": 200, "indicators": ["accessible without auth"]})
    except Exception:
        pass

    return {
        "endpoint": f"{method} {url}",
        "probes_sent": len(probes) + 1,
        "findings": findings,
    }


def _diff(params: dict) -> dict:
    body_a, body_b = params.get("body_a", ""), params.get("body_b", "")
    label_a, label_b = params.get("label_a", "A"), params.get("label_b", "B")
    try:
        obj_a, obj_b = _json.loads(body_a), _json.loads(body_b)
    except Exception:
        return {"error": "One or both bodies are not valid JSON"}

    if not isinstance(obj_a, dict) or not isinstance(obj_b, dict):
        return {"error": "Both bodies must be JSON objects for structural diff"}

    keys_a, keys_b = set(obj_a.keys()), set(obj_b.keys())
    different = []
    for k in keys_a & keys_b:
        if str(obj_a[k]) != str(obj_b[k]):
            different.append({"key": k, "value_a": str(obj_a[k])[:200], "value_b": str(obj_b[k])[:200]})

    same_structure = len(keys_a & keys_b) >= 2
    same_data = len(different) == 0
    only_a = sorted(keys_a - keys_b)
    only_b = sorted(keys_b - keys_a)

    if same_structure and not same_data and not only_a and not only_b:
        conclusion = f"BOLA/IDOR likely — same structure, different data. {label_a} and {label_b} can access the same endpoint but see different resources."
    elif same_structure and same_data:
        conclusion = f"Same resource — identical structure and data."
    else:
        conclusion = f"Different structures — {len(only_a)} keys only in {label_a}, {len(only_b)} only in {label_b}."

    return {
        "keys_only_in_a": only_a,
        "keys_only_in_b": only_b,
        "common_keys": sorted(keys_a & keys_b),
        "different_values": different[:10],
        "conclusion": conclusion,
    }


def _code(params: dict) -> dict:
    method = params.get("method", "GET").upper()
    url = params.get("url", "")
    headers_str = params.get("headers", "{}")
    body = params.get("body", "")
    language = params.get("language", "python").lower()
    try:
        headers = _json.loads(headers_str) if isinstance(headers_str, str) else headers_str
    except Exception:
        headers = {}

    if language == "python":
        h = "\n".join(f'    "{k}": "{v}",' for k, v in (headers or {}).items())
        b = f'\n    data=\'{body}\',' if body else ""
        code = f"""import requests
headers = {{
{h}
}}
resp = requests.{method.lower()}(
    "{url}",{b}
    headers=headers,
    verify=True,
)
print(resp.status_code, resp.text[:500])"""
    elif language == "javascript":
        h = ",\n  ".join(f'"{k}": "{v}"' for k, v in (headers or {}).items())
        b = f',\n  body: JSON.stringify({body})' if body else ""
        code = f"""const headers = {{ {h} }};
const resp = await fetch("{url}", {{
  method: "{method}",
  headers{b}
}});
console.log(resp.status, await resp.text());"""
    elif language == "go":
        h = "\n".join(f'    req.Header.Set("{k}", "{v}")' for k, v in (headers or {}).items())
        b = f'\n    reqBody := strings.NewReader(`{body}`)' if body else ""
        b2 = "reqBody" if body else "nil"
        code = f"""package main
import ("io"; "net/http"; "strings")
func main() {{{b}
    req, _ := http.NewRequest("{method}", "{url}", {b2})
{h}
    resp, _ := http.DefaultClient.Do(req)
    defer resp.Body.Close()
    body, _ := io.ReadAll(resp.Body)
    println(string(body))
}}"""
    else:
        code = f"# Unsupported language: {language}"

    return {"language": language, "code": code}
