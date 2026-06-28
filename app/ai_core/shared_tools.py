# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Centralized shared tool library -- one definition, one handler per tool.

Teams (Ely, Red, Purple, Grey) import tools from here instead of redefining them.

Usage:
  from ai_core.shared_tools import get_tool_def, handle_tool, build_tool_set

  # Get a single tool definition + handler
  definition = get_tool_def("bash")

  # Build a complete tool set for a team/scenario
  tools, tool_map = build_tool_set(["bash", "browser_query", "make_test_request"],
                                    target_endpoint="http://target:8080",
                                    user_id="xxx")

  # Execute a tool call
  result = handle_tool("bash", {"command": "ls -la"}, user_id="xxx")
"""

import json
import os
import re
import time
import subprocess

# ═══════════════════════════════════════════════════════════════
# Tool Definitions
# ═══════════════════════════════════════════════════════════════

TOOL_DEFS = {
    # ── Sandbox / Shell ──
    "bash": {
        "type": "function",
        "function": {
            "name": "bash",
            "description": "Execute shell commands in an isolated sandbox. Use for: running security tools (nuclei, sqlmap, ffuf, nmap), executing scripts, and performing passive reconnaissance. Commands run in sequence.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Shell command to execute"},
                    "commands": {"type": "array", "items": {"type": "string"}, "description": "Batch of commands to run in sequence (alternative to single command)"},
                    "timeout_ms": {"type": "integer", "description": "Max execution time in ms (default: 30000)"},
                },
                "required": [],
            },
        },
    },

    # ── HTTP Requests ──
    "send_request": {
        "type": "function",
        "function": {
            "name": "send_request",
            "description": "Send an HTTP request to a target URL. Returns status, headers, and body preview.",
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]},
                    "url": {"type": "string", "description": "Full URL or path (if target is configured)"},
                    "headers": {"type": "object", "description": "HTTP headers as key-value pairs"},
                    "body": {"type": "string", "description": "Request body (JSON string for POST/PUT/PATCH)"},
                    "allow_redirects": {"type": "boolean", "description": "Follow redirects (default: false)"},
                },
                "required": ["method", "url"],
            },
        },
    },

    "send_raw_request": {
        "type": "function",
        "function": {
            "name": "send_raw_request",
            "description": "Send a raw HTTP request string. Useful for custom or non-standard requests.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target base URL"},
                    "request": {"type": "string", "description": "Raw HTTP request (e.g. 'GET /api/users HTTP/1.1\\nHost: example.com\\n\\n')"},
                },
                "required": ["url", "request"],
            },
        },
    },

    "make_test_request": {
        "type": "function",
        "function": {
            "name": "make_test_request",
            "description": "Send an HTTP request to the TARGET API to VALIDATE a suspected vulnerability. Use to prove exploitability -- do NOT use for exploration. Returns status, headers, body preview, and vulnerability indicators.",
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]},
                    "path": {"type": "string", "description": "URL path (e.g. /api/users/1)"},
                    "headers": {"type": "object", "description": "Additional HTTP headers"},
                    "body": {"type": "string", "description": "Request body as string"},
                    "reasoning": {"type": "string", "description": "What vulnerability are you trying to exploit?"},
                },
                "required": ["method", "path", "reasoning"],
            },
        },
    },

    "parallel_requests": {
        "type": "function",
        "function": {
            "name": "parallel_requests",
            "description": "Send multiple HTTP requests in parallel to the target. Use for fuzzing, brute-forcing, or testing multiple endpoints simultaneously.",
            "parameters": {
                "type": "object",
                "properties": {
                    "requests": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 20,
                        "items": {
                            "type": "object",
                            "properties": {
                                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"]},
                                "path": {"type": "string"},
                                "headers": {"type": "object"},
                                "body": {"type": "string"},
                                "reasoning": {"type": "string"},
                            },
                            "required": ["method", "path"],
                        },
                    },
                },
                "required": ["requests"],
            },
        },
    },

    # ── Browser ──
    "browser_query": {
        "type": "function",
        "function": {
            "name": "browser_query",
            "description": "Use a headless browser to query a web page and extract content matching a CSS selector. Returns the text content of matching elements.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to load in the browser"},
                    "selector": {"type": "string", "description": "CSS selector to extract content from (default: 'body')"},
                },
                "required": ["url"],
            },
        },
    },

    "browser_click": {
        "type": "function",
        "function": {
            "name": "browser_click",
            "description": "Use a headless browser to load a page and click an element matching a CSS selector.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to load in the browser"},
                    "selector": {"type": "string", "description": "CSS selector of the element to click"},
                },
                "required": ["url", "selector"],
            },
        },
    },

    # ── Web Search ──
    "web_search": {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Search the web using DuckDuckGo Lite. Returns a list of {url, title, description} results.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                },
                "required": ["query"],
            },
        },
    },

    # ── Code Analysis ──
    "list_directory": {
        "type": "function",
        "function": {
            "name": "list_directory",
            "description": "List files and subdirectories in a code repository. Use FIRST to map the project tree before reading files. Skips hidden files and common build/vendor directories.",
            "parameters": {
                "type": "object",
                "properties": {
                    "subdirectory": {"type": "string", "description": "Directory to list relative to repo root (e.g. 'src', 'app/routes', '' for root)"},
                },
                "required": [],
            },
        },
    },

    "read_source_file": {
        "type": "function",
        "function": {
            "name": "read_source_file",
            "description": "Read a source file from the repository. Content is limited to the first 10KB. Use AFTER listing directories to target high-value files.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Relative path to the source file"},
                    "reasoning": {"type": "string", "description": "What vulnerability class are you investigating?"},
                },
                "required": ["file_path", "reasoning"],
            },
        },
    },

    "grep_codebase": {
        "type": "function",
        "function": {
            "name": "grep_codebase",
            "description": "Search all source files in the repository for a regex pattern. Use to find dangerous function calls, hardcoded secrets, or auth bypass patterns. Returns file:line matches (max 50).",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Regex pattern or keyword to search for"},
                    "file_pattern": {"type": "string", "description": "File glob filter (e.g. '*.py', '*.java', '*.js')"},
                    "reasoning": {"type": "string", "description": "What vulnerability are you hunting?"},
                },
                "required": ["pattern", "reasoning"],
            },
        },
    },

    # ── Findings ──
    "submit_finding": {
        "type": "function",
        "function": {
            "name": "submit_finding",
            "description": "Report a confirmed vulnerability finding. Call this IMMEDIATELY for each finding -- do not batch. Include evidence, file location, and remediation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Concise finding title"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                    "description": {"type": "string", "description": "Detailed description including exploitation evidence"},
                    "file_path": {"type": "string", "description": "Relative path to the vulnerable file"},
                    "line_number": {"type": "integer", "description": "Line number of the vulnerable code"},
                    "remediation": {"type": "string", "description": "Specific steps to fix the vulnerability"},
                    "cwe_id": {"type": "string", "description": "CWE ID (e.g. 'CWE-89' for SQL injection)"},
                    "cvss_score": {"type": "number", "description": "CVSS 3.1 score (0.0-10.0)"},
                    "endpoint": {"type": "string", "description": "Target endpoint affected (if applicable)"},
                    "evidence": {"type": "object", "description": "Request/response evidence proving exploitation"},
                },
                "required": ["title", "severity", "description"],
            },
        },
    },

    "submit_findings_batch": {
        "type": "function",
        "function": {
            "name": "submit_findings_batch",
            "description": "Report multiple confirmed vulnerabilities at once. Each finding must include title, severity, description, and evidence.",
            "parameters": {
                "type": "object",
                "properties": {
                    "findings": {
                        "type": "array",
                        "minItems": 1,
                        "items": {
                            "type": "object",
                            "properties": {
                                "title": {"type": "string"},
                                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                                "description": {"type": "string"},
                                "file_path": {"type": "string"},
                                "line_number": {"type": "integer"},
                                "remediation": {"type": "string"},
                                "cwe_id": {"type": "string"},
                                "cvss_score": {"type": "number"},
                                "endpoint": {"type": "string"},
                                "category": {"type": "string"},
                                "evidence": {"type": "object"},
                            },
                            "required": ["title", "severity", "description"],
                        },
                    },
                },
                "required": ["findings"],
            },
        },
    },

    # ── Response Analysis ──
    "explain_response": {
        "type": "function",
        "function": {
            "name": "explain_response",
            "description": "Analyze an HTTP response body and headers to identify security-relevant patterns, information disclosure, or suspicious behavior.",
            "parameters": {
                "type": "object",
                "properties": {
                    "status_code": {"type": "integer"},
                    "method": {"type": "string"},
                    "url": {"type": "string"},
                    "response_body": {"type": "string", "description": "The HTTP response body text"},
                    "response_headers": {"type": "object", "description": "Response headers as key-value pairs"},
                },
                "required": ["status_code", "response_body"],
            },
        },
    },
}


# ═══════════════════════════════════════════════════════════════
# Tool Handler Implementations
# ═══════════════════════════════════════════════════════════════

class ToolContext:
    """Context passed to tool handlers -- populated by the calling team."""
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


def get_tool_def(name: str) -> dict | None:
    """Return the OpenAI tool definition for a given tool name."""
    return TOOL_DEFS.get(name)


def build_tool_set(names: list[str], **context) -> tuple[list[dict], dict]:
    """Build a tool set: list of definitions + name→handler map.

    This is the SINGLE point of control for which tools each AI agent gets.
    Each team calls this with their EXACT allowed tool list.

    Args:
        names: List of tool names to include.
        **context: Passed to handlers. Common keys: user_id, target_endpoint,
                   repo_path, scan_id, add_finding_fn

    Returns:
        (tools_list, tool_map) -- ready for use in AI scanner run() methods
    """
    ctx = ToolContext(**context)
    tools = []
    tool_map = {}
    for name in names:
        definition = get_tool_def(name)
        handler = _HANDLERS.get(name)
        if definition and handler:
            tools.append(definition)
            tool_map[name] = lambda args, h=handler, c=ctx: h(args, c)
        elif definition:
            tools.append(definition)
    return tools, tool_map


# Pre-configured tool sets -- scoped per scenario
TOOL_SETS = {
    "code_analysis": ["list_directory", "read_source_file", "grep_codebase", "submit_finding"],
    "interactive_testing": ["make_test_request", "submit_finding"],
    "full_iast": ["list_directory", "read_source_file", "grep_codebase",
                  "make_test_request", "submit_finding"],
    "osint": ["bash", "browser_query", "web_search", "submit_finding"],
    "pentest": ["bash", "send_request", "browser_query", "browser_click",
                "web_search", "submit_findings_batch"],
    "exploration": ["bash", "web_search", "browser_query"],
}


def handle_tool(name: str, args: dict, **context) -> str:
    """Execute a tool by name. Returns JSON string result."""
    handler = _HANDLERS.get(name)
    if not handler:
        return json.dumps({"error": f"Unknown tool: {name}"})
    ctx = ToolContext(**context)
    return handler(args, ctx)


# ═══════════════════════════════════════════════════════════════
# Handler implementations
# ═══════════════════════════════════════════════════════════════

def _h_bash(args: dict, ctx: ToolContext) -> str:
    """Execute shell command(s) in sandbox."""
    user_id = getattr(ctx, 'user_id', 'default')
    commands = args.get("commands", [])
    if args.get("command"):
        commands.append(args["command"])
    timeout_ms = args.get("timeout_ms", 30000)

    if not commands:
        return json.dumps({"error": "No command provided", "stdout": "", "stderr": ""})

    outputs = []
    for cmd in commands[:10]:
        cmd = str(cmd)[:2000]
        if _is_dangerous_command(cmd):
            outputs.append({"command": cmd, "stdout": "", "stderr": "Blocked: dangerous pattern", "exit_code": -1})
            continue
        try:
            proc = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                timeout=min(timeout_ms // 1000, 60),
                cwd="/tmp",
            )
            outputs.append({
                "command": cmd,
                "stdout": proc.stdout[:5000],
                "stderr": proc.stderr[:1000],
                "exit_code": proc.returncode,
            })
        except subprocess.TimeoutExpired:
            outputs.append({"command": cmd, "stdout": "", "stderr": "Timeout", "exit_code": -1})
        except Exception as e:
            outputs.append({"command": cmd, "stdout": "", "stderr": str(e)[:200], "exit_code": -1})

    return json.dumps({"results": outputs})


def _h_send_request(args: dict, ctx: ToolContext) -> str:
    """Send an HTTP request."""
    import requests as _req
    method = args.get("method", "GET")
    url = args.get("url", "")
    headers = args.get("headers", {})
    body = args.get("body", "")
    allow_redirects = args.get("allow_redirects", False)

    if not url:
        return json.dumps({"error": "URL required"})

    # Validate URL
    from core.security import is_url_safe
    safe, reason = is_url_safe(url)
    if not safe:
        return json.dumps({"error": f"URL blocked: {reason}"})

    try:
        kwargs = {"headers": headers, "timeout": 15, "allow_redirects": allow_redirects}
        if body and method in ('POST', 'PUT', 'PATCH'):
            try:
                kwargs["json"] = json.loads(body)
            except (json.JSONDecodeError, TypeError):
                kwargs["data"] = body
        resp = _req.request(method, url, **kwargs)
        resp_body = resp.text[:3000]
        return json.dumps({
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body_preview": resp_body,
            "body_length": len(resp.text),
        })
    except Exception as e:
        return json.dumps({"error": str(e)[:300]})


def _h_parallel_requests(args: dict, ctx: ToolContext) -> str:
    """Send multiple HTTP requests in parallel."""
    import concurrent.futures
    import requests as _req
    from core.security import is_url_safe

    requests_list = args.get("requests", [])
    if not requests_list:
        return json.dumps({"error": "requests array required"})

    target = getattr(ctx, 'target_endpoint', '')
    if not target:
        return json.dumps({"error": "No target endpoint configured"})

    def send_one(req):
        method = req.get("method", "GET")
        path = req.get("path", "/")
        headers = req.get("headers", {})
        body = req.get("body", "")
        reasoning = req.get("reasoning", "")
        try:
            from urllib.parse import urljoin
            url = urljoin(target, path)
            safe, reason = is_url_safe(url)
            if not safe:
                return {"method": method, "path": path, "error": f"Blocked: {reason}"}
            kwargs = {"headers": headers, "timeout": 10, "allow_redirects": False}
            if body and method in ('POST', 'PUT', 'PATCH'):
                try:
                    kwargs["json"] = json.loads(body)
                except (json.JSONDecodeError, TypeError):
                    kwargs["data"] = body
            resp = _req.request(method, url, **kwargs)
            indicators = []
            body_lower = resp.text[:1000].lower()
            if any(kw in body_lower for kw in ['sql', 'mysql', 'error', 'exception']):
                indicators.append('possible_error')
            if resp.status_code in (200, 201) and len(resp.text) > 50:
                indicators.append('data_returned')
            return {
                "method": method, "path": path, "status": resp.status_code,
                "body_preview": resp.text[:500], "indicators": indicators,
                "reasoning": reasoning,
            }
        except Exception as e:
            return {"method": method, "path": path, "error": str(e)[:200]}

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(send_one, r) for r in requests_list[:20]]
        results = [f.result() for f in futures]

    error_count = sum(1 for r in results if "error" in r)
    success_count = sum(1 for r in results if "error" not in r)
    return json.dumps({
        "results": results,
        "total": len(results),
        "success": success_count,
        "errors": error_count,
        "hint": "Review results. If any show 'possible_error' or unexpected data, call submit_finding for each exploitable vulnerability."
    })


def _h_make_test_request(args: dict, ctx: ToolContext) -> str:
    """Send a targeted test request to validate a vulnerability."""
    import requests as _req
    from urllib.parse import urljoin

    target = getattr(ctx, 'target_endpoint', '')
    if not target:
        return json.dumps({"error": "No target endpoint configured", "exploitable": False})

    method = args.get("method", "GET")
    path = args.get("path", "/")
    headers = args.get("headers", {})
    body = args.get("body", "")
    reasoning = args.get("reasoning", "")

    try:
        url = urljoin(target, path)
        kwargs = {"headers": headers, "timeout": 10, "allow_redirects": False}
        if body and method in ('POST', 'PUT', 'PATCH'):
            try:
                kwargs["json"] = json.loads(body)
            except (json.JSONDecodeError, TypeError):
                kwargs["data"] = body

        resp = _req.request(method, url, **kwargs)
        resp_body = resp.text[:2000]
        body_lower = resp_body.lower()

        indicators = []
        exploitable = False
        if any(kw in body_lower for kw in ['sql', 'mysql', 'postgresql', 'syntax error', 'ora-']):
            indicators.append('possible_sql_error'); exploitable = True
        if any(kw in body_lower for kw in ['traceback', 'stack trace', 'exception', 'at line']):
            indicators.append('error_disclosure'); exploitable = True
        if any(kw in body_lower for kw in ['root:', 'daemon:', 'uid=', 'gid=']):
            indicators.append('possible_command_output'); exploitable = True
        if resp.status_code == 200 and len(resp_body) > 100:
            indicators.append('data_returned')
        if resp.status_code == 500:
            indicators.append('server_error'); exploitable = True

        return json.dumps({
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body_preview": resp_body,
            "body_length": len(resp.text),
            "exploitable": exploitable,
            "indicators": indicators,
            "attack_context": reasoning,
            "hint": "If exploitable=true, call submit_finding NOW. If data_returned and endpoint has IDs, test IDOR."
        })
    except Exception as e:
        return json.dumps({"error": str(e)[:300], "exploitable": False})


def _h_browser_query(args: dict, ctx: ToolContext) -> str:
    """Query a page using headless browser."""
    url = args.get("url", "")
    selector = args.get("selector", "body")
    if not url:
        return json.dumps({"error": "URL required"})
    try:
        from ely.browser import query_page, launch_browser, close_browser
        user_id = getattr(ctx, 'user_id', 'default')
        browser, playwright = launch_browser()
        content = query_page(browser, url, selector)
        close_browser(browser, playwright)
        return json.dumps({"content": content[:5000] if isinstance(content, str) else str(content)})
    except Exception as e:
        return json.dumps({"error": str(e)[:300]})


def _h_web_search(args: dict, ctx: ToolContext) -> str:
    """Search the web."""
    query = args.get("query", "")
    if not query or not query.strip():
        return json.dumps({"error": "Empty query"})
    try:
        from ely.search_engine import search_engine
        results = search_engine(query.strip())
        if isinstance(results, str):
            return json.dumps({"error": results})
        return json.dumps({"results": results[:10]})
    except Exception as e:
        return json.dumps({"error": str(e)[:300]})


def _h_list_directory(args: dict, ctx: ToolContext) -> str:
    """List files in a repo directory."""
    repo_path = getattr(ctx, 'repo_path', '')
    if not repo_path:
        return json.dumps({"error": "No repository path configured"})
    subdir = args.get("subdirectory", "")
    clean = subdir.replace("..", "").lstrip("/").lstrip("\\")
    target = os.path.join(repo_path, clean) if clean else repo_path
    if not os.path.isdir(target):
        return json.dumps({"error": f"Directory not found: {subdir}", "files": [], "dirs": []})
    try:
        entries = sorted(os.listdir(target))
        files, dirs = [], []
        for e in entries:
            full = os.path.join(target, e)
            if e.startswith(".") or e in ("node_modules", "__pycache__", "venv", ".git", "target", "build", "dist"):
                continue
            if os.path.isdir(full): dirs.append(e + "/")
            else: files.append({"name": e, "size": os.path.getsize(full)})
        return json.dumps({"path": clean or "/", "directories": dirs[:30], "files": files[:50]})
    except Exception as e:
        return json.dumps({"error": str(e)})


def _h_read_source_file(args: dict, ctx: ToolContext) -> str:
    """Read a source file from the repo."""
    repo_path = getattr(ctx, 'repo_path', '')
    if not repo_path:
        return json.dumps({"error": "No repository path configured"})
    file_path = args.get("file_path", "")
    if ".." in file_path or file_path.startswith("/"):
        return json.dumps({"error": "Invalid file path"})
    full = os.path.join(repo_path, file_path)
    if not os.path.isfile(full):
        return json.dumps({"error": f"File not found: {file_path}"})
    try:
        with open(full, 'r', encoding='utf-8', errors='replace') as fh:
            content = fh.read(10240)
        lines = content.split('\n')
        numbered = [f"{i+1}:{line}" for i, line in enumerate(lines)]
        return json.dumps({"file": file_path, "content": '\n'.join(numbered), "lines": len(lines)})
    except Exception as e:
        return json.dumps({"error": str(e)})


def _h_grep_codebase(args: dict, ctx: ToolContext) -> str:
    """Search all source files for a pattern."""
    repo_path = getattr(ctx, 'repo_path', '')
    if not repo_path:
        return json.dumps({"error": "No repository path configured"})
    pattern = args.get("pattern", "")
    file_pattern = args.get("file_pattern", "*")
    if not pattern:
        return json.dumps({"error": "Pattern required"})
    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error:
        return json.dumps({"error": f"Invalid regex: {pattern}"})

    matches = []
    skip_dirs = {'.git', '__pycache__', 'node_modules', 'venv', '.venv', 'vendor',
                 'target', 'build', 'dist', '.next', '.idea', '.vscode'}
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith('.')]
        for f in files:
            if file_pattern != "*" and not f.endswith(tuple(file_pattern.replace('*', '').split('|'))):
                continue
            fpath = os.path.join(root, f)
            try:
                with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                    for i, line in enumerate(fh, 1):
                        if regex.search(line):
                            rel = os.path.relpath(fpath, repo_path)
                            matches.append({"file": rel, "line": i, "content": line.strip()[:200]})
                            if len(matches) >= 50:
                                break
            except Exception:
                pass
            if len(matches) >= 50:
                break
        if len(matches) >= 50:
            break

    return json.dumps({"matches": matches[:50], "total": len(matches)})


def _h_submit_finding(args: dict, ctx: ToolContext) -> str:
    """Record a single finding (pass-through to caller's callback)."""
    add_fn = getattr(ctx, 'add_finding_fn', None)
    scan_id = getattr(ctx, 'scan_id', '')
    if add_fn:
        add_fn(
            scan_id=scan_id,
            title=args.get("title", ""),
            description=args.get("description", ""),
            severity=args.get("severity", "medium"),
            category="ai_discovered",
            file_path=args.get("file_path", ""),
            line_number=args.get("line_number", 0),
            evidence=args.get("evidence", {}),
            remediation=args.get("remediation", ""),
            cvss_score=args.get("cvss_score", 0.0),
            cwe_id=args.get("cwe_id", ""),
        )
        return json.dumps({"reported": 1})
    return json.dumps({"reported": 0, "error": "No add_finding_fn in context"})


def _h_submit_findings_batch(args: dict, ctx: ToolContext) -> str:
    """Record multiple findings."""
    add_fn = getattr(ctx, 'add_finding_fn', None)
    scan_id = getattr(ctx, 'scan_id', '')
    findings = args.get("findings", [])
    if not add_fn:
        return json.dumps({"reported": 0, "error": "No add_finding_fn in context"})
    reported = 0
    for f in findings:
        add_fn(
            scan_id=scan_id,
            title=f.get("title", ""),
            description=f.get("description", ""),
            severity=f.get("severity", "medium"),
            category=f.get("category", "ai_discovered"),
            file_path=f.get("file_path", ""),
            line_number=f.get("line_number", 0),
            evidence=f.get("evidence", {}),
            remediation=f.get("remediation", ""),
            cvss_score=f.get("cvss_score", 0.0),
            cwe_id=f.get("cwe_id", ""),
        )
        reported += 1
    return json.dumps({"reported": reported})


# ═══════════════════════════════════════════════════════════════
# Handler registry
# ═══════════════════════════════════════════════════════════════

_HANDLERS = {
    "bash": _h_bash,
    "send_request": _h_send_request,
    "send_raw_request": None,  # handled by request_manager directly
    "make_test_request": _h_make_test_request,
    "parallel_requests": _h_parallel_requests,
    "browser_query": _h_browser_query,
    "browser_click": None,
    "web_search": _h_web_search,
    "list_directory": _h_list_directory,
    "read_source_file": _h_read_source_file,
    "grep_codebase": _h_grep_codebase,
    "submit_finding": _h_submit_finding,
    "submit_findings_batch": _h_submit_findings_batch,
    "explain_response": None,
}


# ═══════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════

def _is_dangerous_command(cmd: str) -> bool:
    blocked = ["rm -rf /", ":(){ :|:& };:", "chmod 777 /", "> /dev/sda",
               "mkfs.", "dd if=", "/etc/shadow", "/etc/passwd", "sudo "]
    lower = cmd.lower()
    return any(b in lower for b in blocked)
