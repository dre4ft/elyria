# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
AI-powered deep pentest scanner — optimized two-phase design.
Phase 2a: Flash model batch-explores in parallel (fast, no reasoning).
Phase 2b: Pro model deep-analyzes results (with reasoning).
"""

import asyncio
import json
import re
import time
from urllib.parse import urljoin

import requests

from core.logging import get_logger
from sandbox.tool import BashTool

_log = get_logger("redteam.scanner")


# ═══════════════════════════════════════════════════════════════
# TOOLS — minimal set, data is injected in prompt not read via tools
# ═══════════════════════════════════════════════════════════════

def _get_tools():
    return [
        {
            "type": "function",
            "function": {
                "name": "pentest_make_requests",
                "description": "Make 5-15 HTTP requests in parallel. ALWAYS batch — never make a single request. Use for: API probing, auth testing, BOLA, injection, fuzzing.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "requests": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]},
                                    "path": {"type": "string", "description": "URL path (e.g. /api/users/1)"},
                                    "headers": {"type": "object", "description": "Extra headers"},
                                    "body": {"type": "string", "description": "Request body"},
                                    "reasoning": {"type": "string", "description": "What vulnerability are you testing with this request?"},
                                },
                                "required": ["method", "path", "reasoning"],
                            },
                            "minItems": 5,
                            "maxItems": 15,
                        },
                    },
                    "required": ["requests"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "bash",
                "description": (
                    "Execute 2-5 shell commands in batch in the pentest sandbox. Each command runs and all results return at once. "
                    "Available tools: nmap, curl, python3, jq, sqlmap, ffuf, subfinder. "
                    "USE THIS: dig, curl, python3 JWT, jq parsing, custom scripting. "
                    "FOR NUCLEI: use pentest_quick_nuclei tool instead (optimized)."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "commands": {
                            "type": "array",
                            "items": {"type": "string"},
                            "minItems": 2,
                            "maxItems": 5,
                            "description": "2-5 shell commands to run sequentially. Batch related work. Example: ['dig TARGET A', 'curl -s -I https://TARGET', 'curl -s https://TARGET/robots.txt']",
                        },
                        "timeout_ms": {
                            "type": "integer",
                            "description": "Max execution time per command in ms (default: 30000, max: 60000)",
                        },
                    },
                    "required": ["commands"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "pentest_quick_nuclei",
                "description": "Run nuclei vulnerability scan against a URL with optimized template selection. Faster than raw nuclei because it uses pre-filtered template sets.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL (e.g., https://api.example.com)"},
                        "severity": {"type": "string", "enum": ["critical,high", "critical,high,medium", "critical", "all"], "description": "Severity filter (default: critical,high)"},
                    },
                    "required": ["url"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "pentest_quick_nmap",
                "description": "Port scan top web ports only (80,443,8080,8443,3000,5000,8000,9000) — fast, open ports only.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target hostname or IP"},
                    },
                    "required": ["target"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "pentest_quick_sqli",
                "description": "Quick SQL injection scan against a single URL with sqlmap — limited to 1 risk/level, 10s timeout per test.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Full URL with query params (e.g., https://api.example.com/users?id=1)"},
                        "method": {"type": "string", "enum": ["GET", "POST"], "description": "HTTP method (default: GET)"},
                        "data": {"type": "string", "description": "POST data if method is POST"},
                    },
                    "required": ["url"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "pentest_quick_ffuf",
                "description": "Fast web fuzzing against API paths — uses api-endpoints wordlist, checks for 200/401/403 responses.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Base URL with FUZZ placeholder (e.g., https://TARGET/api/FUZZ)"},
                    },
                    "required": ["url"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "pentest_add_findings",
                "description": "Report one or more confirmed vulnerabilities with ai_description (3 sentences: what found, why exploitable, concrete impact).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "findings": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "title": {"type": "string"},
                                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                                    "category": {"type": "string"},
                                    "description": {"type": "string"},
                                    "endpoint": {"type": "string"},
                                    "method": {"type": "string"},
                                    "evidence": {"type": "object"},
                                    "remediation": {"type": "string"},
                                    "cvss_score": {"type": "number"},
                                    "cwe_id": {"type": "string"},
                                    "ai_description": {"type": "string", "description": "3 punchy sentences: what was found, why exploitable, concrete impact. Max 400 chars."},
                                },
                                "required": ["title", "severity", "description", "endpoint", "ai_description"],
                            },
                            "minItems": 1,
                        },
                    },
                    "required": ["findings"],
                },
            },
        },
    ]


# ═══════════════════════════════════════════════════════════════
# AI SCANNER
# ═══════════════════════════════════════════════════════════════

class AIScanner:
    def __init__(self, campaign_id, target_url, user_id, auth_config=None,
                 deterministic_findings=None, collection_requests=None, id_list=None,
                 callbacks=None, description="", explore_rounds=15, analysis_rounds=5,
                 stop_check=None):
        self.campaign_id = campaign_id
        self.target = target_url.rstrip("/")
        self.user_id = user_id
        self.auth = auth_config or {}
        self.findings_ref = deterministic_findings or []
        self.collection_requests = collection_requests or []
        self.id_list = id_list or {}
        self.description = description
        self.callbacks = callbacks or {}
        self.explore_rounds = max(1, min(50, int(explore_rounds)))
        self.analysis_rounds = max(1, min(25, int(analysis_rounds)))
        self.stop_check = stop_check or (lambda: False)
        self.conversation = []
        self._setup_session()
        self._setup_providers()
        self.bash_tool = BashTool(sandbox=None, manager=None, target=self.target)

    def _cleanup_sandbox(self):
        try:
            self.bash_tool.destroy()
        except Exception:
            pass
        try:
            if hasattr(self, 'session'):
                self.session.close()
        except Exception:
            pass

    def _setup_session(self):
        self.session = requests.Session()
        self.session.timeout = 15
        for k, v in (self.auth.get("headers") or {}).items():
            self.session.headers[k] = v
        token = self.auth.get("bearer_token")
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"
        proxy = self.auth.get("proxy")
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def _setup_providers(self):
        from ai_core.ai_wrapper import AIWrapper
        from database.ai_config_mgmt import get_default_config

        from database.app_config import get as _cfg, get_api_key

        def _resolve(slot, fallback_model):
            cfg = get_default_config(slot)
            if cfg:
                url = cfg["base_url"] or "https://api.openai.com/v1"
                api_key = cfg.get("api_key", "")
                if cfg["provider_type"] == "lmstudio":
                    url = url.rstrip("/").replace("/api/v1", "/v1")
                    if not url.endswith("/v1"):
                        url = url.rstrip("/") + "/v1"
                    if not api_key:
                        api_key = "not-needed"
                if not api_key:
                    api_key = get_api_key("openai_api_key")
                return {"provider_type": cfg["provider_type"], "url": url, "api_key": api_key, "model": cfg["model"] or fallback_model}
            api_key = get_api_key("openai_api_key")
            if not api_key:
                raise RuntimeError(f"No API key for slot '{slot}' — set a default in /hub")
            return {"provider_type": "openai", "url": "https://api.openai.com/v1", "api_key": api_key, "model": fallback_model}

        flash_cfg = _resolve("flash", "gpt-4o-mini")
        pro_cfg = _resolve("pro", "gpt-4o")
        self.flash = AIWrapper(provider_type=flash_cfg["provider_type"], url=flash_cfg["url"], api_key=flash_cfg["api_key"], model=flash_cfg["model"]).provider
        self.pro = AIWrapper(provider_type=pro_cfg["provider_type"], url=pro_cfg["url"], api_key=pro_cfg["api_key"], model=pro_cfg["model"]).provider
        self.flash_model = flash_cfg["model"]
        self.pro_model = pro_cfg["model"]
        self.conversation = []

    def _url(self, path):
        return urljoin(self.target, path.lstrip("/"))

    # ── Parallel request execution ──

    async def _execute_requests(self, requests_list):
        """Execute multiple HTTP requests in parallel."""
        async def do_one(req):
            method = req.get("method", "GET").upper()
            path = req.get("path", "/")
            headers = req.get("headers") or {}
            body = req.get("body", "")
            reasoning = req.get("reasoning", "")
            url = self._url(path)
            h = dict(self.session.headers)
            h.update(headers)

            loop = asyncio.get_event_loop()
            start = time.monotonic()

            def blocking():
                try:
                    resp = self.session.request(method, url, headers=h, data=body,
                                                timeout=15, allow_redirects=False)
                    elapsed = int((time.monotonic() - start) * 1000)
                    body_preview = resp.text[:2000] if resp.text else ""
                    # Log
                    if self.callbacks.get("on_log"):
                        self.callbacks["on_log"](
                            endpoint=path, method=method, request_url=url,
                            request_headers=h, request_body=body[:2000],
                            response_status=resp.status_code, response_headers=dict(resp.headers),
                            response_body_preview=body_preview, response_time_ms=elapsed,
                            check_name=f"AI batch: {reasoning[:80]}",
                        )
                    return {
                        "path": path, "method": method, "reasoning": reasoning,
                        "status": resp.status_code, "time_ms": elapsed,
                        "headers": dict(resp.headers), "body_preview": body_preview,
                        "body_length": len(resp.text) if resp.text else 0,
                    }
                except Exception as e:
                    return {"path": path, "method": method, "reasoning": reasoning, "error": str(e)}

            return await loop.run_in_executor(None, blocking)

        tasks = [do_one(r) for r in requests_list]
        return await asyncio.gather(*tasks)

    # ── Tool handlers ──

    async def _handle_make_requests(self, args):
        requests_list = args.get("requests", [])
        results = await self._execute_requests(requests_list)
        return json.dumps(results, default=str)

    def _handle_add_findings(self, args):
        findings = args.get("findings", [])
        for f in findings:
            endpoint = f.get("endpoint", "")
            method = f.get("method", "GET")
            # Auto-attach evidence from the most recent matching scan log
            evidence = f.get("evidence", {})
            if not evidence or not evidence.get("request_url"):
                evidence = self._find_matching_evidence(endpoint, method)
            finding = {
                "title": f.get('title', ''),
                "severity": f.get("severity", "info"),
                "category": f.get("category", "AI Deep Scan"),
                "description": f.get("description", ""),
                "endpoint": endpoint,
                "method": method,
                "evidence": evidence,
                "remediation": f.get("remediation", ""),
                "cvss_score": f.get("cvss_score", 0.0),
                "cwe_id": f.get("cwe_id", ""),
                "ai_analysis": f.get("ai_description") or f.get("description", ""),
            }
            if self.callbacks.get("on_finding"):
                self.callbacks["on_finding"](finding)
        return json.dumps({"reported": len(findings)})

    def _find_matching_evidence(self, endpoint: str, method: str) -> dict:
        """Find the most recent scan log matching the endpoint and method."""
        try:
            from redteam.database import get_scan_logs
            logs = get_scan_logs(self.campaign_id, limit=20, page=1)
            for log in logs.get("logs", []):
                log_endpoint = log.get("endpoint", "")
                log_method = log.get("method", "")
                # Normalize: strip base URL from endpoint
                if self.target in log_endpoint:
                    log_endpoint = log_endpoint.replace(self.target, "")
                if endpoint in log_endpoint or log_endpoint in endpoint:
                    if method.upper() == log_method.upper():
                        return {
                            "request_method": log_method,
                            "request_url": log.get("request_url", ""),
                            "request_headers": log.get("request_headers", "{}"),
                            "request_body": log.get("request_body", ""),
                            "response_status": log.get("response_status", 0),
                            "response_headers": log.get("response_headers", "{}"),
                            "response_body": log.get("response_body_preview", ""),
                        }
        except Exception:
            pass
        return {}

    # ── Prompt builders ──

    def _build_context_block(self):
        """All context injected directly — no read tools needed."""
        parts = []

        if self.description:
            parts.append(f"## Campaign description\n{self.description}\n")

        if self.findings_ref:
            parts.append(f"## Deterministic scan findings ({len(self.findings_ref)} total)\n")
            for f in self.findings_ref[:30]:
                parts.append(f"- [{f.get('severity','?')}] {f.get('title','')} | {f.get('endpoint','')} | {f.get('method','')}")
            parts.append("")

        if self.collection_requests:
            parts.append(f"## Collection requests ({len(self.collection_requests)} endpoints)\n")
            for r in self.collection_requests[:50]:
                url = r.get("url", "")[:80]
                parts.append(f"- {r.get('method','GET').upper()} {url} | name={r.get('name','?')}")
            parts.append("")

        if self.id_list:
            parts.append(f"## ID list for BOLA testing ({len(self.id_list)} users)\n```json\n{json.dumps(self.id_list, indent=2)}\n```\n")

        # Last 15 scan logs for context
        try:
            from redteam.database import get_scan_logs
            result = get_scan_logs(self.campaign_id, limit=15, page=1)
            logs = result.get("logs", []) if isinstance(result, dict) else (result or [])
            if logs:
                parts.append("## Recent scan logs\n")
                for l in logs:
                    parts.append(f"- {l.get('method','')} {l.get('endpoint','')} → {l.get('response_status','?')} | {(l.get('response_body_preview') or '')[:100]}")
                parts.append("")
        except Exception:
            pass

        return "\n".join(parts)

    # ── Main scan ──

    async def run(self):
        """Extensive AI deep scan — 20+ rounds: explore → analyze → probe deeper → verify → report."""
        ai_findings = []
        ai_tokens = {"prompt": 0, "completion": 0, "total": 0}

        # Spawn sandbox for bash tool
        spawn_result = self.bash_tool.spawn(self.target)
        if spawn_result.get("status") != "ok":
            msg = f"Sandbox unavailable — bash tool disabled ({spawn_result.get('detail', 'unknown error')})"
            _log.info(f"{msg}")
            if self.callbacks.get("on_progress"):
                self.callbacks["on_progress"](0, msg)
        orig_cb = self.callbacks.get("on_finding")
        def capture(f):
            ai_findings.append(f)
            if orig_cb:
                orig_cb(f)
        self.callbacks["on_finding"] = capture

        context = self._build_context_block()
        tools = _get_tools()

        self._aborted = False

        def _beat():
            if self.stop_check():
                self._aborted = True
                return True
            try:
                from redteam.scan_events import heartbeat
                heartbeat(self.campaign_id)
            except Exception:
                pass
            return False

        # ── Token accumulator ──
        def _add_tokens(resp):
            u = resp.get("usage") if isinstance(resp, dict) else None
            if u:
                ai_tokens["prompt"] += u.get("prompt_tokens", 0)
                ai_tokens["completion"] += u.get("completion_tokens", 0)
                ai_tokens["total"] += u.get("total_tokens", 0)

        # ── Shared helper: process tool calls from a response ──
        async def _process_tool_calls(msgs, resp):
            _add_tokens(resp)
            tc_raw = resp.get("tool_calls") or []
            # Also detect Qwen/LM Studio <tool_call> tags in text
            if not tc_raw:
                tc_raw = _extract_tool_calls_from_text(
                    (resp.get("content") or "") + (resp.get("reasoning_content") or "")
                )
            # Always save assistant message to maintain conversation structure
            msg = {"role": "assistant", "content": resp.get("content") or ""}
            reasoning = resp.get("reasoning_content")
            if reasoning:
                msg["reasoning_content"] = reasoning
            if tc_raw:
                msg["tool_calls"] = _format_tool_calls(tc_raw)
            msgs.append(msg)
            if not tc_raw:
                return False
            for t in tc_raw:
                try:
                    if isinstance(t, dict):
                        fn_name, fn_args, cid = t["function"]["name"], t["function"]["arguments"], t["id"]
                    else:
                        fn_name, fn_args, cid = t.function.name, t.function.arguments, t.id
                    args = json.loads(fn_args) if isinstance(fn_args, str) else fn_args
                except (json.JSONDecodeError, TypeError, KeyError, AttributeError) as e:
                    if self.callbacks.get("on_log"):
                        self.callbacks["on_log"](endpoint="AI Scanner", method="ERROR", request_url="",
                            response_status=0, response_body_preview=f"Tool call parse error: {e}",
                            response_time_ms=0, check_name="AI parse error")
                    continue
                result = await self._execute_tool(fn_name, args)
                msgs.append({"role": "tool", "tool_call_id": cid, "content": result})
            return True

        def _extract_tool_calls_from_text(text):
            """Extract tool calls from text in multiple formats.

            Handles:
              - Anthropic XML: <tool_call>{"name": "...", "arguments": {...}}</tool_call>
              - DeepSeek raw JSON: {"name": "...", "arguments": {...}}
            """
            if not text:
                return []
            calls = []
            seen_ids = set()

            def _add_call(name, args):
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except Exception:
                        pass
                key = (name, json.dumps(args, sort_keys=True) if isinstance(args, dict) else str(args))
                if key in seen_ids:
                    return
                seen_ids.add(key)
                cid = f"call_{len(calls)}"
                calls.append({"id": cid, "type": "function", "function": {"name": name, "arguments": json.dumps(args) if not isinstance(args, str) else args}})

            # ── Path A: <tool_call> XML tags (Anthropic / Qwen / LM Studio format) ──
            for m in re.finditer(r'<tool_call>\s*(.*?)\s*</tool_call>', text, re.DOTALL):
                try:
                    raw = m.group(1).strip()
                    data = json.loads(raw)
                    name = data.get("name", "")
                    args = data.get("arguments", {})
                    _add_call(name, args)
                except (json.JSONDecodeError, ValueError):
                    # Try repairing: truncate to last valid JSON position
                    try:
                        last_comma = raw.rfind('"}')
                        if last_comma > 100:
                            repaired = raw[:last_comma+2]
                            if not repaired.endswith(']}'):
                                repaired += ']}'
                            data = json.loads(repaired)
                            _add_call(data.get("name", ""), data.get("arguments", {}))
                    except (json.JSONDecodeError, ValueError):
                        pass
                    continue

            # ── Path B: {"name": "...", "arguments": {...}} — DeepSeek JSON format ──
            for m in re.finditer(r'"name"\s*:\s*"([^"]+)"', text):
                fn_name = m.group(1)
                pos = m.start()
                depth = 0
                obj_start = -1
                for i in range(pos, max(pos - 2000, -1), -1):
                    c = text[i]
                    if c == '}':
                        depth += 1
                    elif c == '{':
                        if depth == 0:
                            obj_start = i
                            break
                        depth -= 1
                if obj_start < 0:
                    continue
                depth = 0
                obj_end = -1
                in_str = False
                escaped = False
                for i in range(obj_start, min(len(text), obj_start + 8000)):
                    c = text[i]
                    if escaped:
                        escaped = False
                    elif c == '\\':
                        escaped = True
                    elif c == '"':
                        in_str = not in_str
                    elif not in_str:
                        if c == '{':
                            depth += 1
                        elif c == '}':
                            depth -= 1
                            if depth == 0:
                                obj_end = i + 1
                                break
                if obj_end < 0:
                    continue
                try:
                    candidate = text[obj_start:obj_end]
                    obj = json.loads(candidate)
                    if isinstance(obj, dict) and "arguments" in obj:
                        _add_call(obj.get("name", fn_name), obj.get("arguments", {}))
                except (json.JSONDecodeError, ValueError):
                    continue

            return calls

        # ══════════════════════════════════════════════════════════
        # PHASE 2 — Unified multi-round pentest conversation
        # Alternates between flash exploration rounds and pro analysis
        # ══════════════════════════════════════════════════════════

        system = {"role": "system", "content": f"""You are an expert API penetration testing agent with tool access.

TARGET: {self.target}
AUTH: {'Bearer token configured — make authenticated requests' if self.auth.get('bearer_token') else 'No auth configured'}
{context}

CRITICAL: You have SIX tools. MAXIMIZE every response — call MULTIPLE tools or batch commands.

TOOLS:
  pentest_make_requests — 5-15 parallel HTTP requests in one call. Your PRIMARY tool for API probing.
  pentest_quick_nuclei  — Fast vulnerability scan (optimized template set, 45s timeout)
  pentest_quick_nmap    — Top 9 web ports scan (80,443,8080,...,9090), open ports only
  pentest_quick_sqli    — Quick SQL injection scan (single URL, low intensity)
  pentest_quick_ffuf    — Fast API path fuzzing (api-endpoints wordlist)
  bash                  — 2-5 shell commands in batch. Use for: curl, python3 JWT, jq, dig, custom scripts
  pentest_add_findings  — Report confirmed vulnerabilities

50/50 RULE:
- After every batch of HTTP requests (pentest_make_requests), call bash OR a quick_* tool.
- After every bash/quick_* tool, call pentest_make_requests with 5-15 requests.
- NEVER call the same tool twice in a row without alternating.

BATCH RULES:
- bash ALWAYS runs 2-5 commands per call. Never use bash for a single command.
- pentest_make_requests ALWAYS makes 5-15 requests per call.
- pentest_add_findings ALWAYS reports 2-10 findings per call.

ABSOLUTE RULES:
- EVERY response MUST call at least ONE tool. Never text-only.
- If a tool returns empty/error/timeout, IMMEDIATELY fall back to pentest_make_requests. Do NOT retry the same tool.
- NEVER describe — CALL THE TOOL.
- ONLY report findings you have confirmed evidence for."""}

        msgs = [system]
        self.conversation = msgs[:]

        # ── Round templates: 3 categories rotated for 50/50 bash↔HTTP regardless of N ──
        BASH_ROUNDS = [
            "BASH RECON: Call bash with commands: ['nmap -sV -p 80,443,8080,8443,3000,5000,8000,9000 --open TARGET', 'curl -s -I https://TARGET', 'curl -s https://TARGET/robots.txt', 'curl -s https://TARGET/.well-known/security.txt', 'dig TARGET A +short']. Then call pentest_make_requests with 8 GET requests to /api, /admin, /docs, /graphql, /swagger, /.well-known/jwks.json, /api/v1, /api/health.",
            "BASH JWT + INJECTION: Call bash with commands: ['curl -s https://TARGET/.well-known/jwks.json | jq .', 'python3 -c \"import jwt,base64,sys; parts=sys.stdin.read().strip().split(\\\".\\\"); print(base64.urlsafe_b64decode(parts[1]+\\\"==\\\").decode())\" <<< YOUR_JWT', 'curl -s \"https://TARGET/api/users?id=1 OR 1=1--\"', 'curl -s \"https://TARGET/api/users?id=1'\\'' UNION SELECT 1,2,3--\"']. Then call pentest_make_requests with 8 SQLi/XSS payload requests.",
            "BASH DEEP RECON: Call bash with commands: ['curl -s https://crt.sh/?q=%25.TARGET_DOMAIN&output=json | python3 -c \"import sys,json; [print(c[\\'name_value\\']) for c in json.load(sys.stdin)[:30]]\"', 'dig TARGET_DOMAIN MX TXT NS +short', 'curl -s https://TARGET/sitemap.xml | head -30', 'ffuf -u TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200 -timeout 5 -s | head -15']. Then call pentest_make_requests with 8 requests to newly discovered paths.",
        ]
        QUICK_ROUNDS = [
            "SCAN + HTTP: Call pentest_quick_nuclei for TARGET. Then call pentest_make_requests with 10 requests probing .env, /actuator, /actuator/health, /debug, /console, /swagger-ui.html, /api-docs, /graphiql, /metrics, /status with GET method.",
            "FUZZ + SQLI: Call pentest_quick_ffuf with url TARGET/api/FUZZ. Then call pentest_quick_sqli on the 3 most promising endpoints found so far. Then call pentest_make_requests with 8 requests to ffuf-discovered paths.",
            "NMAP + HTTP: Call pentest_quick_nmap. Then call pentest_make_requests with 10 requests to any new ports discovered. Also retest all known endpoints with PUT, DELETE, PATCH methods.",
        ]
        HTTP_ROUNDS = [
            "HTTP MAP: Call pentest_make_requests with 15 requests: GET /api/users, POST /api/login, GET /api/me, GET /api/products, GET /api/orders, POST /api/orders, GET /api/admin/stats, GET /api/wallet, GET /api/health, GET /api/config, PUT /api/users/1, DELETE /api/orders/1, PATCH /api/users/1, POST /api/register, GET /api/teams.",
            "AUTH BYPASS: Call pentest_make_requests with 12 requests: test ALL known endpoints WITHOUT Authorization header. Add requests with Authorization: Bearer invalid, Bearer null, Bearer ' OR '1'='1. Test JWT alg:none bypass.",
            "BOLA/IDOR: Call pentest_make_requests with 15 requests: iterate user IDs 1-20 on /api/users/X, /api/orders/X, /api/wallet/X, /api/profile/X. Also test /api/teams/X with different team IDs. Use GET, PUT, DELETE for each.",
            "BUSINESS LOGIC: Call pentest_make_requests with 15 requests: POST /api/orders with quantity=-1, 0, 99999, price=0, price=-100. POST /api/wallet/transfer with amount=-1, 999999. POST /api/coupons with reuse. PUT /api/users/1 with role=admin, isAdmin=true.",
            "MASS ASSIGNMENT + LEAKS: Call pentest_make_requests with 15 requests: PATCH/PUT /api/users/X and /api/profile with role=admin, isAdmin=true, permissions=['admin'], verified=true, balance=99999. Check every response for API keys, tokens, passwords, PII, stack traces in headers and body.",
            "INJECTION SWEEP: Call pentest_make_requests with 15 requests: SQLi on all query params (' UNION SELECT, 1 OR 1=1, admin'--), XSS (<script>, <img onerror>, javascript:), path traversal (../../etc/passwd, ..%2f..%2f), SSTI ({{7*7}}, ${7*7}) on body and headers.",
            "SSRF + RACE: Call pentest_make_requests with 12 requests: test URL/webhook/callback params with http://169.254.169.254, http://metadata.google.internal, file:///etc/passwd, http://127.0.0.1:8000. Then 5 concurrent requests to state-changing endpoints (wallet transfer, order create, coupon redeem).",
            "EXPLOIT CHAIN + FINAL: Call bash with commands: ['curl -s -X POST https://TARGET/api/auth/login -H \"Content-Type: application/json\" -d \"{\\\"username\\\":\\\"admin\\\",\\\"password\\\":\\\"admin\\\"}\"', 'curl -s https://TARGET/api/admin -H \"Authorization: Bearer FORGED_TOKEN\"', 'python3 -c \"import jwt,datetime; print(jwt.encode({\\\"sub\\\":\\\"1\\\",\\\"role\\\":\\\"admin\\\",\\\"exp\\\":datetime.datetime.utcnow()+datetime.timedelta(days=1)}, key=\\\"secret\\\", algorithm=\\\"HS256\\\"))\"']. Then call pentest_make_requests with 10 requests chaining discovered exploits. Then call pentest_add_findings with 5-10 confirmed findings.",
        ]

        # Distribution pattern: alternates bash↔HTTP, produces ~40/20/40% (bash/quick/http)
        # regardless of how many rounds are configured
        DISTRIBUTION = [
            "BASH", "HTTP", "QUICK", "HTTP", "BASH", "HTTP", "BASH", "HTTP",
            "QUICK", "HTTP", "BASH", "HTTP", "HTTP", "QUICK", "HTTP",
            "BASH", "HTTP", "QUICK", "HTTP", "BASH", "HTTP", "BASH", "HTTP",
            "QUICK", "HTTP", "BASH", "HTTP", "HTTP", "QUICK", "HTTP",
        ]

        # Build rounds dynamically from the distribution pattern
        bash_idx = quick_idx = http_idx = 0
        exploration_prompts = []
        for i in range(self.explore_rounds):
            category = DISTRIBUTION[i % len(DISTRIBUTION)]
            if category == "BASH":
                prompt = BASH_ROUNDS[bash_idx % len(BASH_ROUNDS)]
                bash_idx += 1
            elif category == "QUICK":
                prompt = QUICK_ROUNDS[quick_idx % len(QUICK_ROUNDS)]
                quick_idx += 1
            else:
                prompt = HTTP_ROUNDS[http_idx % len(HTTP_ROUNDS)]
                http_idx += 1
            exploration_prompts.append(f"Round {i+1}: {prompt}")

        total_explore = len(exploration_prompts)
        total_analyze = self.analysis_rounds

        # ── Interleaved explore/analyze for progressive findings ──
        # Calculate: after how many explore rounds do we inject an analyze round?
        analysis_prompts = [
            "Analysis: Review results so far. Call pentest_add_findings for every CONFIRMED vulnerability. If you need verification, call pentest_make_requests with 1-5 targeted probes.",
            "Analysis: Continue deep analysis. Report high and medium severity findings. Probe suspicious responses. Look for chained vulnerabilities and patterns.",
            "Analysis: Deep dive on business logic and authorization. Review order/payment/cart, BOLA/IDOR, privilege escalation patterns. Report all confirmed findings.",
            "Analysis: Review auth findings. Confirm BOLA/IDOR cases. Verify mass assignment impact and auth bypass. Report everything confirmed.",
            "Analysis: Final sweep. Ensure every anomaly has been addressed. Report any remaining findings. Verification probes if needed. Leave no stone unturned.",
        ]

        explore_idx = 0
        analyze_idx = 0
        # Interleave: distribute analysis rounds evenly among exploration
        explore_per_analyze = max(1, total_explore // max(1, total_analyze))

        while explore_idx < total_explore or analyze_idx < total_analyze:
            # Run a batch of exploration rounds
            batch_end = min(explore_idx + explore_per_analyze, total_explore)
            for i in range(explore_idx, batch_end):
                prompt = exploration_prompts[i]
                msgs.append({"role": "user", "content": prompt})
                if _beat(): break
                try:
                    resp = self.flash.chat(msgs, tools=tools)
                    _add_tokens(resp)
                except Exception:
                    explore_idx = i + 1
                    continue
                if await _process_tool_calls(msgs, resp):
                    self.conversation = msgs[:]
                else:
                    # Force the model to call tools by providing an explicit example
                    msgs.append({"role": "user", "content": """You MUST call a tool NOW. Not text — a TOOL CALL.

pentest_make_requests example:
{"requests": [{"method": "GET", "path": "/api/users", "reasoning": "Enumerate users"}, {"method": "POST", "path": "/api/login", "reasoning": "Test default credentials", "body": "{\\"username\\":\\"admin\\",\\"password\\":\\"admin\\"}"}]}

bash example (2-5 commands):
{"commands": ["curl -s https://TARGET/api/health", "curl -s -I https://TARGET", "dig TARGET MX +short"]}

Make at least 5 HTTP requests or 3 bash commands NOW."""})
                    if _beat(): break
                    try:
                        resp = self.flash.chat(msgs, tools=tools)
                        _add_tokens(resp)
                        if not await _process_tool_calls(msgs, resp):
                            # Last resort: skip this round, model is uncooperative
                            msgs.append({"role": "user", "content": "Round skipped — no tool calls received. Next round will be more specific."})
                    except Exception:
                        pass
                if self.callbacks.get("on_progress"):
                    pct = int(60 + (i + 1) * 30 / total_explore)
                    self.callbacks["on_progress"](pct, f"AI explore round {i + 1}/{total_explore}")
            explore_idx = batch_end

            # Inject an analysis round
            if analyze_idx < total_analyze:
                if analyze_idx == 0:
                    msgs[0] = {"role": "system", "content": f"""You are a senior penetration tester. Analyze results and push findings.

TARGET: {self.target}
{context}

PHASED APPROACH — cycle through:
1. RECON with tools (bash nmap/curl/nuclei/sqlmap) → map the surface
2. HTTP probing (pentest_make_requests) → test business logic, BOLA, auth, injection
3. EXPLOIT with tools (bash sqlmap/nuclei/curl) → confirm and exploit weaknesses
4. ANALYSIS → pentest_add_findings for every confirmed vulnerability
5. REPEAT based on what you found — go deeper on anomalies

Each analysis round: call pentest_add_findings for CONFIRMED vulnerabilities. Call pentest_make_requests or bash if you need to verify. Report progressively — don't wait.

OWASP API TOP 10 COVERAGE — track your progress:
☐ API1 BOLA — Object-level auth on /api/{{resource}}/{{id}} endpoints
☐ API2 Broken Auth — JWT weaknesses, credential stuffing, token forgery
☐ API3 Mass Assignment — Adding role/isAdmin fields to PUT/PATCH
☐ API4 Resource Consumption — ReDoS, large payloads, pagination abuse
☐ API5 BFLA — Admin endpoints accessible to regular users
☐ API6 Business Logic — Negative values, coupon abuse, workflow bypass
☐ API7 SSRF — URL validation bypass, metadata endpoints
☐ API8 Misconfiguration — Verbose errors, CORS with credentials, security headers
☐ API9 Inventory — Old API versions, GraphQL, undocumented endpoints
☐ API10 Unsafe Consumption — Trusting third-party API responses

SUPPLEMENTARY:
☐ JWT Algorithm Confusion — RS256→HS256 downgrade via JWKS
☐ Race Conditions — Concurrent requests to state-changing endpoints
☐ GraphQL — Auth bypass, field suggestions, introspection leak
☐ Cache Poisoning — X-Forwarded-Host reflection, unkeyed headers
☐ BOLA via Batch — Per-item auth in bulk endpoints"""}
                msgs.append({"role": "user", "content": analysis_prompts[analyze_idx]})
                if _beat(): break
                try:
                    resp = self.pro.chat(msgs, tools=tools)
                    _add_tokens(resp)
                    if not await _process_tool_calls(msgs, resp):
                        msgs.append({"role": "user", "content": """CALL A TOOL NOW. If you have findings: call pentest_add_findings. If you need to verify: call pentest_make_requests. Example pentest_add_findings: {"findings":[{"title":"IDOR on /api/users","severity":"high","description":"Any user can access other users data by changing the ID","endpoint":"/api/users/{id}","method":"GET","ai_description":"IDOR allows horizontal privilege escalation. Attacker enumerates all user IDs."}]}"""})
                        if _beat(): break
                        try:
                            resp = self.pro.chat(msgs, tools=tools)
                            _add_tokens(resp)
                            await _process_tool_calls(msgs, resp)
                        except Exception:
                            pass
                except Exception:
                    pass
                if self.callbacks.get("on_progress"):
                    pct = int(90 + (analyze_idx + 1) * 10 / total_analyze)
                    self.callbacks["on_progress"](pct, f"AI analyze round {analyze_idx + 1}/{total_analyze}")
                analyze_idx += 1

        # ══════════════════════════════════════════════════════════
        # FINAL PASS — Blind spot sweep
        # ══════════════════════════════════════════════════════════
        if ai_findings:
            finding_titles = "\n".join(f"- [{f.get('severity','?')}] {f.get('title','')}" for f in ai_findings)
            cats_found = {f.get('category','') for f in ai_findings}
            cats_found_str = ", ".join(sorted(cats_found)) if cats_found else "none"
        else:
            finding_titles = "(no findings yet)"
            cats_found_str = "none"

        blind_spot_prompt = f"""FINAL BLIND SPOT SWEEP.

Your findings so far ({len(ai_findings)} total, categories: {cats_found_str}):
{finding_titles}

A human pentester would STILL check these — for each one, either confirm it's already covered OR make targeted probe requests NOW:

1. **JWT algorithm confusion**: Did you check if JWKS contains a symmetric key (kty:oct)? If yes, did you FORGE tokens with it and test them? This is the #1 missed vulnerability.
2. **GraphQL without auth**: Did you test /graphql with NO Authorization header at all? GraphQL endpoints often bypass REST middleware.
3. **Negative values**: Did you try negative numbers in ALL numeric fields — quantities, prices, amounts? Not just the obvious ones.
4. **Race conditions**: Did you send concurrent requests to state-changing endpoints? Two identical transfers at the same time?
5. **Cache poisoning**: Did you check if X-Forwarded-Host or Host headers are reflected in responses? If yes, can you poison links?
6. **Coupon/promo reuse**: Did you test if the same coupon can be used multiple times in concurrent requests?
7. **SSRF via parser differential**: If there's a URL validation endpoint, did you test URL parser bypasses (http://safe.com@127.0.0.1)?
8. **ReDoS in search**: If there's a search endpoint, did you test regex injection with exponential backtracking patterns?
9. **CORS with credentials**: Is Access-Control-Allow-Credentials:true set? If yes, every authenticated endpoint can be exploited cross-origin.
10. **Info disclosure in headers**: Do response headers leak Server, X-Powered-By, X-Auth-Method, or version numbers?
11. **Bulk endpoint IDOR**: If there's a bulk/batch endpoint, does it verify ownership for EACH item or just the first?

For every question above where the answer is NO or UNCERTAIN: call pentest_make_requests NOW with targeted probes. Then call pentest_add_findings for anything you confirm."""

        msgs.append({"role": "user", "content": blind_spot_prompt})
        if not self._aborted:
            try:
                resp = self.pro.chat(msgs, tools=tools)
                _add_tokens(resp)
                await _process_tool_calls(msgs, resp)
            except Exception:
                pass
        if self.callbacks.get("on_progress"):
            self.callbacks["on_progress"](98, "Final blind spot sweep")

        self.callbacks["on_finding"] = orig_cb
        self._cleanup_sandbox()
        return {"findings": ai_findings, "tokens": ai_tokens,
                "flash_model": self.flash_model,
                "pro_model": self.pro_model,
                "explore_rounds": self.explore_rounds, "analysis_rounds": self.analysis_rounds}

    TOOL_MAP = {
        "pentest_make_requests": "_handle_make_requests",
        "pentest_add_findings": "_handle_add_findings",
        "bash": "_handle_bash",
        "pentest_quick_nuclei": "_handle_quick_nuclei",
        "pentest_quick_nmap": "_handle_quick_nmap",
        "pentest_quick_sqli": "_handle_quick_sqli",
        "pentest_quick_ffuf": "_handle_quick_ffuf",
    }

    def _handle_quick_nuclei(self, args):
        url = args.get("url", self.target)
        sev = args.get("severity", "critical,high")
        cmd = f"nuclei -u {url} -t exposures/ -t misconfiguration/ -t vulnerabilities/ -severity {sev} -silent -timeout 8 -retries 1 2>&1 | head -30"
        return self._handle_bash({"commands": [cmd], "timeout_ms": 45000})

    def _handle_quick_nmap(self, args):
        target = args.get("target", self.target)
        cmd = f"nmap -sV -p 80,443,8080,8443,3000,5000,8000,9000,9090 --open {target} 2>&1"
        return self._handle_bash({"commands": [cmd], "timeout_ms": 30000})

    def _handle_quick_sqli(self, args):
        url = args.get("url", self.target)
        method = args.get("method", "GET")
        data = args.get("data", "")
        data_flag = f"--data='{data}'" if data and method == "POST" else ""
        cmd = f"sqlmap -u {url} --batch --level=1 --risk=1 --timeout=10 --answers='follow=N' {data_flag} 2>&1"
        return self._handle_bash({"commands": [cmd], "timeout_ms": 45000})

    def _handle_quick_ffuf(self, args):
        url = args.get("url", "")
        if not url:
            url = f"{self.target}/api/FUZZ"
        if "TARGET" in url:
            url = url.replace("TARGET", self.target)
        cmd = f"ffuf -u {url} -w /usr/share/seclists/Discovery/Web-Content/api-endpoints.txt -mc 200,401,403 -timeout 5 -s 2>&1 | head -20"
        return self._handle_bash({"commands": [cmd], "timeout_ms": 30000})

    async def _execute_tool(self, name, args):
        m = self.TOOL_MAP.get(name)
        if m:
            parsed = json.loads(args) if isinstance(args, str) else args
            fn = getattr(self, m)
            if asyncio.iscoroutinefunction(fn):
                return await fn(parsed)
            return fn(parsed)
        return json.dumps({"error": f"Unknown tool: {name}"})

    def _handle_bash(self, args):
        result_str = self.bash_tool.handle(args)
        try:
            result = json.loads(result_str)
            from redteam.database import add_bash_log
            if result.get("batch"):
                for r in result.get("results", []):
                    add_bash_log(
                        campaign_id=self.campaign_id,
                        command=r.get("command", ""),
                        exit_code=r.get("exit_code", -1),
                        stdout=r.get("stdout", ""),
                        stderr=r.get("stderr", ""),
                        elapsed_ms=r.get("elapsed_ms", 0),
                    )
            else:
                add_bash_log(
                    campaign_id=self.campaign_id,
                    command=args.get("command", args.get("commands", [""])[0] if args.get("commands") else ""),
                    exit_code=result.get("exit_code", -1),
                    stdout=result.get("stdout", ""),
                    stderr=result.get("stderr", ""),
                    elapsed_ms=result.get("elapsed_ms", 0),
                )
        except Exception:
            pass
        return result_str


def _format_tool_calls(raw):
    result = []
    for t in (raw or []):
        if isinstance(t, dict):
            result.append({"id": t.get("id", ""), "type": "function",
                "function": {"name": t["function"]["name"], "arguments": t["function"]["arguments"]}})
        else:
            result.append({"id": t.id, "type": "function",
                "function": {"name": t.function.name, "arguments": t.function.arguments}})
    return result
