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
from strike.sandbox.tool import BashTool


import requests


# ═══════════════════════════════════════════════════════════════
# TOOLS — minimal set, data is injected in prompt not read via tools
# ═══════════════════════════════════════════════════════════════

def _get_tools():
    return [
        {
            "type": "function",
            "function": {
                "name": "pentest_make_requests",
                "description": "Make MULTIPLE HTTP requests to the target API in one call. Pass an array of requests — they run in parallel.",
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
                            "minItems": 1,
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
                    "Execute a command in the pentest sandbox. "
                    "Available tools: nmap, sqlmap, nuclei, ffuf, amass, subfinder, httpx, curl, "
                    "python3, jq, yq, go. "
                    "The sandbox has network access to the target. "
                    "Use this for reconnaissance, exploitation, fuzzing, and data extraction. "
                    "Chain multiple bash calls: enumerate → analyze → exploit → confirm."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "Shell command to execute in the sandbox. Examples: 'nmap -sV TARGET', 'sqlmap -u http://TARGET/api/users?id=1 --batch', 'nuclei -u http://TARGET -severity critical,high'",
                        },
                        "timeout_ms": {
                            "type": "integer",
                            "description": "Max execution time in milliseconds (default: 30000)",
                        },
                    },
                    "required": ["command"],
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
            finding = {
                "title": f.get('title', ''),
                "severity": f.get("severity", "info"),
                "category": f.get("category", "AI Deep Scan"),
                "description": f.get("description", ""),
                "endpoint": f.get("endpoint", ""),
                "method": f.get("method", "GET"),
                "evidence": f.get("evidence", {}),
                "remediation": f.get("remediation", ""),
                "cvss_score": f.get("cvss_score", 0.0),
                "cwe_id": f.get("cwe_id", ""),
                "ai_analysis": f.get("ai_description") or f.get("description", ""),
            }
            if self.callbacks.get("on_finding"):
                self.callbacks["on_finding"](finding)
        return json.dumps({"reported": len(findings)})

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
        try:
            self.bash_tool.spawn(self.target)
        except Exception as e:
            print(f"[AI_SCANNER] Sandbox spawn failed: {e} — bash tool disabled", flush=True)
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
            if not text:
                return []
            calls = []
            for m in re.finditer(r'<tool_call>\s*(.*?)\s*</tool_call>', text, re.DOTALL):
                try:
                    raw = m.group(1).strip()
                    data = json.loads(raw)
                    name = data.get("name", "")
                    args = data.get("arguments", {})
                    if isinstance(args, str):
                        try: args = json.loads(args)
                        except: pass
                    cid = f"call_{len(calls)}"
                    calls.append({"id": cid, "type": "function", "function": {"name": name, "arguments": json.dumps(args) if not isinstance(args, str) else args}})
                except (json.JSONDecodeError, ValueError) as e:
                    # Try repairing: truncate to last valid JSON position
                    try:
                        # Simple repair — find last complete object
                        last_comma = raw.rfind('"}')
                        if last_comma > 100:
                            repaired = raw[:last_comma+2]
                            if not repaired.endswith(']}'):
                                repaired += ']}'
                            data = json.loads(repaired)
                            name = data.get("name", "")
                            args = data.get("arguments", {})
                            if isinstance(args, str):
                                try: args = json.loads(args)
                                except: pass
                            cid = f"call_{len(calls)}"
                            calls.append({"id": cid, "type": "function", "function": {"name": name, "arguments": json.dumps(args) if not isinstance(args, str) else args}})
                    except (json.JSONDecodeError, ValueError):
                        pass
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

RULES:
- Call pentest_make_requests for ALL probing — batch 5-15 requests per call
- Call pentest_add_findings ONLY for CONFIRMED vulnerabilities with clear evidence
- Adapt your strategy based on results: if you find an anomaly, probe deeper
- Cover every attack vector: BOLA, business logic, privilege escalation, injection, auth bypass, mass assignment, SSRF, sensitive data exposure
- Never describe what you would do — actually DO it by calling tools"""}

        msgs = [system]
        self.conversation = msgs[:]

        # ── Rounds 1-15: Exploration with flash (fast, no reasoning) ──
        exploration_prompts = [
            "Round 1: Reconnaissance. Make 10-15 requests to map the API surface. Test all collection endpoints with baseline requests. Probe for admin endpoints, old API versions, and hidden paths. Specifically check: /.well-known/jwks.json, /.well-known/openid-configuration, /api/docs, /graphql, /actuator, /.env, /debug.",
            "Round 2: Authorization. Test BOLA/IDOR by substituting IDs from the ID list into collection request paths, query params, and bodies. Try accessing admin endpoints with regular user tokens. Test WITHOUT auth headers entirely — many APIs have GraphQL or webhook endpoints that bypass middleware.",
            "Round 3: Business logic. Test order/payment/cart endpoints with negative prices, zero quantities, and large discounts. Try coupon codes like WELCOME10, VIP50, FREE100. Test for workflow bypass — can you skip steps? Test for negative quantity arbitrage (buy -1 items = refund).",
            "Round 4: Injection. Test query params and body fields with SQL injection, XSS, path traversal, and template injection payloads. Look for error messages leaking info. Test regex injection in search/filter endpoints — send exponential patterns like '(a+)+$' to trigger ReDoS.",
            "Round 5: Authentication + JWT. Test without auth headers, with invalid tokens, with expired tokens. Fetch /.well-known/jwks.json — look for symmetric keys (kty:oct) alongside RSA keys. If both RS256 and HS256 exist, forge tokens with the exposed HMAC secret. Test alg:none, alg:HS256 with public key as secret. Test kid injection.",
            "Round 6: Mass assignment & property auth. PUT/PATCH user/account endpoints adding role=admin, isAdmin=true fields. Try adding sensitive fields to request bodies. Test if PATCH allows partial updates that bypass validation.",
            "Round 7: HTTP method abuse. Test DELETE, PUT, PATCH, OPTIONS, TRACE on every collection endpoint. Look for methods that should be blocked but aren't. Test POST to GET-only endpoints with override headers (X-HTTP-Method-Override).",
            "Round 8: Header manipulation. Test with malformed Content-Type, SQLi in User-Agent, extremely large headers, duplicate headers, missing required headers. Test X-Forwarded-Host reflection — if it appears in response bodies/links, you have cache poisoning.",
            "Round 9: Rate limiting & resource consumption. Make many rapid requests. Test with large payloads, deep nesting in JSON, pagination abuse (limit=999999). Test GraphQL with deeply nested queries for DoS.",
            "Round 10: Sensitive data. Check every response for API keys, tokens, passwords, PII. Test error responses for stack traces. Check .env and config endpoints. Check response headers — Server, X-Powered-By, X-Auth-Method leak version info for CVE matching.",
            "Round 11: API versioning. Test /v1/, /v2/, /api/v1/, /api/v2/ variants of collection endpoints. Old versions often have fewer security controls. Test deprecated endpoints mentioned in docs.",
            "Round 12: Content-type & parsing. Send XML, HTML, form-encoded to JSON endpoints. Send oversized JSON, deeply nested objects, duplicate keys. Test if duplicate query params are handled inconsistently (param pollution).",
            "Round 13: Race conditions. Identify ALL state-changing endpoints (order creation, transfers, coupon redemption). Send 5 identical concurrent requests in ONE pentest_make_requests call. Check for duplicate orders, double transfers. If you got balance/credit info, try concurrent spends.",
            "Round 14: JWT deep dive + chaining. If JWKS exists, decode the token (jwt.io). If symmetric key found, FORGE tokens for admin users and test them. Then use forged admin token to access every endpoint. Chain JWT forge → IDOR → business logic. Report the full kill chain.",
            "Round 15: Blind spot sweep. Review ALL responses from ALL previous rounds. Look for: CORS with Access-Control-Allow-Credentials:true (enables cross-origin auth theft), Cache-Control headers (missing = cache poisoning), GraphQL endpoints (test without auth), webhook/SSRF endpoints, coupon reuse, negative values that passed validation. Probe anything you haven't tested yet.",
        ]

        # Use configured rounds (capped in __init__)
        exploration_prompts = exploration_prompts[:self.explore_rounds]
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
                    msgs.append({"role": "user", "content": "You MUST call tools. Make at least 5 requests with pentest_make_requests."})
                    if _beat(): break
                    try:
                        resp = self.flash.chat(msgs, tools=tools)
                        _add_tokens(resp)
                        await _process_tool_calls(msgs, resp)
                    except Exception:
                        pass
                if self.callbacks.get("on_progress"):
                    pct = int(60 + (i + 1) * 30 / total_explore)
                    self.callbacks["on_progress"](pct, f"AI explore round {i + 1}/{total_explore}")
            explore_idx = batch_end

            # Inject an analysis round
            if analyze_idx < total_analyze:
                if analyze_idx == 0:
                    msgs[0] = {"role": "system", "content": f"""You are a senior penetration tester. Analyze results and report findings.

TARGET: {self.target}
{context}

Each analysis round: review the exploration data above. Call pentest_add_findings for CONFIRMED vulnerabilities. Call pentest_make_requests if you need to verify something. Report progressively — don't wait.

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
                        msgs.append({"role": "user", "content": "Call pentest_add_findings for every vulnerability you identified. Verify with pentest_make_requests if needed."})
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
    }

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
        # Log bash execution to scan logs
        try:
            result = json.loads(result_str)
            from redteam.database import add_bash_log
            add_bash_log(
                campaign_id=self.campaign_id,
                command=args.get("command", ""),
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
