# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
AI-powered Purple Team scanner — deep code analysis with tool use.
Two-model architecture: Flash model for exploration, Pro model for analysis.
"""

import json
import os
import re
import time
import requests
from core.logging import get_logger
from database.ai_config_mgmt import get_default_config
from database.app_config import get_api_key
from ai_core.ai_wrapper import AIWrapper
from purpleteam.repo_manager import list_repo_files, detect_language, parse_dependencies

_log = get_logger("purpleteam.ai")


def _get_tools():
    return [
        {
            "type": "function",
            "function": {
                "name": "read_source_file",
                "description": "Read the content of a source file from the repository. Use to understand code structure, find vulnerabilities, and trace data flows.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string", "description": "Relative path to the source file"},
                        "reasoning": {"type": "string", "description": "Why are you reading this file? What vulnerability are you investigating?"},
                    },
                    "required": ["file_path", "reasoning"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "grep_codebase",
                "description": "Search the entire codebase for a pattern or keyword. Use to find all occurrences of a function, variable, import, or configuration.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "Regex or keyword to search for"},
                        "file_pattern": {"type": "string", "description": "Optional file pattern filter (e.g. '*.py', '*.java')"},
                        "reasoning": {"type": "string", "description": "What are you searching for and why?"},
                    },
                    "required": ["pattern", "reasoning"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "make_test_request",
                "description": "Send a test HTTP request to the target API endpoint. Use to validate suspected vulnerabilities.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]},
                        "path": {"type": "string", "description": "URL path (e.g. /api/users/1)"},
                        "headers": {"type": "object", "description": "Extra headers to send"},
                        "body": {"type": "string", "description": "Request body (JSON string)"},
                        "reasoning": {"type": "string", "description": "What vulnerability are you testing?"},
                    },
                    "required": ["method", "path", "reasoning"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "list_source_files",
                "description": "List all source files in the repository. Use to understand project structure and discover endpoints, controllers, models, etc.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "subdirectory": {"type": "string", "description": "Optional subdirectory to list"},
                    },
                    "required": [],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "submit_finding",
                "description": "Report a confirmed security vulnerability. Use AFTER investigating with read_source_file, grep_codebase, or make_test_request. Call this for EACH vulnerability you confirm.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "findings": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "title": {"type": "string", "description": "Concise title describing the vulnerability"},
                                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                                    "description": {"type": "string", "description": "What is the bug, why is it exploitable, what is the concrete impact (max 500 chars)"},
                                    "file_path": {"type": "string", "description": "Relative path to the affected file"},
                                    "line_number": {"type": "integer", "description": "Line number where the vulnerability is"},
                                    "remediation": {"type": "string", "description": "Specific fix recommendation"},
                                    "cwe_id": {"type": "string", "description": "CWE identifier (e.g. CWE-89, CWE-79)"},
                                    "cvss_score": {"type": "number", "description": "CVSS 3.1 base score (0.0-10.0)"},
                                },
                                "required": ["title", "severity", "description", "file_path"],
                            },
                            "minItems": 1,
                        },
                    },
                    "required": ["findings"],
                },
            },
        },
    ]


class AIPurpleScanner:
    def __init__(self, repo_path, target_endpoint="", user_id="", static_findings=None):
        self.repo_path = repo_path
        self.target_endpoint = target_endpoint
        self.user_id = user_id
        self.static_findings = static_findings or []
        self.language, self.framework = detect_language(repo_path)
        self._files = list_repo_files(repo_path)
        self._wrapper = None
        self._flash_model = ""
        self._pro_model = ""
        self._tokens = {"prompt": 0, "completion": 0, "total": 0}
        self._ai_findings = []
        self._session = requests.Session()
        self._session.timeout = 10

    def _setup_providers(self):
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
        self._flash = AIWrapper(provider_type=flash_cfg["provider_type"], url=flash_cfg["url"], api_key=flash_cfg["api_key"], model=flash_cfg["model"]).provider
        self._pro = AIWrapper(provider_type=pro_cfg["provider_type"], url=pro_cfg["url"], api_key=pro_cfg["api_key"], model=pro_cfg["model"]).provider
        self._flash_model = flash_cfg["model"]
        self._pro_model = pro_cfg["model"]

    # ── Tool handlers ──

    def _handle_read_source_file(self, args):
        file_path = args.get("file_path", "")
        if ".." in file_path or file_path.startswith("/"):
            return json.dumps({"error": "Invalid file path"})
        full_path = os.path.join(self.repo_path, file_path)
        if not os.path.isfile(full_path):
            return json.dumps({"error": f"File not found: {file_path}"})
        try:
            with open(full_path, "r", errors="replace") as f:
                content = f.read()[:10000]
            return json.dumps({"file_path": file_path, "content": content, "lines": content.count(chr(10)) + 1})
        except Exception as e:
            return json.dumps({"error": str(e)})

    def _handle_grep_codebase(self, args):
        pattern = args.get("pattern", "")
        file_pattern = args.get("file_pattern", "")
        results = []
        import re as _re
        try:
            pat = _re.compile(pattern, _re.IGNORECASE)
        except Exception:
            pat = _re.compile(_re.escape(pattern), _re.IGNORECASE)
        for f in self._files:
            if file_pattern:
                import fnmatch
                if not fnmatch.fnmatch(os.path.basename(f), file_pattern):
                    continue
            try:
                full_path = os.path.join(self.repo_path, f)
                with open(full_path, "r", errors="replace") as fh:
                    for i, line in enumerate(fh, 1):
                        if pat.search(line):
                            results.append({"file": f, "line": i, "content": line.strip()[:200]})
                            if len(results) >= 50:
                                break
                if len(results) >= 50:
                    break
            except Exception:
                pass
        return json.dumps({"matches": results[:50], "total": len(results)})

    def _handle_make_test_request(self, args):
        if not self.target_endpoint:
            return json.dumps({"error": "No target endpoint configured"})
        method = args.get("method", "GET")
        path = args.get("path", "/")
        headers = args.get("headers", {})
        body = args.get("body", "")
        try:
            from urllib.parse import urljoin
            url = urljoin(self.target_endpoint, path)
            resp = self._session.request(method, url, headers=headers, data=body, timeout=10)
            return json.dumps({
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body_preview": resp.text[:2000],
            })
        except Exception as e:
            return json.dumps({"error": str(e)})

    def _handle_list_source_files(self, args):
        subdir = args.get("subdirectory", "")
        files = self._files
        if subdir:
            files = [f for f in files if f.startswith(subdir)]
        return json.dumps({"files": files[:100], "total": len(files)})

    def _handle_submit_finding(self, args):
        """Handle the submit_finding tool — store findings directly."""
        findings_list = args.get("findings", [])
        _log.info(f"[AI:submit_finding] Called with {len(findings_list)} finding(s)")
        reported = 0
        for f in findings_list:
            title = f.get("title", "")
            if not title:
                continue
            _log.info(f"[AI:submit_finding] → [{f.get('severity','?')}] {title[:100]}")
            self._ai_findings.append({
                "title": f"[AI] {title}",
                "description": f.get("description", ""),
                "severity": f.get("severity", "medium"),
                "category": "ai_discovered",
                "file_path": f.get("file_path", ""),
                "line_number": f.get("line_number", 0),
                "evidence": f.get("evidence", {}),
                "remediation": f.get("remediation", ""),
                "cvss_score": f.get("cvss_score", 0.0),
                "cwe_id": f.get("cwe_id", ""),
            })
            reported += 1
        return json.dumps({"reported": reported})

    # ── Main scan loop ──

    def _run_phase(self, model, model_name, msgs, tools, tool_map, scan_id, add_finding_fn, max_rounds, phase_name, progress_cb, pct_start, pct_end):
        """Run a conversation phase: loop until model stops making tool calls."""
        MAX_TOOL_TURNS = 50
        turn = 0
        while turn < MAX_TOOL_TURNS:
            turn += 1
            if progress_cb:
                p = min(95, pct_start + int((turn / (max_rounds * 3)) * (pct_end - pct_start)))
                progress_cb(p, f"AI {phase_name} turn {turn}")

            _log.info(f"[AI:{phase_name}] Turn {turn} — sending {len(msgs)} msgs to {model_name}")
            resp = model.chat(msgs, tools=tools)
            self._tokens["prompt"] += (resp.get("usage") or {}).get("prompt_tokens", 0)
            self._tokens["completion"] += (resp.get("usage") or {}).get("completion_tokens", 0)
            self._tokens["total"] += (resp.get("usage") or {}).get("total_tokens", 0)

            content = resp.get("content", "") or ""
            reasoning = resp.get("reasoning_content", "") or ""
            tool_calls = resp.get("tool_calls")
            _log.info(f"[AI:{phase_name}] Turn {turn} response: content={len(content)}chars, reasoning={len(reasoning)}chars, tool_calls={len(tool_calls or [])}")
            if reasoning:
                _log.info(f"[AI:{phase_name}] Reasoning: {reasoning[:300]}")
            if content:
                _log.info(f"[AI:{phase_name}] Content: {content[:300]}")

            if not tool_calls:
                _log.info(f"[AI:{phase_name}] Model stopped making tool calls — phase complete")
                if content:
                    _log.info(f"[AI:{phase_name}] Final content: {content[:500]}")
                break

            if turn == 12:
                _log.info(f"[AI:{phase_name}] Nudging model to report findings after {turn} turns")
                msgs.append({"role": "user", "content": "You have gathered enough information. Now call submit_finding for each confirmed vulnerability you discovered. If you found none, state that explicitly."})

            normalized = _normalize_tool_calls(tool_calls)
            msgs.append({"role": "assistant", "content": content, "tool_calls": normalized})

            for tc in tool_calls:
                tc_id, tc_name, tc_args = _extract_tc_info(tc)
                _log.info(f"[AI:{phase_name}] Tool call: {tc_name}({tc_args[:200]})")
                handler = tool_map.get(tc_name)
                try:
                    args = json.loads(tc_args)
                    result = handler(args)
                    _log.info(f"[AI:{phase_name}] Tool result: {tc_name} → {len(result)} chars")
                except Exception as e:
                    result = json.dumps({"error": f"invalid arguments: {e}"})
                    _log.error(f"[AI:{phase_name}] Tool {tc_name} failed: {e}")
                msgs.append({"role": "tool", "tool_call_id": tc_id, "content": result})

    def run(self, scan_id, add_finding_fn, progress_cb=None, explore_rounds=15, analysis_rounds=5):
        self._setup_providers()
        self._ai_findings = []
        _log.info(f"[AI] Starting — flash={self._flash_model}, pro={self._pro_model}, "
                  f"repo={self.repo_path}, target={self.target_endpoint or 'none'}, "
                  f"files={len(self._files)}, static_findings={len(self.static_findings)}")
        tools = _get_tools()
        tool_map = {
            "read_source_file": self._handle_read_source_file,
            "grep_codebase": self._handle_grep_codebase,
            "make_test_request": self._handle_make_test_request,
            "list_source_files": self._handle_list_source_files,
            "submit_finding": self._handle_submit_finding,
        }

        deps = parse_dependencies(self.repo_path, self.language)
        dep_text = "\n".join(f"- {d['name']} @ {d.get('version', '?')}" for d in deps[:30]) or "(none)"
        static_text = "\n".join(
            f"- [{f['severity']}] {f['title']} ({f.get('file_path', '?')})"
            for f in self.static_findings[:30]
        ) or "(none)"

        system_prompt = f"""You are an expert application security engineer performing a Purple Team deep code review on a {self.language}/{self.framework} codebase.

**Static analysis already found:**
{static_text}

**Dependencies:** {len(deps)} packages detected.

**Your mission:** Find vulnerabilities the static scanner MISSED:
- Business logic flaws (auth bypass, privilege escalation, workflow abuse, race conditions)
- Injection points missed by regex (NoSQL injection, template injection, XPath, LDAP)
- Insecure framework defaults and misconfigurations
- Cryptographic weaknesses (weak keys, predictable RNG for security tokens)
- Authorization flaws (missing ownership checks, BOLA/IDOR, function-level auth gaps)
- Chained vulnerabilities (combine low-severity issues into high-impact exploits)
- Sensitive data leaks in logs, error messages, or debug output

**Method:** Use grep_codebase to find patterns, read_source_file to analyze suspicious code, make_test_request to validate exploitable endpoints, then call submit_finding for EACH vulnerability you confirm.

**IMPORTANT:** Call submit_finding EVERY TIME you find a real vulnerability. One call per finding. Be specific: include the exact file path, line number, CWE ID, and a CVSS score."""

        exploration_prompt = f"""Explore this {self.language}/{self.framework} codebase for security vulnerabilities:

1. List source files to map the project structure
2. Grep for high-risk patterns: exec(, eval(, os.system(, subprocess, pickle.load, yaml.load, requests.get(.*format, innerHTML, dangerouslySetInnerHTML, raw SQL with f-strings, hardcoded keys/secrets
3. Read key files: auth modules, database handlers, API routes, middleware, configuration
4. Trace data flow from user input to dangerous sinks
5. For every confirmed vulnerability, call submit_finding immediately"""

        analysis_prompt = f"""Deep-dive into the most critical areas:

1. **Authentication flow**: Read the auth module, check token validation, session management, password handling
2. **Authorization**: Check every endpoint for ownership verification — are users isolated? Can user A access user B's data?
3. **Input validation**: For every POST/PUT endpoint found, verify input is validated before reaching DB queries, file operations, or command execution
4. **Cryptography**: How are secrets stored? What RNG is used for tokens? What hash algorithm for passwords?
5. **Error handling**: Do error responses leak stack traces, SQL errors, or internal paths?
6. **Configuration**: Is DEBUG enabled? Are there default admin credentials? Exposed management endpoints?

For each confirmed vulnerability, call submit_finding with full details."""

        total_findings = 0

        # ── Phase 1: Flash exploration ──
        if self._flash_model and explore_rounds > 0:
            if progress_cb:
                progress_cb(10, "AI Phase 1: Exploring codebase...")
            try:
                msgs = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": exploration_prompt},
                ]
                self._run_phase(self._flash, self._flash_model, msgs, tools, tool_map,
                               scan_id, add_finding_fn, explore_rounds, "explore",
                               progress_cb, 10, 40)
            except Exception as e:
                _log.warning(f"Flash exploration failed: {e}")

        # ── Phase 2: Pro deep analysis ──
        if self._pro_model and analysis_rounds > 0:
            if progress_cb:
                progress_cb(45, "AI Phase 2: Deep analysis...")
            try:
                msgs = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": analysis_prompt},
                ]
                self._run_phase(self._pro, self._pro_model, msgs, tools, tool_map,
                               scan_id, add_finding_fn, analysis_rounds, "analysis",
                               progress_cb, 45, 85)
            except Exception as e:
                _log.warning(f"Pro analysis failed: {e}")

        # ── Save all AI findings to DB ──
        _log.info(f"[AI] Collected {len(self._ai_findings)} findings via submit_finding: "
                  f"{[f['title'][:60] for f in self._ai_findings]}")
        for f in self._ai_findings:
            add_finding_fn(
                scan_id=scan_id,
                title=f["title"],
                description=f["description"],
                severity=f["severity"],
                category=f.get("category", "ai_discovered"),
                file_path=f.get("file_path", ""),
                line_number=f.get("line_number", 0),
                evidence=f.get("evidence", {}),
                remediation=f.get("remediation", ""),
                cvss_score=f.get("cvss_score", 0.0),
                cwe_id=f.get("cwe_id", ""),
                ai_analysis=f.get("description", ""),
                finding_part="practices",
            )
            total_findings += 1

        if progress_cb:
            progress_cb(90, f"AI analysis complete ({total_findings} findings)")
        return total_findings

    def _parse_ai_findings(self, content):
        """Parse structured findings from AI response text."""
        findings = []
        # Find JSON blocks first
        import re
        json_blocks = re.findall(r'```(?:json)?\s*(\{.*?\})\s*```', content, re.DOTALL)
        for block in json_blocks:
            try:
                data = json.loads(block)
                if isinstance(data, dict):
                    finding = {
                        "title": f"[AI] {data.get('title', 'AI Finding')}",
                        "description": data.get("description", data.get("impact", "")),
                        "severity": data.get("severity", "medium"),
                        "category": data.get("category", data.get("cwe_id", "ai_discovered")),
                        "file_path": data.get("file_path", data.get("file", "")),
                        "line_number": data.get("line_number", data.get("line", 0)),
                        "evidence": data.get("evidence", {}),
                        "remediation": data.get("remediation", data.get("fix", "")),
                        "cvss_score": data.get("cvss_score", data.get("cvss", 0.0)),
                        "cwe_id": data.get("cwe_id", ""),
                    }
                    findings.append(finding)
            except json.JSONDecodeError:
                pass

        # Parse markdown-style finding sections
        sections = re.split(r'(?:^|\n)(?:#{1,3}\s*|(?:\*\*)?(?:Finding|Vulnerability|Issue)\s*(?:#?\d+|:)?)', content)
        for section in sections:
            title_match = re.search(r'(?:Title|Finding|Vulnerability)[:\s]*([^\n]+)', section, re.IGNORECASE)
            sev_match = re.search(r'severity[:\s]*(critical|high|medium|low|info)', section, re.IGNORECASE)
            desc_match = re.search(r'(?:description|details|impact)[:\s]*([^\n]+(?:\n[^\n#]+){0,5})', section, re.IGNORECASE)
            file_match = re.search(r'(?:file|path|location)[:\s]*([^\s\n]+)', section, re.IGNORECASE)
            cwe_match = re.search(r'(?:CWE|cwe)[:\s]*(\d{1,4})', section, re.IGNORECASE)

            if title_match and sev_match:
                finding = {
                    "title": f"[AI] {title_match.group(1).strip()[:120]}",
                    "severity": sev_match.group(1).lower(),
                    "description": desc_match.group(1).strip()[:500] if desc_match else section[:300],
                    "file_path": file_match.group(1) if file_match else "",
                    "cwe_id": f"CWE-{cwe_match.group(1)}" if cwe_match else "",
                    "category": "ai_discovered",
                    "evidence": {},
                    "remediation": "",
                    "cvss_score": 0.0,
                    "line_number": 0,
                }
                findings.append(finding)

        if not findings and len(content) > 50:
            # Fallback: create one finding from the analysis text
            for line in content.split("\n"):
                sev_match = re.search(r'(critical|high|medium|low|info)', line, re.IGNORECASE)
                if sev_match and len(line) > 20:
                    findings.append({
                        "title": f"[AI] {line.strip()[:120]}",
                        "severity": sev_match.group(1).lower(),
                        "description": content[:500],
                        "category": "ai_discovered",
                        "file_path": "",
                        "evidence": {},
                        "remediation": "",
                        "cvss_score": 0.0,
                        "cwe_id": "",
                        "line_number": 0,
                    })
                    break

        return findings

    def get_tokens(self):
        return self._tokens

    def get_models(self):
        return {"flash": self._flash_model, "pro": self._pro_model}


def _normalize_tool_calls(raw):
    """Convert tool calls from provider (may be objects or dicts) to dict format for msgs."""
    result = []
    for t in (raw or []):
        if isinstance(t, dict):
            result.append({
                "id": t.get("id", ""), "type": "function",
                "function": {"name": t["function"]["name"], "arguments": t["function"]["arguments"]},
            })
        else:
            result.append({
                "id": t.id, "type": "function",
                "function": {"name": t.function.name, "arguments": t.function.arguments},
            })
    return result


def _extract_tc_info(tc):
    """Extract (id, name, arguments) from a tool call (dict or object)."""
    if isinstance(tc, dict):
        return tc.get("id", ""), tc["function"]["name"], tc["function"]["arguments"]
    return tc.id, tc.function.name, tc.function.arguments
