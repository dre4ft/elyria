# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
AI-powered Purple Team scanner -- deep code analysis with tool use.
Two-model architecture: Flash model for exploration, Pro model for analysis.

Uses ai_core.shared_tools for common tool definitions (bash, browser, search,
code analysis, HTTP requests, findings) -- avoids redefining tools per team.
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
from ai_core.shared_tools import build_tool_set, handle_tool
from purpleteam.repo_manager import list_repo_files, detect_language

_log = get_logger("purpleteam.ai")


def _load_skill(name: str) -> str:
    try:
        from ai_core.skills_loader import load_agent_skill
        return load_agent_skill(name)
    except Exception:
        return ""


class AIPurpleScanner:
    def __init__(self, repo_path, target_endpoint="", user_id="", static_findings=None,
                 controllers=None, call_graph=None):
        self.repo_path = repo_path
        self.target_endpoint = target_endpoint
        self.user_id = user_id
        self.static_findings = static_findings or []
        self.controllers = controllers or []
        self.call_graph = call_graph or {}
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
                raise RuntimeError(f"No API key for slot '{slot}' -- set a default in /hub")
            return {"provider_type": "openai", "url": "https://api.openai.com/v1", "api_key": api_key, "model": fallback_model}

        flash_cfg = _resolve("flash", "gpt-4o-mini")
        pro_cfg = _resolve("pro", "gpt-4o")
        self._flash = AIWrapper(provider_type=flash_cfg["provider_type"], url=flash_cfg["url"], api_key=flash_cfg["api_key"], model=flash_cfg["model"]).provider
        self._pro = AIWrapper(provider_type=pro_cfg["provider_type"], url=pro_cfg["url"], api_key=pro_cfg["api_key"], model=pro_cfg["model"]).provider
        self._flash_model = flash_cfg["model"]
        self._pro_model = pro_cfg["model"]

    # ── Tool handlers ──

    def _handle_list_directory(self, args):
        subdir = args.get("subdirectory", "")
        # Security: prevent path traversal
        clean = subdir.replace("..", "").lstrip("/").lstrip("\\")
        target = os.path.join(self.repo_path, clean) if clean else self.repo_path
        if not os.path.isdir(target):
            return json.dumps({"error": f"Directory not found: {subdir}", "files": [], "dirs": []})
        try:
            entries = sorted(os.listdir(target))
            files = []
            dirs = []
            for e in entries:
                full = os.path.join(target, e)
                if e.startswith(".") or e in ("node_modules", "__pycache__", "venv", ".git", "target", "build", "dist"):
                    continue
                if os.path.isdir(full):
                    dirs.append(e + "/")
                elif os.path.isfile(full):
                    size = os.path.getsize(full)
                    files.append({"name": e, "size": size})
            # Limit to avoid huge listings
            return json.dumps({
                "path": clean or "/",
                "directories": dirs[:20],
                "files": files[:20],
                "total_entries": len(dirs) + len(files),
            })
        except Exception as e:
            return json.dumps({"error": str(e)})

    def _handle_read_source_file(self, args):
        file_path = args.get("file_path", "")
        if ".." in file_path or file_path.startswith("/"):
            return json.dumps({"error": "Invalid file path"})
        full_path = os.path.join(self.repo_path, file_path)
        if not os.path.isfile(full_path):
            return json.dumps({"error": f"File not found: {file_path}"})
        try:
            with open(full_path, "r", errors="replace") as f:
                content = f.read()[:2000]
            return json.dumps({"file_path": file_path, "content": content, "lines": content.count(chr(10)) + 1, "truncated": len(content) >= 2000})
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
                            if len(results) >= 10:
                                break
                if len(results) >= 10:
                    break
            except Exception:
                pass
        return json.dumps({"matches": results[:10], "total": len(results)})

    def _handle_make_test_request(self, args):
        if not self.target_endpoint:
            return json.dumps({"error": "No target endpoint configured", "exploitable": False})
        method = args.get("method", "GET")
        path = args.get("path", "/")
        headers = args.get("headers", {})
        body = args.get("body", "")
        reasoning = args.get("reasoning", "")
        try:
            from urllib.parse import urljoin
            url = urljoin(self.target_endpoint, path)
            req_kwargs = {"headers": headers, "timeout": 10, "allow_redirects": False}
            if body and method in ('POST', 'PUT', 'PATCH'):
                try:
                    req_kwargs["json"] = json.loads(body)
                except (json.JSONDecodeError, TypeError):
                    req_kwargs["data"] = body
            resp = self._session.request(method, url, **req_kwargs)
            resp_body = resp.text[:2000]
            # Detect vulnerability indicators
            indicators = []
            exploitable = False
            body_lower = resp_body.lower()
            if any(kw in body_lower for kw in ['sql', 'mysql', 'postgresql', 'syntax error', 'ora-']):
                indicators.append('possible_sql_error')
                exploitable = True
            if any(kw in body_lower for kw in ['traceback', 'stack trace', 'exception', 'at line']):
                indicators.append('error_disclosure')
                exploitable = True
            if any(kw in body_lower for kw in ['root:', 'daemon:', 'uid=', 'gid=']):
                indicators.append('possible_command_output')
                exploitable = True
            if resp.status_code == 200 and len(resp_body) > 100:
                indicators.append('data_returned')
            if resp.status_code == 500:
                indicators.append('server_error')
                exploitable = True
            return json.dumps({
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body_preview": resp_body,
                "body_length": len(resp.text),
                "exploitable": exploitable,
                "indicators": indicators,
                "attack_context": reasoning,
                "hint": "If exploitable=true, call submit_finding NOW with this request/response as evidence. If status=200 and you got data, test with other IDs/params for IDOR."
            })
        except Exception as e:
            return json.dumps({"error": str(e), "exploitable": False})

    def _handle_list_source_files(self, args):
        subdir = args.get("subdirectory", "")
        files = self._files
        if subdir:
            files = [f for f in files if f.startswith(subdir)]
        return json.dumps({"files": files[:100], "total": len(files)})

    def _handle_submit_finding(self, args):
        """Handle the submit_finding tool -- accepts BOTH formats:
        Batch: {"findings": [{"title": ..., "severity": ...}, ...]}
        Single: {"title": ..., "severity": ..., "description": ...}
        """
        # Accept both single and batch format
        if "findings" in args:
            findings_list = args["findings"]
        elif "title" in args:
            findings_list = [args]  # wrap single finding
        else:
            _log.warning(f"[AI:submit_finding] Unknown format: {json.dumps(args)[:200]}")
            return json.dumps({"reported": 0, "error": "No findings or title field"})

        _log.info(f"[AI:submit_finding] Called with {len(findings_list)} finding(s)")
        reported = 0
        for f in findings_list:
            title = f.get("title", "")
            if not title:
                continue
            _log.info(f"[AI:submit_finding] -> [{f.get('severity','?')}] {title[:100]}")
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
        return json.dumps({"reported": reported, "hint": "Finding stored. Continue with next vulnerability or call submit_finding again for more."})

    # ── Vulnerability briefs builder ──

    def _read_lines(self, file_path, line_number, before=10, after=10):
        """Read ±N lines around a specific line in a source file. Returns formatted string."""
        full_path = os.path.join(self.repo_path, file_path)
        if not os.path.isfile(full_path):
            return ""
        try:
            with open(full_path, "r", errors="replace") as f:
                lines = f.readlines()
            start = max(0, line_number - before - 1)
            end = min(len(lines), line_number + after)
            result = []
            for i in range(start, end):
                prefix = ">>>" if i == line_number - 1 else "   "
                result.append(f"{prefix} {i+1}: {lines[i].rstrip()}")
            return "\n".join(result)
        except Exception:
            return ""

    def _build_vuln_briefs(self):
        """Build compact vulnerability candidates from static findings + call graph sinks.
        Each candidate includes ±10 lines of surrounding code context (~100 tokens avg)."""
        candidates = {}  # (file_path, line_number) -> candidate dict

        for f in self.static_findings:
            fp = f.get("file_path", "")
            ln = f.get("line_number", 0)
            if not fp or not ln:
                continue
            key = (fp, ln)
            if key not in candidates:
                candidates[key] = {
                    "title": f.get("title", "Unknown"),
                    "severity": f.get("severity", "info"),
                    "file_path": fp,
                    "line_number": ln,
                    "cwe_id": f.get("cwe_id", ""),
                    "sink_type": f.get("category", ""),
                }

        for s in self.call_graph.get("sinks", []):
            fp = s.get("file", "")
            ln = s.get("line", 0)
            if not fp or not ln:
                continue
            key = (fp, ln)
            if key not in candidates:
                candidates[key] = {
                    "title": f"Sink: {s.get('type', 'unknown')}",
                    "severity": "medium",
                    "file_path": fp,
                    "line_number": ln,
                    "cwe_id": "",
                    "sink_type": s.get("type", ""),
                }

        briefs = []
        for i, (key, c) in enumerate(candidates.items()):
            fp, ln = key
            context = self._read_lines(fp, ln, before=10, after=10)
            if not context:
                continue
            sink_str = f" | {c['sink_type']}" if c.get("sink_type") else ""
            cwe_str = f" | {c['cwe_id']}" if c.get("cwe_id") else ""
            brief = (
                f"### Candidate {i+1}: {c['title'][:120]}{sink_str}\n"
                f"Severity: {c['severity']}{cwe_str} | File: {fp}:{ln}\n"
                f"```\n{context}\n```"
            )
            briefs.append(brief)

        return briefs

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

            _log.info(f"[AI:{phase_name}] Turn {turn} -- sending {len(msgs)} msgs to {model_name}")
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
                _log.info(f"[AI:{phase_name}] Model stopped making tool calls -- phase complete")
                if content:
                    _log.info(f"[AI:{phase_name}] Final content: {content[:500]}")
                break

            if turn == 8:
                _log.info(f"[AI:{phase_name}] Nudge: remind to submit findings")
                msgs.append({"role": "user", "content": "You've explored enough. STOP exploring and CALL submit_finding NOW for every vulnerability found. Use format: submit_finding(title=\"...\", severity=\"critical\", description=\"...\", file_path=\"...\", line_number=N)"})
            if turn == 15:
                _log.info(f"[AI:{phase_name}] Final nudge: force submit")
                msgs.append({"role": "user", "content": "FINAL REMINDER: You MUST call submit_finding before continuing. If you found SQL injection, hardcoded passwords, missing auth, or insecure deserialization -- REPORT THEM NOW with submit_finding(). Do not explore more files."})

            normalized = _normalize_tool_calls(tool_calls)
            msgs.append({"role": "assistant", "content": content, "tool_calls": normalized})

            for tc in tool_calls:
                tc_id, tc_name, tc_args = _extract_tc_info(tc)
                _log.info(f"[AI:{phase_name}] Tool call: {tc_name}({tc_args[:200]})")
                handler = tool_map.get(tc_name)
                try:
                    args = json.loads(tc_args)
                    result = handler(args)
                    _log.info(f"[AI:{phase_name}] Tool result: {tc_name} -> {len(result)} chars")
                except Exception as e:
                    result = json.dumps({"error": f"invalid arguments: {e}"})
                    _log.error(f"[AI:{phase_name}] Tool {tc_name} failed: {e}")
                msgs.append({"role": "tool", "tool_call_id": tc_id, "content": result})

    def run(self, scan_id, add_finding_fn, progress_cb=None, explore_rounds=15, analysis_rounds=5):
        self._setup_providers()
        self._ai_findings = []
        _log.info(f"[AI] Starting -- flash={self._flash_model}, pro={self._pro_model}, "
                  f"repo={self.repo_path}, target={self.target_endpoint or 'none'}, "
                  f"files={len(self._files)}, static_findings={len(self.static_findings)}")
        has_target = bool(self.target_endpoint)
        ctx = {
            "repo_path": self.repo_path,
            "target_endpoint": self.target_endpoint,
            "scan_id": scan_id,
            "add_finding_fn": add_finding_fn,
            "user_id": self.user_id,
        }
        # Understanding phase: code-only tools (no make_test_request)
        understand_tools, understand_tool_map = build_tool_set(
            ["list_directory", "read_source_file", "grep_codebase", "submit_finding"],
            **ctx,
        )
        # Override submit_finding to track findings in memory
        understand_tool_map["submit_finding"] = self._handle_submit_finding

        # Interactive phase: code tools + target testing
        interactive_tools, interactive_tool_map = [], {}
        if has_target:
            interactive_tools, interactive_tool_map = build_tool_set(
                ["list_directory", "read_source_file", "grep_codebase",
                 "submit_finding", "make_test_request"],
                **ctx,
            )
            interactive_tool_map["submit_finding"] = self._handle_submit_finding

        # Compact tech guidance — 2 lines max per framework
        tech_guidance = {
            ("python", "fastapi"): "Check Pydantic strictness, Depends() auth bypass, middleware order, path param type confusion.",
            ("python", "flask"): "Check SECRET_KEY hardness, @login_required gaps, Jinja2 autoescape, before_request bypass.",
            ("python", "django"): "Check DEBUG, ALLOWED_HOSTS, CSRF gaps, raw() queryset SQLi, FileField validation.",
            ("java", "spring"): "Check SecurityFilterChain gaps, @PreAuthorize bypass, actuator exposure, JPA native query SQLi.",
            ("javascript", "express"): "Check middleware order, helmet.js, req.params coercion, JWT verify() algorithm.",
            ("javascript", "nestjs"): "Check @Guards() ordering, class-validator gaps, GraphQL resolver auth, TypeORM raw queries.",
            ("go", "go"): "Check middleware chains, sqlx raw queries, template/html escaping, crypto/rand for tokens.",
            ("ruby", "rails"): "Check Strong Parameters, protect_from_forgery, AR SQLi via where(), devise config.",
            ("php", "laravel"): "Check Eloquent $guarded, debug mode, CSRF, raw DB::statement(), .env exposure.",
            ("php", "symfony"): "Check security.yaml firewalls, isGranted() gaps, Doctrine raw SQL, Twig autoescape.",
        }.get((self.language, self.framework), f"Focus on {self.language}-specific injection, auth, and misconfigurations.")

        has_target = bool(self.target_endpoint)

        # Compact system prompt — ~350 tokens vs ~2500 before
        system_prompt = f"""You are a security engineer auditing a {self.language}/{self.framework} codebase.
Tech guidance: {tech_guidance}

{"Live target: " + self.target_endpoint + " — use make_test_request to validate exploitability." if has_target else "SAST-only: no live target available."}

Your job: validate vulnerability candidates and report confirmed findings.

Report with submit_finding(title, severity, description, file_path, line_number, remediation, cwe_id, cvss_score).
severity: critical|high|medium|low|info
Include the vulnerable code snippet and exploitation evidence in description.
cwe_id format: "CWE-89"
cvss_score: float 0.0-10.0

{"For exploitable findings, FIRST call make_test_request with a payload, THEN submit_finding with the response as evidence." if has_target else ""}
{_load_skill("purpleteam")}"""

        # Compact understanding prompt — candidates are injected separately
        understanding_prompt = "Validate each vulnerability candidate below. For each one, read the surrounding code, trace the data flow, and call submit_finding if confirmed. Be precise about file paths and line numbers."

        # Phase 2: targeted exploitation — only sends confirmed findings
        interactive_prompt_template = """**Exploit confirmed findings on {target}**

For each finding below, send a test request with make_test_request to prove exploitability:
1. Craft a payload specific to the vulnerability type
2. Send the request to the appropriate endpoint
3. If exploitable, call submit_finding with the request/response as evidence

Findings to exploit:
{findings_list}"""

        total_findings = 0

        # ── Build vulnerability briefs from static findings + call graph sinks ──
        briefs = self._build_vuln_briefs()
        _log.info(f"[AI] Built {len(briefs)} vulnerability briefs from "
                  f"{len(self.static_findings)} static findings + "
                  f"{len(self.call_graph.get('sinks', []))} sinks")

        use_model = self._flash if self._flash_model else self._pro
        use_model_name = self._flash_model or self._pro_model
        has_model = bool(self._flash_model or self._pro_model)

        # ── Phase 1: Validate candidates in batches of 5 (fresh conversation each) ──
        batch_size = 5
        total_batches = (len(briefs) + batch_size - 1) // batch_size if briefs else 1

        if has_model and briefs:
            for batch_idx in range(total_batches):
                start = batch_idx * batch_size
                batch = briefs[start:start + batch_size]
                if not batch:
                    break

                pct_start = 10 + int(batch_idx / max(1, total_batches) * 55)
                pct_end = 10 + int((batch_idx + 1) / max(1, total_batches) * 55)
                if progress_cb:
                    progress_cb(pct_start, f"AI validating batch {batch_idx+1}/{total_batches}")

                batch_text = "\n\n".join(batch)
                user_msg = f"{understanding_prompt}\n\n**Vulnerability candidates to validate:**\n\n{batch_text}"

                msgs = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_msg},
                ]

                try:
                    self._run_phase(use_model, use_model_name, msgs, understand_tools,
                                   understand_tool_map, scan_id, add_finding_fn,
                                   max(3, explore_rounds // max(1, total_batches)),
                                   f"batch{batch_idx+1}", progress_cb, pct_start, pct_end)
                except Exception as e:
                    _log.warning(f"Batch {batch_idx+1}/{total_batches} failed: {e}")

            _log.info(f"[AI] Phase 1 done — {len(self._ai_findings)} findings collected across {total_batches} batches")
        elif has_model:
            # No briefs — fall back to free exploration
            if progress_cb:
                progress_cb(10, "AI exploring codebase...")
            try:
                msgs = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Explore this {self.language}/{self.framework} codebase and find vulnerabilities. Use list_directory to see the structure, grep_codebase for dangerous patterns (execute, eval, password, secret, token, Runtime.exec, readObject), read_source_file on suspicious files, and submit_finding for each vulnerability found."},
                ]
                self._run_phase(use_model, use_model_name, msgs, understand_tools,
                               understand_tool_map, scan_id, add_finding_fn,
                               explore_rounds, "explore", progress_cb, 10, 65)
            except Exception as e:
                _log.warning(f"Exploration phase failed: {e}")

        # ── Phase 2: Exploit confirmed findings on target (Pro model, minimal context) ──
        if self._pro_model and analysis_rounds > 0 and has_target and self._ai_findings:
            if progress_cb:
                progress_cb(70, "AI exploiting confirmed findings...")

            findings_list = "\n".join(
                f"- [{f['severity']}] {f['title']} ({f.get('file_path', '?')}:{f.get('line_number', 0)})"
                for f in self._ai_findings[:15]
            )

            exploit_system = system_prompt + (
                "\n\n**PHASE 2 — EXPLOITATION**: You now have make_test_request. "
                "For each finding below, prove exploitability by sending a test request. "
                "Submit confirmed exploits with the request/response as evidence. "
                "Do NOT explore more code — only test the findings listed below."
            )

            exploit_msg = interactive_prompt_template.format(
                target=self.target_endpoint,
                findings_list=findings_list,
            )

            try:
                msgs = [
                    {"role": "system", "content": exploit_system},
                    {"role": "user", "content": exploit_msg},
                ]
                self._run_phase(self._pro, self._pro_model, msgs, interactive_tools,
                               interactive_tool_map, scan_id, add_finding_fn,
                               analysis_rounds, "exploit", progress_cb, 70, 90)
            except Exception as e:
                _log.warning(f"Exploit phase failed: {e}")
        elif has_target and not self._ai_findings:
            _log.info("[AI] Skipping exploit phase — no findings to exploit")

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
