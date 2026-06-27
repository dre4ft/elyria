# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Grey Team — AI OSINT Refiner (Phase 2).

Takes deterministic findings from Phase 1 and uses LLM to:
  1. Refine each finding with AI intelligence (exploitability, attack vector, priority)
  2. Correlate findings into attack chains
  3. Generate an executive summary

Uses Flash model for batch refinement, Pro model for correlation and summary.
Optionally uses the sandbox bash tool for passive OSINT verification commands.
"""

import json
import re
import os
import time
from pathlib import Path

from core.logging import get_logger

_log = get_logger("greyteam.refiner")


def _load_skill(name: str) -> str:
    try:
        from ai_core.skills_loader import load_agent_skill
        return load_agent_skill(name)
    except Exception:
        return ""


def _get_refiner_tools(has_sandbox: bool = False) -> list[dict]:
    tools = [
        {
            "type": "function",
            "function": {
                "name": "osint_refine_finding",
                "description": "Enrich a deterministic finding with AI intelligence. Add exploitability assessment, attack vector mapping, and remediation priority for THIS specific target context.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "finding_id": {
                            "type": "string",
                            "description": "Index of the finding to refine (0-based, from the findings list)",
                        },
                        "ai_description": {
                            "type": "string",
                            "description": "2-3 punchy sentences: what was found, why it matters for THIS target, and how an attacker would exploit it. Be specific to the target domain. Max 500 chars.",
                        },
                        "exploitability_score": {
                            "type": "integer", "minimum": 1, "maximum": 10,
                            "description": "1=trivial (public exploit, no skills needed), 5=moderate (some customization), 10=hard (requires significant R&D)",
                        },
                        "attack_vector": {
                            "type": "string",
                            "description": "How this fits into an attack. Use MITRE ATT&CK language where applicable (e.g., 'T1595 - Active Scanning', 'T1589 - Gather Victim Identity Information').",
                        },
                        "remediation_priority": {
                            "type": "string",
                            "enum": ["immediate", "short-term", "long-term", "informational"],
                            "description": "immediate=fix today, short-term=this sprint, long-term=roadmap, informational=no action needed",
                        },
                    },
                    "required": ["finding_id", "ai_description"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "osint_create_finding",
                "description": "Create a NEW finding discovered during AI analysis. Use this when you discover something the Phase 1 scanner missed — exposed services, misconfigurations, leaked data, suspicious patterns, or infrastructure issues you noticed during review.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "title": {
                            "type": "string",
                            "description": "Concise, descriptive title. e.g., 'Exposed Django debug mode on staging subdomain'",
                        },
                        "severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low", "info"],
                            "description": "Severity based on real-world exploitability for this target",
                        },
                        "category": {
                            "type": "string",
                            "description": "Category: DNS, WHOIS, SSL/TLS, HTTP Headers, Email, Exposed Service, Configuration, Data Leak, Infrastructure, etc.",
                        },
                        "description": {
                            "type": "string",
                            "description": "Detailed description: what was found, why it matters, how an attacker would exploit it. Max 800 chars.",
                        },
                        "evidence": {
                            "type": "string",
                            "description": "Evidence supporting this finding — command output, URL, observed behavior, data snippet. Max 500 chars.",
                        },
                        "remediation": {
                            "type": "string",
                            "description": "Actionable remediation steps. Max 400 chars.",
                        },
                        "cwe_id": {
                            "type": "string",
                            "description": "CWE ID if applicable (e.g., CWE-200, CWE-693, CWE-798)",
                        },
                    },
                    "required": ["title", "severity", "description", "evidence"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "osint_correlate_findings",
                "description": "Link multiple findings into an attack chain. Shows how an attacker combines individual weaknesses into a real attack path.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "finding_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                            "minItems": 2,
                            "description": "Indexes of findings that chain together (0-based)",
                        },
                        "chain_name": {
                            "type": "string",
                            "description": "Descriptive name, e.g., 'Subdomain Takeover via Expired DNS → Staging Server Access'",
                        },
                        "chain_description": {
                            "type": "string",
                            "description": "Step-by-step attack scenario: how the attacker moves from finding A to B to C. Be concrete. Max 800 chars.",
                        },
                        "overall_severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low", "info"],
                        },
                    },
                    "required": ["finding_ids", "chain_name", "chain_description", "overall_severity"],
                },
            },
        },
    ]

    if has_sandbox:
        tools.append({
            "type": "function",
            "function": {
                "name": "bash",
                "description": "Execute passive OSINT commands in the sandbox. Use for: dig, whois, curl to public APIs (crt.sh, archive.org, api.github.com), python3 for data processing, jq for JSON parsing. Use 'commands' array to run up to 5 commands sequentially. NEVER: nmap, sqlmap, ffuf, or any active scanning/fuzzing.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "Single shell command"},
                        "commands": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 5, "description": "Up to 5 commands sequentially"},
                        "timeout_ms": {"type": "integer", "description": "Timeout per command in ms (default 15000)"},
                    },
                    "required": [],
                },
            },
        })

    # Browser tool — always available
    tools.append({
        "type": "function",
        "function": {
            "name": "osint_browse",
            "description": "Browse a web page using a headless browser. Use to: inspect JS-rendered pages, check for exposed admin panels, verify website content, extract data from dynamic pages, read pages that curl can't render. Returns the page text content.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Full URL to browse (e.g., 'https://target.com/admin')"},
                    "selector": {"type": "string", "description": "CSS selector to extract specific content (e.g., 'body', '#content', '.results'). Default: 'body'"},
                    "reasoning": {"type": "string", "description": "What OSINT data are you looking for?"},
                },
                "required": ["url", "reasoning"],
            },
        },
    })

    # Search engine tool — always available
    tools.append({
        "type": "function",
        "function": {
            "name": "osint_search",
            "description": "Search the web for OSINT intelligence. Use for: finding leaked credentials, exposed documents, company tech stack mentions, employee info, news about security incidents. Similar to Google dorking but uses a real search engine.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query. Use dork syntax: site:target.com, filetype:pdf, intitle:admin, inurl:config. Example: 'site:example.com filetype:pdf confidential'"},
                    "reasoning": {"type": "string", "description": "What intelligence are you trying to gather?"},
                },
                "required": ["query", "reasoning"],
            },
        },
    })

    return tools


def _dump_debug_conversation(report_id: str, messages: list, tokens: dict,
                             refinements: int, created: int, chains: list):
    """Save the full AI conversation to a debug file for inspection."""
    try:
        from pathlib import Path
        debug_dir = Path("logs")
        debug_dir.mkdir(exist_ok=True)
        debug_path = debug_dir / f"greyteam_debug_{report_id}.json"

        # Sanitize messages: truncate large content fields
        sanitized = []
        for m in messages:
            sm = {"role": m.get("role", "?")}
            content = m.get("content", "")
            if isinstance(content, str) and len(content) > 2000:
                sm["content"] = content[:2000] + f"... [truncated, total {len(content)} chars]"
            else:
                sm["content"] = content

            if m.get("reasoning_content"):
                rc = m["reasoning_content"]
                sm["reasoning_content"] = rc[:500] + f"... [truncated, total {len(rc)} chars]" if len(rc) > 500 else rc

            if m.get("tool_calls"):
                # Summarize tool calls
                tc_summary = []
                for tc in m["tool_calls"]:
                    fn = tc.get("function", {})
                    tc_summary.append({
                        "name": fn.get("name", "?"),
                        "args": json.loads(fn.get("arguments", "{}")) if isinstance(fn.get("arguments"), str) else fn.get("arguments", {}),
                    })
                sm["tool_calls"] = tc_summary

            elif m.get("role") == "tool":
                content_s = sm.get("content", "")
                if isinstance(content_s, str) and len(content_s) > 1000:
                    sm["content"] = content_s[:1000] + f"... [truncated, total {len(content_s)} chars]"

            sanitized.append(sm)

        debug_data = {
            "report_id": report_id,
            "stats": {
                "refinements": refinements,
                "created": created,
                "chains": len(chains),
                "tokens": tokens,
            },
            "messages": sanitized,
        }

        with open(debug_path, "w", encoding="utf-8") as f:
            json.dump(debug_data, f, indent=2, ensure_ascii=False, default=str)

        _log.info(f"[greyteam] Debug conversation saved to {debug_path} ({len(sanitized)} messages)")
    except Exception as e:
        _log.warning(f"[greyteam] Failed to save debug conversation: {e}")


class AIOSINTRefiner:
    """Phase 2 — AI refinement of deterministic OSINT findings."""

    def __init__(self, report_id: str, domain: str, user_id: str,
                 deterministic_findings: list[dict] | None = None,
                 callbacks: dict | None = None, description: str = "",
                 rounds: int = 5, stop_check=None, bash_tool=None):
        self.report_id = report_id
        self.domain = domain
        self.user_id = user_id
        self.findings_ref = deterministic_findings or []
        self.callbacks = callbacks or {}
        self.rounds = max(2, min(10, int(rounds)))
        self.stop_check = stop_check or (lambda: False)
        self.description = description
        self.bash_tool = bash_tool
        self.conversation = []
        self._setup_providers()
        self._aborted = False

    def _setup_providers(self):
        from ai_core.ai_wrapper import AIWrapper
        from database.ai_config_mgmt import get_default_config
        from database.app_config import get_api_key

        def _resolve(slot, fallback_model):
            cfg = get_default_config(slot)
            _log.info(
                f"[greyteam] Resolving AI slot '{slot}': "
                f"found={cfg is not None}, "
                f"provider={cfg.get('provider_type', 'N/A') if cfg else 'N/A'}, "
                f"model={cfg.get('model', 'N/A') if cfg else 'N/A'}, "
                f"has_payload={bool(cfg.get('payload_encrypted', '')) if cfg else False}, "
                f"api_key_len={len(cfg.get('api_key', '')) if cfg else 0}"
            )
            if cfg:
                url = cfg["base_url"] or "https://api.openai.com/v1"
                api_key = cfg.get("api_key", "")
                provider_type = cfg.get("provider_type", "openai")
                if provider_type == "lmstudio":
                    url = url.rstrip("/").replace("/api/v1", "/v1")
                    if not url.endswith("/v1"):
                        url = url.rstrip("/") + "/v1"
                    if not api_key:
                        api_key = "not-needed"
                if not api_key:
                    api_key = get_api_key("openai_api_key")
                if not api_key:
                    _log.warning(
                        f"[greyteam] No API key for slot '{slot}' "
                        f"(provider={provider_type}). Set it in Hub > AI Agent "
                        f"or set OPENAI_API_KEY env var."
                    )
                    return None
                return {
                    "provider_type": provider_type, "url": url,
                    "api_key": api_key, "model": cfg["model"] or fallback_model,
                }
            api_key = get_api_key("openai_api_key")
            if not api_key:
                _log.warning(
                    f"[greyteam] No default AI config for slot '{slot}' "
                    f"and no OPENAI_API_KEY set."
                )
                return None
            return {
                "provider_type": "openai", "url": "https://api.openai.com/v1",
                "api_key": api_key, "model": fallback_model,
            }

        flash_cfg = _resolve("flash", "gpt-4o-mini")
        pro_cfg = _resolve("pro", "gpt-4o")

        if flash_cfg and pro_cfg:
            self.flash = AIWrapper(
                provider_type=flash_cfg["provider_type"], url=flash_cfg["url"],
                api_key=flash_cfg["api_key"], model=flash_cfg["model"],
            ).provider
            self.pro = AIWrapper(
                provider_type=pro_cfg["provider_type"], url=pro_cfg["url"],
                api_key=pro_cfg["api_key"], model=pro_cfg["model"],
            ).provider
            self.flash_model = flash_cfg["model"]
            self.pro_model = pro_cfg["model"]
        else:
            raise RuntimeError(
                "No AI providers configured for Grey Team — "
                "set up Flash and Pro models in Hub > AI Agent"
            )

    def _build_context_block(self) -> str:
        parts = [f"## Target Domain\n{self.domain}\n"]

        if self.description:
            parts.append(f"## Scan Description\n{self.description}\n")

        if self.findings_ref:
            parts.append(f"## Deterministic Findings ({len(self.findings_ref)} total)\n")
            # Group by category
            by_cat = {}
            for i, f in enumerate(self.findings_ref):
                cat = f.get("category", "Other")
                by_cat.setdefault(cat, []).append(i)

            for cat, idxs in sorted(by_cat.items()):
                parts.append(f"\n### {cat} ({len(idxs)} findings)")
                for idx in idxs[:8]:
                    f = self.findings_ref[idx]
                    parts.append(
                        f"{idx}. [{f.get('severity', '?')}] {f.get('title', '')}"
                    )
                if len(idxs) > 8:
                    parts.append(f"  ... and {len(idxs) - 8} more")

        return "\n".join(parts)

    def render(self) -> str:
        return self.chat({"role": "user", "content": self._build_context_block()})

    def _findings_summary_json(self) -> str:
        simplified = []
        for i, f in enumerate(self.findings_ref):
            simplified.append({
                "id": str(i),
                "title": f.get("title", ""),
                "severity": f.get("severity", "info"),
                "category": f.get("category", ""),
                "finding_type": f.get("finding_type", "osint"),
                "description": f.get("description", "")[:200],
                "evidence": f.get("evidence", "")[:300],
            })
        return json.dumps(simplified, indent=2, ensure_ascii=False)

    # ── Tool handlers ──

    def _handle_refine(self, args: dict) -> str:
        finding_id = args.get("finding_id", "")
        ai_desc = args.get("ai_description", "")

        # Find the finding
        finding = None
        try:
            idx = int(finding_id)
            if 0 <= idx < len(self.findings_ref):
                finding = self.findings_ref[idx]
        except (ValueError, TypeError):
            # Try matching by title
            for f in self.findings_ref:
                if f.get("title", "") == finding_id:
                    finding = f
                    break

        if not finding:
            return json.dumps({"error": f"Finding '{finding_id}' not found"})

        # Update the finding with AI intelligence
        finding["ai_description"] = ai_desc
        finding["exploitability_score"] = args.get("exploitability_score", 5)
        finding["attack_vector"] = args.get("attack_vector", "")
        finding["remediation_priority"] = args.get("remediation_priority", "informational")

        # Notify via callback
        if self.callbacks.get("on_refine"):
            self.callbacks["on_refine"](finding)

        return json.dumps({
            "refined": finding_id,
            "title": finding.get("title", ""),
            "exploitability": args.get("exploitability_score", 5),
            "priority": args.get("remediation_priority", "informational"),
        })

    def _handle_correlate(self, args: dict) -> str:
        finding_ids = args.get("finding_ids", [])
        chain_name = args.get("chain_name", "")
        chain_desc = args.get("chain_description", "")
        overall_sev = args.get("overall_severity", "medium")

        resolved = []
        for fid in finding_ids:
            try:
                idx = int(fid)
                if 0 <= idx < len(self.findings_ref):
                    resolved.append(self.findings_ref[idx].get("title", fid))
                else:
                    resolved.append(fid)
            except (ValueError, TypeError):
                resolved.append(fid)

        chain = {
            "finding_ids": finding_ids,
            "chain_name": chain_name,
            "chain_description": chain_desc,
            "overall_severity": overall_sev,
            "resolved_titles": resolved,
        }

        if self.callbacks.get("on_chain"):
            self.callbacks["on_chain"](chain)

        return json.dumps({
            "correlated": len(resolved),
            "chain": chain_name,
            "severity": overall_sev,
        })

    def _handle_bash(self, args: dict) -> str:
        if not self.bash_tool:
            return json.dumps({"error": "Sandbox bash tool not available"})

        blocked = ["nmap", "sqlmap", "ffuf", "nuclei", "msf", "metasploit",
                   "hydra", "medusa", "nc -", "netcat", "telnet"]

        def _check_blocked(cmd: str) -> str | None:
            cmd_lower = cmd.lower()
            for b in blocked:
                if b in cmd_lower:
                    return b
            return None

        # ── Batch mode — up to 5 commands run sequentially ──
        commands = args.get("commands", [])
        if commands:
            results = []
            for cmd in commands[:5]:
                blocked_tool = _check_blocked(cmd)
                if blocked_tool:
                    results.append({
                        "command": cmd[:200],
                        "exit_code": -1,
                        "stdout": "",
                        "stderr": f"Blocked: '{blocked_tool}' — grey team is PASSIVE only",
                    })
                else:
                    try:
                        r = json.loads(self.bash_tool.handle({
                            "command": cmd,
                            "timeout_ms": args.get("timeout_ms", 15000),
                        }))
                        results.append({
                            "command": cmd[:200],
                            "exit_code": r.get("exit_code", -1),
                            "stdout": r.get("stdout", "")[:3000],
                            "stderr": r.get("stderr", "")[:1000],
                            "elapsed_ms": r.get("elapsed_ms", 0),
                        })
                    except Exception as e:
                        results.append({
                            "command": cmd[:200],
                            "exit_code": -1,
                            "stdout": "",
                            "stderr": str(e)[:500],
                        })
            return json.dumps({"batch": True, "count": len(results), "results": results}, ensure_ascii=False)

        # ── Single command ──
        command = args.get("command", "")
        if not command:
            return json.dumps({"error": "No command or commands provided"})

        blocked_tool = _check_blocked(command)
        if blocked_tool:
            return json.dumps({
                "error": f"Active scanning tool '{blocked_tool}' blocked. Grey team is PASSIVE only.",
                "hint": "Use dig, whois, curl to public APIs, python3, or jq instead.",
            })
        try:
            result = self.bash_tool.handle({
                "command": command,
                "timeout_ms": args.get("timeout_ms", 15000),
            })
            return result
        except Exception as e:
            return json.dumps({"error": str(e)[:500]})

    def _handle_browse(self, args: dict) -> str:
        """Browse a URL using headless browser for OSINT reconnaissance."""
        try:
            from ely.browser import basic_handler
            url = args.get("url", "")
            if not url:
                return json.dumps({"error": "URL required"})
            output = basic_handler(self.user_id, url=url,
                                   selector=args.get("selector", "body"),
                                   action="query")
            return json.dumps({"status": 200, "url": url, "content": str(output)[:5000]})
        except Exception as e:
            return json.dumps({"error": f"Browser error: {str(e)[:300]}"})

    def _handle_search(self, args: dict) -> str:
        """Search the web for OSINT intelligence."""
        try:
            from ely.search_engine import search_engine
            query = args.get("query", "")
            if not query:
                return json.dumps({"error": "Search query required"})
            results = search_engine(query)
            if isinstance(results, list):
                preview = [{"title": r.get("title", ""), "snippet": r.get("snippet", ""), "url": r.get("url", "")}
                          for r in results[:8]]
            else:
                preview = str(results)[:3000]
            return json.dumps({"status": 200, "query": query, "results": preview})
        except Exception as e:
            return json.dumps({"error": f"Search error: {str(e)[:300]}"})

    def _handle_create_finding(self, args: dict) -> str:
        """Create a brand new finding from AI analysis."""
        new_finding = {
            "title": args.get("title", ""),
            "severity": args.get("severity", "medium"),
            "category": args.get("category", "OSINT"),
            "description": args.get("description", ""),
            "evidence": args.get("evidence", ""),
            "remediation": args.get("remediation", ""),
            "cwe_id": args.get("cwe_id", ""),
            "source": "ai",
            "finding_type": "osint",
            "ai_description": "",
            "file_path": "N/A",
            "line_number": 0,
        }

        # Notify via callback
        if self.callbacks.get("on_create_finding"):
            self.callbacks["on_create_finding"](new_finding)

        # Also add to ref findings so it can be referenced in chains
        self.findings_ref.append(new_finding)

        return json.dumps({
            "created": True,
            "title": args.get("title", ""),
            "severity": args.get("severity", "medium"),
            "index": len(self.findings_ref) - 1,
        })

    TOOL_MAP = {
        "osint_refine_finding": "_handle_refine",
        "osint_create_finding": "_handle_create_finding",
        "osint_correlate_findings": "_handle_correlate",
        "bash": "_handle_bash",
        "osint_browse": "_handle_browse",
        "osint_search": "_handle_search",
    }

    def _execute_tool(self, name: str, args) -> str:
        m = self.TOOL_MAP.get(name)
        if m:
            parsed = json.loads(args) if isinstance(args, str) else args
            # Log tool call (truncate large args)
            args_snip = json.dumps(parsed, ensure_ascii=False, default=str)
            if len(args_snip) > 300:
                args_snip = args_snip[:300] + "..."
            _log.info(f"[greyteam] TOOL CALL >>> {name}({args_snip})")
            fn = getattr(self, m)
            start = time.monotonic()
            result = fn(parsed)
            elapsed = int((time.monotonic() - start) * 1000)
            # Log result snippet
            result_snip = result[:300] if len(result) > 300 else result
            status = "OK" if '"error"' not in result[:100] else "ERROR"
            _log.info(f"[greyteam] TOOL RESULT <<< {name} [{status}] in {elapsed}ms: {result_snip}")
            return result
        _log.warning(f"[greyteam] TOOL UNKNOWN: {name}")
        return json.dumps({"error": f"Unknown tool: {name}"})

    # ── Main run ──

    def run(self) -> dict:
        ai_tokens = {"prompt": 0, "completion": 0, "total": 0}
        ai_refinements = 0
        ai_chains = []
        ai_created = 0

        orig_refine = self.callbacks.get("on_refine")

        def capture_refine(f):
            nonlocal ai_refinements
            ai_refinements += 1
            if orig_refine:
                orig_refine(f)

        self.callbacks["on_refine"] = capture_refine

        orig_chain = self.callbacks.get("on_chain")

        def capture_chain(c):
            ai_chains.append(c)
            if orig_chain:
                orig_chain(c)

        self.callbacks["on_chain"] = capture_chain

        orig_create = self.callbacks.get("on_create_finding")

        def capture_create(f):
            nonlocal ai_created
            ai_created += 1
            if orig_create:
                orig_create(f)

        self.callbacks["on_create_finding"] = capture_create

        context = self._build_context_block()
        findings_json = self._findings_summary_json()
        tools = _get_refiner_tools(has_sandbox=self.bash_tool is not None)
        self._aborted = False

        def _add_tokens(resp):
            u = resp.get("usage") if isinstance(resp, dict) else None
            if u:
                ai_tokens["prompt"] += u.get("prompt_tokens", 0)
                ai_tokens["completion"] += u.get("completion_tokens", 0)
                ai_tokens["total"] += u.get("total_tokens", 0)

        def _process_tool_calls(msgs, resp) -> bool:
            _add_tokens(resp)
            tc_raw = resp.get("tool_calls") or []
            content_text = resp.get("content") or ""
            reasoning_text = resp.get("reasoning_content") or ""
            _log.info(
                f"[greyteam] _process_tool_calls: native_tool_calls={len(tc_raw) if tc_raw else 0}, "
                f"content_len={len(content_text)}, reasoning_len={len(reasoning_text)}"
            )
            if not tc_raw:
                combined = content_text + reasoning_text
                tc_raw = _extract_tool_calls_from_text(combined)
                _log.info(
                    f"[greyteam] _process_tool_calls: text extraction found {len(tc_raw)} tool calls, "
                    f"combined_len={len(combined)}, "
                    f"snip={combined[-500:] if len(combined) > 500 else combined}"
                )
            msg = {"role": "assistant", "content": content_text}
            if reasoning_text:
                msg["reasoning_content"] = reasoning_text
            if tc_raw:
                msg["tool_calls"] = _format_tool_calls(tc_raw)
            msgs.append(msg)
            if not tc_raw:
                # Log the full response for debugging when no tool calls found
                _log.warning(
                    f"[greyteam] _process_tool_calls: NO tool calls extracted! "
                    f"content_head={content_text[:300]}, "
                    f"reasoning_head={reasoning_text[:300]}"
                )
                return False
            for t in tc_raw:
                try:
                    if isinstance(t, dict):
                        fn_name, fn_args, cid = (
                            t["function"]["name"],
                            t["function"]["arguments"],
                            t["id"],
                        )
                    else:
                        fn_name, fn_args, cid = (
                            t.function.name,
                            t.function.arguments,
                            t.id,
                        )
                    args = (
                        json.loads(fn_args)
                        if isinstance(fn_args, str)
                        else fn_args
                    )
                except (json.JSONDecodeError, TypeError, KeyError, AttributeError):
                    continue
                result = self._execute_tool(fn_name, args)
                msgs.append({"role": "tool", "tool_call_id": cid, "content": result})
            return True

        def _beat():
            if self.stop_check():
                self._aborted = True
                return True
            return False

        def _converse(msgs, provider, tools, max_turns=6):
            """Multi-turn conversation within a round. AI can call tools, see
            results, and continue until it gives a text-only response or max turns."""
            for _ in range(max_turns):
                if _beat():
                    break
                try:
                    resp = provider.chat(msgs, tools=tools)
                except Exception as e:
                    _log.error(f"[greyteam] Chat error in _converse: {e}")
                    break
                _add_tokens(resp)
                had_tools = _process_tool_calls(msgs, resp)
                if not had_tools:
                    break  # AI gave its final response for this round

        # ═══════════════════════════════════════════════════════
        # SYSTEM PROMPT
        # ═══════════════════════════════════════════════════════

        bash_block = ""
        if self.bash_tool:
            bash_block = "\n- bash: Execute PASSIVE OSINT commands (dig, whois, curl to public APIs, python3, jq). Up to 5 commands in batch. BLOCKED: nmap, sqlmap, ffuf, nuclei."

        system = {
            "role": "system",
            "content": f"""You are an expert OSINT analyst reviewing scan results for {self.domain}.

YOUR ROLE:
1. Review each deterministic finding and enrich it with AI intelligence via osint_refine_finding
2. Use osint_create_finding to ADD NEW findings you discover during analysis
3. Correlate findings into realistic attack chains via osint_correlate_findings
4. Use osint_browse to inspect web pages with a headless browser — check for exposed panels, verify content, read JS-rendered pages
5. Use osint_search to search the web for leaked credentials, exposed documents, company info, security incidents
{bash_block}

TOOLS:
- osint_refine_finding: Add exploitation context, attack vector, and priority to an existing finding
- osint_create_finding: Create a NEW finding you discovered during analysis
- osint_correlate_findings: Link multiple findings into attack chains
- osint_browse: Browse a URL with a headless browser. Use for JS-rendered pages, admin panels, content verification.
- osint_search: Search the web. Use dork syntax: site:target.com, filetype:pdf, intitle:admin, inurl:config.
- osint_correlate_findings: Chain 2+ findings into an attack scenario

RULES:
- Refine the most impactful findings first (critical/high, then medium). Skip pure info findings unless they chain into something bigger.
- CREATE new findings when you discover something the scanner missed — use bash to verify your suspicion first, then call osint_create_finding.
- For each refinement, provide a concrete, specific ai_description tied to THIS target ({self.domain}).
- Correlate at least 2-3 attack chains — think like an attacker.
- Use bash 'commands' array to run multiple passive lookups efficiently (e.g., dig + whois + crt.sh in one call).
{_load_skill("greyteam")}""",
        }

        msgs = [system]
        self.conversation = msgs[:]

        # ═══════════════════════════════════════════════════════
        # REFINEMENT ROUNDS
        # ═══════════════════════════════════════════════════════

        total_findings = len(self.findings_ref)
        if total_findings == 0:
            return {
                "findings": [],
                "chains": [],
                "refinements": 0,
                "tokens": ai_tokens,
                "flash_model": self.flash_model,
                "pro_model": self.pro_model,
            }

        # Round 1: Batch refine critical/high findings
        if any(f.get("severity") in ("critical", "high") for f in self.findings_ref):
            round1_prompt = f"""ROUND 1: Refine CRITICAL and HIGH severity findings.

Below is the full list of Phase 1 findings as JSON. For each finding with severity "critical" or "high", call osint_refine_finding with:
- A specific ai_description explaining what this means for {self.domain}
- An exploitability_score (1-10)
- A remediation_priority
- An attack_vector (MITRE ATT&CK if applicable)

Batch your calls — do 5-10 refine calls per response. Do NOT call anything for medium/low/info findings yet.

FINDINGS:
{findings_json}"""

            msgs.append({"role": "user", "content": round1_prompt})
            _converse(msgs, self.flash, tools)

            if self.callbacks.get("on_progress"):
                self.callbacks["on_progress"](91, "AI: refined critical/high findings")

        # Round 2: Refine medium findings + discover new ones
        round2_prompt = f"""ROUND 2: Research & Refine MEDIUM findings.

You have bash access to verify and enrich findings. Use this workflow:
1. FIRST: run passive OSINT commands (dig, whois, crt.sh, curl) to gather fresh data
2. THEN: based on results, call osint_refine_finding for impactful medium findings
3. ALSO: call osint_create_finding for anything NEW you discover (exposed subdomains, misconfigurations, etc.)

Take your time — do research, then refine/create. This is a multi-turn conversation."""

        msgs.append({"role": "user", "content": round2_prompt})
        _converse(msgs, self.flash, tools)

        if self.callbacks.get("on_progress"):
            self.callbacks["on_progress"](95, "AI: researched and refined findings")

        # Round 3: Correlate into attack chains (Pro model)
        round3_prompt = f"""ROUND 3: CORRELATE findings into attack chains.

Review ALL findings (including any you just created). Identify at least 2-3 groups that chain together into realistic attack scenarios for {self.domain}.

For each chain, call osint_correlate_findings with finding_ids, chain_name, chain_description, and overall_severity.

Findings for reference:
{findings_json[:3000]}"""

        msgs.append({"role": "user", "content": round3_prompt})
        _converse(msgs, self.pro, tools)

        if self.callbacks.get("on_progress"):
            self.callbacks["on_progress"](97, "AI: correlated attack chains")

        # Round 4: Final sweep
        round4_prompt = """ROUND 4: FINAL SWEEP.

Review the current state. Any findings still unrefined? Any additional chains or new discoveries? Use tools now. If everything is covered, respond with: "Refinement complete." """

        msgs.append({"role": "user", "content": round4_prompt})
        _converse(msgs, self.pro, tools)

        if self.callbacks.get("on_progress"):
            self.callbacks["on_progress"](99, "AI: final sweep")

        # Round 5: Executive summary (Pro model, no tools)
        summary_prompt = f"""ROUND 5: EXECUTIVE SUMMARY.

Write a concise executive summary of the OSINT assessment for {self.domain}. Format:

## Executive Summary
- **Overall risk level**: (Critical/High/Medium/Low) based on findings
- **Key risks**: 3-5 bullet points of the most important findings
- **Attack surface size**: Subdomains found, exposed services, email addresses, technologies
- **Top priorities**: What to fix first, in order
- **Recommendation**: Whether this domain is ready for production based on OSINT exposure

Keep it under 300 words. No tool calls needed."""

        msgs.append({"role": "user", "content": summary_prompt})
        summary = ""
        if not _beat():
            try:
                resp = self.pro.chat(msgs, tools=None)  # no tools for summary
                _add_tokens(resp)
                summary = resp.get("content", "") if isinstance(resp, dict) else str(resp)
            except Exception:
                pass

        self.callbacks["on_refine"] = orig_refine
        self.callbacks["on_chain"] = orig_chain
        self.callbacks["on_create_finding"] = orig_create

        # ── Dump full conversation to debug file ──
        _dump_debug_conversation(self.report_id, msgs, ai_tokens,
                                 ai_refinements, ai_created, ai_chains)

        return {
            "refinements": ai_refinements,
            "created": ai_created,
            "chains": ai_chains,
            "summary": summary,
            "tokens": ai_tokens,
            "flash_model": self.flash_model,
            "pro_model": self.pro_model,
        }


def _extract_tool_calls_from_text(text: str) -> list[dict]:
    """Extract tool calls from text in multiple formats.

    Handles:
      - Anthropic XML: <tool_call>{"name": "...", "arguments": {...}}</tool_call>
      - DeepSeek raw JSON: {"name": "...", "arguments": {...}}
      - Markdown code blocks: ```json {...} ```
    """
    if not text:
        return []
    calls = []
    seen_ids = set()  # dedup by (name, args_hash)

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
        calls.append({
            "id": cid, "type": "function",
            "function": {
                "name": name,
                "arguments": json.dumps(args) if not isinstance(args, str) else args,
            },
        })

    # ── Path A: <tool_call> XML tags (Anthropic format) ──
    for m in re.finditer(
        r'<tool_call>\s*(.*?)\s*</tool_call>', text, re.DOTALL
    ):
        try:
            raw = m.group(1).strip()
            data = json.loads(raw)
            _add_call(data.get("name", ""), data.get("arguments", {}))
        except (json.JSONDecodeError, ValueError):
            continue

    # ── Path B: {"name": "...", "arguments": {...}} — DeepSeek JSON format ──
    # Build a JSON-balance extractor
    for m in re.finditer(r'"name"\s*:\s*"([^"]+)"', text):
        fn_name = m.group(1)
        # Walk backwards to find opening brace
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
        # Walk forwards from pos to find closing brace
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


def _format_tool_calls(raw) -> list[dict]:
    result = []
    for t in raw or []:
        if isinstance(t, dict):
            result.append({
                "id": t.get("id", ""), "type": "function",
                "function": {
                    "name": t["function"]["name"],
                    "arguments": t["function"]["arguments"],
                },
            })
        else:
            result.append({
                "id": t.id, "type": "function",
                "function": {
                    "name": t.function.name,
                    "arguments": t.function.arguments,
                },
            })
    return result
