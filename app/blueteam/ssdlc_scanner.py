"""
Blue Team SSDLC Scanner — Security-by-design analysis agent.
Multi-round analysis → comprehensive security requirements report.
"""

import json

import time
from urllib.parse import urljoin


class SSDLCAnalyzer:
    """Expert security analyst that reviews API specs and documentation
    through a security-by-design lens, then produces a comprehensive
    SSDLC requirements report."""

    def __init__(self, target_url, user_id, master_prompt="", documentation="",
                 openapi_spec="", collection_requests=None, callbacks=None,
                 analysis_rounds=8, report_rounds=5):
        self.target = target_url.rstrip("/")
        self.user_id = user_id
        self.master_prompt = master_prompt
        self.documentation = documentation
        self.openapi_spec = openapi_spec
        self.collection_requests = collection_requests or []
        self.callbacks = callbacks or {}
        self.analysis_rounds = max(3, min(20, int(analysis_rounds)))
        self.report_rounds = max(3, min(10, int(report_rounds)))
        self._setup_provider()

    def _setup_provider(self):
        from ai_core.ai_wrapper import AIWrapper
        from database.ai_config_mgmt import get_default_config
        from database.app_config import get_api_key

        cfg = get_default_config("pro")
        if cfg:
            url = cfg["base_url"] or "https://api.openai.com/v1"
            api_key = cfg.get("api_key", "")
            model = cfg.get("model") or "gpt-4o"
            if cfg["provider_type"] == "lmstudio":
                url = url.rstrip("/").replace("/api/v1", "/v1")
                if not url.endswith("/v1"):
                    url = url.rstrip("/") + "/v1"
                if not api_key:
                    api_key = "not-needed"
            if not api_key:
                api_key = get_api_key("openai_api_key")
            provider_type = cfg["provider_type"]
        else:
            api_key = get_api_key("openai_api_key")
            if not api_key:
                raise RuntimeError("No API key for 'pro' slot — set a default in /hub")
            url = "https://api.openai.com/v1"
            model = "gpt-4o"
            provider_type = "openai"

        wrapper = AIWrapper(provider_type=provider_type, url=url, api_key=api_key, model=model)
        self.pro = wrapper.provider
        self.pro_model = model

    def _build_context(self):
        parts = []

        if self.master_prompt:
            parts.append(f"## MASTER PROMPT (prioritaire)\n{self.master_prompt}\n")

        parts.append(f"## Cible analysee\nURL: {self.target}\n")

        if self.openapi_spec:
            spec = self.openapi_spec[:10000] if len(self.openapi_spec) > 10000 else self.openapi_spec
            parts.append(f"## Specification OpenAPI\n```\n{spec}\n```\n")
            if len(self.openapi_spec) > 10000:
                parts.append("(spec tronquee a 10000 caracteres)\n")

        if self.documentation:
            doc = self.documentation[:8000] if len(self.documentation) > 8000 else self.documentation
            parts.append(f"## Documentation fournie\n{doc}\n")
            if len(self.documentation) > 8000:
                parts.append("(documentation tronquee a 8000 caracteres)\n")

        if self.collection_requests:
            parts.append(f"## Collection d'endpoints ({len(self.collection_requests)} endpoints)\n")
            for r in self.collection_requests[:60]:
                url = r.get("url", "")[:80]
                parts.append(f"- {r.get('method','GET').upper()} {url} | name={r.get('name','?')}")
            parts.append("")

        return "\n".join(parts)

    def run(self):
        print(f"[BLUETEAM] Starting SSDLC analysis — target: {self.target}", flush=True)
        print(f"[BLUETEAM] Analysis rounds: {self.analysis_rounds}, Report rounds: {self.report_rounds}", flush=True)
        print(f"[BLUETEAM] Pro model: {self.pro_model}", flush=True)

        context = self._build_context()
        ai_tokens = {"total": 0}

        def _add_tokens(resp):
            u = resp.get("usage") if isinstance(resp, dict) else None
            if u:
                ai_tokens["total"] += u.get("total_tokens", 0)

        def _beat():
            try:
                from pentest.scan_events import heartbeat
                heartbeat("blueteam")
            except Exception:
                pass

        def _progress(pct, msg):
            print(f"[BLUETEAM] Progress {pct}% — {msg}", flush=True)
            if self.callbacks.get("on_progress"):
                self.callbacks["on_progress"](pct, msg)

        # ═══════════════════════════════════════
        # PHASE 1 — Multi-round Security Analysis
        # ═══════════════════════════════════════
        print(f"[BLUETEAM] Phase 1 — Starting {self.analysis_rounds} analysis rounds...", flush=True)

        system = {"role": "system", "content": f"""You are an EXPERT SSDLC (Secure Software Development Lifecycle) security architect. You analyze API specifications and documentation through a security-by-design lens.

{context}

YOUR ROLE:
- You are a DEFENSIVE security expert — identify weaknesses BEFORE they become vulnerabilities
- Apply OWASP ASVS (Application Security Verification Standard) v4.0+
- Apply OWASP API Security Top 10 mitigations
- Apply NIST SP 800-53 / ISO 27001 control frameworks
- Think like an attacker to anticipate threats, then design defenses
- Every finding must include a concrete security requirement

ANALYSIS FRAMEWORK:
1. Authentication & Authorization architecture
2. Data protection (transit, at rest, processing)
3. Input validation & output encoding
4. API design patterns (rate limiting, versioning, deprecation)
5. Error handling & logging
6. Dependency & supply chain security
7. Infrastructure & deployment security
8. Compliance & regulatory requirements"""}

        msgs = [system]

        analysis_prompts = [
            "Round 1: Authentication & Authorization. Analyze the auth model. Is it OAuth2/OIDC? JWT? API keys? Identify weaknesses in token handling, session management, and privilege separation. Map all roles and their access levels. Identify missing auth on sensitive endpoints.",
            "Round 2: Data Protection. Analyze how data flows through the API. Which data is PII? How is it protected in transit (TLS), at rest (encryption), and during processing? Identify data leakage risks, excessive data exposure, and missing encryption.",
            "Round 3: Input Validation & Injection. Review all request parameters, headers, and body schemas. Identify missing validation, type coercion risks, mass assignment vectors, and injection surfaces (SQL, NoSQL, XSS, SSTI, path traversal). Check content-type handling.",
            "Round 4: API Architecture. Analyze rate limiting, versioning strategy, deprecation policy, CORS configuration, security headers (HSTS, CSP, X-Frame-Options). Identify missing security headers, overly permissive CORS, and resource exhaustion risks.",
            "Round 5: Error Handling & Logging. Review error responses for information leakage (stack traces, DB errors, internal paths). Analyze logging strategy — are security events logged? Is sensitive data redacted from logs?",
            "Round 6: Business Logic & Workflows. Trace multi-step flows (registration, payment, checkout). Identify race conditions, workflow bypass opportunities, and abuse cases. Check idempotency on state-changing operations.",
            "Round 7: Supply Chain & Dependencies. Based on the tech stack implied by the API design, identify dependency risks. Are there known-vulnerable patterns? Check for hardcoded credentials, unsafe defaults, and insecure third-party integrations.",
            "Round 8: Compliance & Governance. Map findings to compliance frameworks (GDPR, PCI-DSS, SOC2, HIPAA as applicable). Identify audit logging gaps, data retention issues, and consent management requirements.",
        ]

        for i, prompt in enumerate(analysis_prompts[:self.analysis_rounds]):
            msgs.append({"role": "user", "content": prompt})
            try:
                _beat()
                _progress(10 + i * 60 // self.analysis_rounds, f"Analyse SSDLC round {i+1}/{self.analysis_rounds}")
                print(f"[BLUETEAM] Analysis round {i+1}/{self.analysis_rounds} — calling LLM...", flush=True)
                resp = self.pro.chat(msgs, tools=None)
                _add_tokens(resp)
                content = resp.get("content", "")
                print(f"[BLUETEAM] Analysis round {i+1} — response: {len(content)} chars, tokens so far: {ai_tokens['total']}", flush=True)
                msgs.append({"role": "assistant", "content": content})
            except Exception as e:
                print(f"[BLUETEAM] Analysis round {i+1} FAILED: {e}", flush=True)
                msgs.append({"role": "assistant", "content": f"[Error: {e}]"})
                continue

        # ═══════════════════════════════════════
        # PHASE 2 — Report Writing
        # ═══════════════════════════════════════

        print(f"[BLUETEAM] Phase 2 — Starting {self.report_rounds} report writing rounds...", flush=True)
        _progress(75, "Redaction du rapport SSDLC...")

        report_system = {"role": "system", "content": f"""You are an EXPERT SSDLC security architect writing a comprehensive security-by-design report.

{context}

Based on your multi-round analysis above, produce a PROFESSIONAL security requirements document in French, using Markdown.

The report MUST follow this structure:

# Rapport d'Analyse SSDLC — Security by Design

## 1. Resume Executif
- Niveau de risque global
- Top 5 priorites immediates
- Score de maturite securite estime (1-5)

## 2. Perimetre d'Analyse
- Cible analysee
- Documents utilises (OpenAPI, documentation, collections)
- Methodologie (OWASP ASVS, NIST SP 800-53)

## 3. Analyse par Domaine
Pour chaque domaine (Auth, Data, Input Validation, Architecture, Error Handling, Business Logic, Supply Chain):
- Forces identifiees
- Faiblesses structurelles
- Risques associes

## 4. Exigences de Securite
Tableau complet : | ID | Domaine | Exigence | Priorite (C/H/M/L) | Justification | Reference ASVS/NIST |

## 5. Plan d'Action Priorise
- Actions immediate (critiques, < 2 semaines)
- Actions court terme (hautes, < 1 mois)
- Actions moyen terme (moyennes, < 3 mois)
- Actions long terme (basses, roadmap)

## 6. Matrice de Conformite
Mapping vers : OWASP ASVS v4.0, OWASP API Top 10, NIST SP 800-53, RGPD (si applicable)

## 7. Recommandations Architecturelles
- Schema d'architecture securise recommande
- Patterns de securite a implementer
- Outils et librairies recommandes

## 8. Annexes
- Glossaire
- References
- Liste complete des endpoints analyses

IMPORTANT: Write the COMPLETE report. Each section must be fully detailed. Be precise, actionable, and constructive.

Use Mermaid diagrams (```mermaid ... ```) to illustrate:
- Architecture flow (graph TD)
- Attack surface mapping (graph LR)
- Risk matrices (pie charts)
- Sequence diagrams for auth/remediation flows
At least 3-4 diagrams throughout the report.

Mermaid syntax rules:
- Node labels containing spaces or special chars MUST be wrapped in quotes: A["API Gateway"]
- Use --- for links, --> for directed edges, -.-&gt; for dotted
- No empty lines inside mermaid code blocks
- No trailing semicolons
- Pie chart: pie title "Risk Distribution"\n    "Critical" : 3\n    "High" : 7"""}

        report_msgs = [report_system]
        report_prompts = [
            "ONLY write section 1 (Resume Executif) and section 2 (Perimetre d'Analyse). Do NOT write other sections. Start with '# Rapport d'Analyse SSDLC — Security by Design' then '## 1. Resume Executif'.",
            "ONLY write section 3 (Analyse par Domaine). Cover all 7 domains. Do NOT repeat sections 1-2. Start with '## 3. Analyse par Domaine'.",
            "ONLY write section 4 (Exigences de Securite) with the full requirements table. Do NOT repeat previous sections. Start with '## 4. Exigences de Securite'.",
            "ONLY write section 5 (Plan d'Action Priorise) and section 6 (Matrice de Conformite). Do NOT repeat previous sections. Start with '## 5. Plan d'Action Priorise'.",
            "ONLY write section 7 (Recommandations Architecturelles) and section 8 (Annexes). Do NOT repeat previous sections. Start with '## 7. Recommandations Architecturelles'.",
        ]

        for ri, rp in enumerate(report_prompts[:self.report_rounds]):
            report_msgs.append({"role": "user", "content": rp})
            try:
                _beat()
                _progress(75 + (ri + 1) * 25 // self.report_rounds,
                         f"Redaction rapport {ri+1}/{self.report_rounds}")
                print(f"[BLUETEAM] Report round {ri+1}/{self.report_rounds} — calling LLM...", flush=True)
                resp = self.pro.chat(report_msgs, tools=None)
                _add_tokens(resp)
                content = resp.get("content", "")
                print(f"[BLUETEAM] Report round {ri+1} — response: {len(content)} chars, total tokens: {ai_tokens['total']}", flush=True)
                report_msgs.append({"role": "assistant", "content": content})
            except Exception as e:
                print(f"[BLUETEAM] Report round {ri+1} FAILED: {e}", flush=True)
                report_msgs.append({"role": "assistant", "content": f"[Error: {e}]"})

        # Collect final report — concatenate sections in order (each round = one section)
        report_parts = []
        for msg in report_msgs:
            if msg.get("role") == "assistant" and msg.get("content") and "Error:" not in str(msg.get("content", "")):
                report_parts.append(msg["content"])
        report = "\n\n".join(report_parts) if report_parts else ""

        # Count findings (look for requirement IDs in the report)
        import re
        finding_ids = re.findall(r'\| (?:SSDLC|REQ)-\d+', report)

        _progress(100, "Analyse SSDLC terminee")
        print(f"[BLUETEAM] Analysis complete — {len(report)} chars report, {ai_tokens['total']} total tokens", flush=True)

        return {
            "report_markdown": report,
            "findings_count": len(finding_ids) or len(re.findall(r'\| [A-Z]+-\d+', report)),
            "analysis_rounds": self.analysis_rounds,
            "report_rounds": self.report_rounds,
            "tokens": ai_tokens,
            "pro_model": self.pro_model,
        }
