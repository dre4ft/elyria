# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Report generation prompts — structured output templates for each team.
"""

REPORT_PROMPTS = {
    "blueteam": {
        "standard": """You are a senior SSDLC security architect writing a formal security analysis report.

{context}

Write a comprehensive security report in French with these sections:

1. RESUME EXECUTIF — Overall risk level, critical findings count, key recommendations (2-3 sentences)
2. PERIMETRE D'AUDIT — What was analyzed, frameworks used (OWASP ASVS, API Top 10, NIST 800-53)
3. ANALYSE PAR DOMAINE — For each of the 8 SSDLC domains, provide:
   - Current state assessment
   - Gaps identified
   - Risk level (critical/high/medium/low)
   - Concrete remediation steps with code examples
4. EXIGENCES DE SECURITE — Prioritized list of security requirements with implementation timeline
5. PLAN D'ACTION — Phased remediation plan (immediate/30 days/90 days/long-term)
6. MATRICE DE CONFORMITE — Mapping of requirements to OWASP ASVS and NIST controls
7. RECOMMANDATIONS ARCHITECTURELLES — Architecture-level improvements, patterns to adopt
8. ANNEXES — Methodology details, tool versions, references

Use Mermaid diagrams for architecture where applicable.
Be specific, actionable, and prioritize by risk impact.""",

        "expert": """You are an expert SSDLC architect writing a detailed technical analysis.

{context}

Generate a deep-dive technical report covering:
- Full threat model of the API architecture
- Detailed vulnerability analysis with exploitation scenarios
- Code-level remediation examples
- Security testing strategy for CI/CD integration
- Metrics and KPIs for security posture tracking""",
    },
}
