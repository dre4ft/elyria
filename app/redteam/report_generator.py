# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Pentest report generator — produces a professional-grade markdown report.
Pure markdown, no inline HTML — rendered client-side by marked.js.
"""

from datetime import datetime, timezone


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _severity_order(sev):
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(sev, 5)


def _severity_label(sev):
    return sev.upper()


def generate_report(campaign, findings, ai_insights=None, finding_logs=None, scan_config=None):
    """Generate a complete pentest report in GitHub-flavored Markdown."""
    finding_logs = finding_logs or {}
    scan_config = scan_config or {}
    campaign_name = campaign.get("name", "Unnamed Campaign")
    target = campaign.get("target_url", "N/A")
    desc = campaign.get("description", "")
    created = campaign.get("created_at", _now())

    sorted_findings = sorted(findings, key=lambda f: _severity_order(f.get("severity", "info")))

    counts = {}
    for f in sorted_findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1

    total = len(sorted_findings)
    critical = counts.get("critical", 0)
    high = counts.get("high", 0)
    medium = counts.get("medium", 0)
    low = counts.get("low", 0)
    info = counts.get("info", 0)

    risk_level = (
        "Critical" if critical + high > 3
        else "High" if critical + high > 0
        else "Medium" if medium > 2
        else "Low"
    )

    report = f"""# Pentest Report

**Confidential** — Prepared for authorized security assessment only.

---

## 1. Executive Summary

**Target:** `{target}`
**Assessment Date:** {created}
**Overall Risk Level:** **{risk_level.upper()}**

This report presents the findings of a comprehensive API security assessment conducted against **{campaign_name}**. The assessment followed the **OWASP API Security Top 10 (2023)** methodology, combining automated scanning with AI-enhanced analysis.

### Key Findings

| Severity | Count |
|----------|-------|
| **Critical** | {critical} |
| **High** | {high} |
| **Medium** | {medium} |
| **Low** | {low} |
| **Info** | {info} |

**Total findings: {total}**

"""

    if scan_config and scan_config.get("flash_model"):
        tokens = scan_config.get("tokens", {})
        pt = tokens.get("prompt", 0)
        ct = tokens.get("completion", 0)
        tt = tokens.get("total", 0)
        report += f"""### Configuration du scan IA

| Parametre | Valeur |
|-----------|--------|
| **Modele Flash** | `{scan_config.get('flash_model', 'N/A')}` |
| **Modele Pro** | `{scan_config.get('pro_model', 'N/A')}` |
| **Rounds exploration** | {scan_config.get('explore_rounds', 0)} |
| **Rounds analyse** | {scan_config.get('analysis_rounds', 0)} |
| **Tokens prompt** | {pt:,} |
| **Tokens completion** | {ct:,} |
| **Tokens totaux** | {tt:,} |

"""
    if ai_insights:
        report += f"""### AI-Powered Analysis

{ai_insights}

"""

    report += f"""---

## 2. Scope & Methodology

### Scope
- **Target:** `{target}`
- **Campaign:** {campaign_name}
- **Description:** {desc}

### Methodology

1. **Reconnaissance** — Endpoint discovery, API fingerprinting, documentation analysis
2. **Automated Scanning** — OWASP API Security Top 10 checks using Elyria Pentest Engine
3. **AI-Enhanced Analysis** — Deep-dive vulnerability verification and business logic assessment
4. **Reporting** — Professional-grade report with evidence and remediation guidance

### OWASP API Security Top 10 Coverage

| # | Category | Covered |
|---|----------|---------|
| API1 | Broken Object Level Authorization | ✓ |
| API2 | Broken Authentication | ✓ |
| API3 | Broken Object Property Level Authorization | ✓ |
| API4 | Unrestricted Resource Consumption | ✓ |
| API5 | Broken Function Level Authorization | ✓ |
| API6 | Unrestricted Access to Sensitive Business Flows | ✓ |
| API7 | Server Side Request Forgery | ✓ |
| API8 | Security Misconfiguration | ✓ |
| API9 | Improper Inventory Management | ✓ |
| API10 | Unsafe Consumption of APIs | ✓ |

---

## 3. Findings Summary

| # | Severity | Title | Category | Endpoint |
|---|----------|-------|----------|----------|
"""

    for idx, f in enumerate(sorted_findings, 1):
        sev = _severity_label(f.get("severity", "info"))
        title = f.get("title", "-")[:80]
        cat = f.get("category", "-")
        endpoint = f.get("endpoint", "-")
        # Shorten endpoint for display
        if len(endpoint) > 55:
            endpoint = endpoint[:52] + "..."
        report += f"| {idx} | **{sev}** | {title} | {cat} | `{endpoint}` |\n"

    report += f"""
---

## 4. Detailed Findings

"""

    for idx, f in enumerate(sorted_findings, 1):
        sev = _severity_label(f.get("severity", "info"))
        title = f.get("title", "No title")
        description = f.get("description", "")
        cat = f.get("category", "")
        endpoint = f.get("endpoint", "N/A")
        method = f.get("method", "GET")
        remediation = f.get("remediation", "")
        cvss = f.get("cvss_score", 0.0)
        cwe = f.get("cwe_id", "")
        ai_analysis = f.get("ai_analysis", "")
        evidence = f.get("evidence", {})
        if isinstance(evidence, str):
            try:
                import json as _json
                evidence = _json.loads(evidence)
            except Exception:
                evidence = {}

        report += f"""### Finding #{idx}: {title}

| | |
|---|---|
| **Severity** | **{sev}** |
| **Category** | {cat} |
| **Endpoint** | `{method} {endpoint}` |
| **CVSS Score** | {cvss} |
| **CWE** | {cwe} |

**Description**

{description}

"""

        if evidence:
            report += f"""**Evidence**

```json
{_format_json(evidence)}
```

"""

        if ai_analysis:
            report += f"""**AI Analysis**

{ai_analysis}

"""

        report += f"""**Remediation**

{remediation}

---

"""

    report += """## 5. Remediation Roadmap

### Immediate (0-7 days)
- Address all **Critical** and **High** severity findings
- Implement rate limiting on all endpoints
- Enable security headers (HSTS, CSP, X-Content-Type-Options)
- Remove verbose error messages in production

### Short-term (7-30 days)
- Address all **Medium** severity findings
- Implement proper authentication and authorization controls
- Conduct a review of all exposed endpoints and remove unnecessary ones
- Validate and sanitize all user inputs

### Long-term (30-90 days)
- Address all **Low** and **Info** findings
- Implement a comprehensive API security testing program
- Establish API security policies and developer training
- Deploy API gateway with WAF capabilities

---

## 6. Appendices

### A. Request/Response Evidence

The following section provides the HTTP request and response details that led to each finding.

"""
    for idx, f in enumerate(sorted_findings, 1):
        fid = f.get("finding_id", "")
        log = finding_logs.get(fid)
        if not log:
            continue
        title = f.get("title", f"Finding #{idx}")
        method = log.get("method", "GET")
        req_url = log.get("request_url", f.get("endpoint", ""))
        req_headers = log.get("request_headers", {})
        if isinstance(req_headers, str):
            try:
                import json as _json
                req_headers = _json.loads(req_headers)
            except Exception:
                req_headers = {}
        req_body = log.get("request_body", "")
        resp_status = log.get("response_status", 0)
        resp_headers = log.get("response_headers", {})
        if isinstance(resp_headers, str):
            try:
                import json as _json
                resp_headers = _json.loads(resp_headers)
            except Exception:
                resp_headers = {}
        resp_body = log.get("response_body_preview", "")

        report += f"""#### A.{idx} — {title}

**Request**
```
{method} {req_url}
```
"""
        if req_headers:
            report += f"""**Request Headers**
```json
{_format_json(req_headers)}
```
"""
        if req_body:
            report += f"""**Request Body**
```json
{_format_json(req_body)}
```
"""
        report += f"""**Response Status:** {resp_status}

"""
        if resp_headers:
            report += f"""**Response Headers**
```json
{_format_json(resp_headers)}
```
"""
        if resp_body:
            report += f"""**Response Body**
```json
{_format_json(resp_body)}
```
"""
        report += "---\n\n"

    report += """### B. Assessment Configuration
- **Tool:** Elyria Pentest Engine
- **Methodology:** OWASP API Security Top 10 (2023)
- **AI Enhancement:** Enabled

### C. Glossary

| Term | Definition |
|------|------------|
| BOLA | Broken Object Level Authorization — accessing resources belonging to other users |
| BFLA | Broken Function Level Authorization — accessing administrative functions without privileges |
| SSRF | Server-Side Request Forgery — tricking the server into making requests to internal resources |
| CVSS | Common Vulnerability Scoring System — industry standard for rating vulnerability severity |
| CWE | Common Weakness Enumeration — standard classification of security weaknesses |

---

*Report generated by Elyria Pentest Engine on {_now()}*
*This report is confidential and intended for authorized recipients only.*
"""
    return report


def _format_json(obj, indent=2):
    import json as _json
    return _json.dumps(obj, indent=indent, default=str, ensure_ascii=False)
