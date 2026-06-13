# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Purple Team report generator — produces a 3-part professional markdown report.
Part 1: Known CVEs
Part 2: Common Weakness Enumeration (CWE)
Part 3: Bad Practices & Exploitations
"""

from datetime import datetime, timezone


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _severity_order(sev):
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(sev, 5)


def _severity_label(sev):
    return sev.upper()


def generate_report(scan, findings, scan_config=None):
    """Generate a complete Purple Team report in GitHub-flavored Markdown."""
    scan_config = scan_config or {}
    scan_name = scan.get("name", "Unnamed Scan")
    repo_url = scan.get("repo_url", "N/A")
    target = scan.get("target_endpoint", "N/A")
    language = scan_config.get("language", "unknown")
    framework = scan_config.get("framework", "unknown")
    created = scan.get("created_at", _now())

    # Split findings by part
    cve_findings = [f for f in findings if f.get("finding_part") == "cves"]
    cwe_findings = [f for f in findings if f.get("finding_part") == "cwes"]
    practice_findings = [f for f in findings if f.get("finding_part") not in ("cves", "cwes")]
    # Also include dynamic + AI findings in part 3
    for f in findings:
        cat = f.get("category", "")
        if cat.startswith("dynamic_") or cat == "ai_discovered":
            if f not in practice_findings:
                practice_findings.append(f)

    cve_findings = sorted(cve_findings, key=lambda f: _severity_order(f.get("severity", "info")))
    cwe_findings = sorted(cwe_findings, key=lambda f: _severity_order(f.get("severity", "info")))
    practice_findings = sorted(practice_findings, key=lambda f: _severity_order(f.get("severity", "info")))

    def _counts(items):
        c = {}
        for f in items:
            sev = f.get("severity", "info")
            c[sev] = c.get(sev, 0) + 1
        return c

    cve_counts = _counts(cve_findings)
    cwe_counts = _counts(cwe_findings)
    practice_counts = _counts(practice_findings)

    total = len(findings)
    risk_level = "Critical" if (cve_counts.get("critical", 0) + cwe_counts.get("critical", 0) + practice_counts.get("critical", 0)) > 2 else \
                 "High" if (cve_counts.get("critical", 0) + cwe_counts.get("high", 0) + practice_counts.get("critical", 0) + practice_counts.get("high", 0)) > 3 else \
                 "Medium" if total > 10 else "Low"

    report = f"""# Purple Team Report — IAST Code Security Analysis

**Confidential** — Prepared for authorized security assessment only.

---

## Executive Summary

**Repository:** `{repo_url}`
**Target Endpoint:** `{target}`
**Language/Framework:** {language} / {framework}
**Assessment Date:** {created}
**Overall Risk Level:** **{risk_level.upper()}**

This report presents the findings of a comprehensive **Purple Team** security assessment combining static code analysis (SAST), dependency vulnerability scanning (SCA), pattern-based weakness detection, and AI-powered deep code review.

| Part | Findings |
|------|----------|
| **Part 1 — CVE Connues** | {len(cve_findings)} |
| **Part 2 — CWE** | {len(cwe_findings)} |
| **Part 3 — Mauvaises Pratiques & Exploitations** | {len(practice_findings)} |
| **Total** | **{total}** |

"""

    # AI scan config
    if scan_config.get("flash_model"):
        tokens = scan_config.get("tokens", {})
        report += f"""### Configuration du scan IA

| Parametre | Valeur |
|-----------|--------|
| **Modele Flash** | `{scan_config.get('flash_model', 'N/A')}` |
| **Modele Pro** | `{scan_config.get('pro_model', 'N/A')}` |
| **Tokens utilises** | {tokens.get('total', 0):,} |

"""

    report += f"""---

## Methodology

### Phases d'analyse

1. **Analyse statique deterministe** — Detection du langage/framework, parsing des dependances, pattern matching
2. **Scan CVE (NIST NVD)** — Verification des dependances contre la base CVE du NIST
3. **Scan CWE (MITRE)** — Detection des faiblesses communes (CWE Top 25, OWASP Top 10)
4. **Analyse dynamique IAST** — Validation des vulnerabilites contre l'API cible (si disponible)
5. **Deep Code Review IA** — Analyse approfondie par IA avec lecture du code source et requetes HTTP

### Couverture OWASP Top 10 (2021)

| # | Category | Covered |
|---|----------|---------|
| A01 | Broken Access Control | ✓ |
| A02 | Cryptographic Failures | ✓ |
| A03 | Injection | ✓ |
| A04 | Insecure Design | ✓ |
| A05 | Security Misconfiguration | ✓ |
| A06 | Vulnerable Components | ✓ |
| A07 | Auth Failures | ✓ |
| A08 | Software & Data Integrity | ✓ |
| A09 | Logging & Monitoring | ✓ |
| A10 | SSRF | ✓ |

---

## Part 1 — CVE Connues

CVE vulnerabilities found in project dependencies.

"""

    if cve_findings:
        report += "| # | Severity | CVE | CVSS | Dependency | Description |\n"
        report += "|---|----------|-----|------|------------|-------------|\n"
        for idx, f in enumerate(cve_findings, 1):
            sev = _severity_label(f.get("severity", "info"))
            cve_id = f.get("cve_id", "-")
            cvss = f.get("cvss_score", 0.0)
            file_path = f.get("file_path", "-")
            desc = f.get("description", "")[:100]
            report += f"| {idx} | **{sev}** | {cve_id} | {cvss:.1f} | {file_path} | {desc} |\n"

        report += "\n### CVE Details\n\n"
        for idx, f in enumerate(cve_findings, 1):
            report += f"""#### CVE #{idx}: {f.get('cve_id', '')}

| | |
|---|---|
| **Severity** | **{_severity_label(f.get('severity', 'info'))}** |
| **CVSS Score** | {f.get('cvss_score', 0.0)} |
| **Dependency** | {f.get('file_path', '-')} |

**Description**

{f.get('description', 'No description')}

**Remediation**

{f.get('remediation', 'Update to the latest patched version.')}

---
"""
    else:
        report += "No known CVEs detected in project dependencies.\n\n"

    # ── Part 2: CWE ──
    report += """## Part 2 — CWE (Common Weakness Enumeration)

Code-level weaknesses detected via pattern matching.

"""

    if cwe_findings:
        # Group by CWE ID
        from collections import defaultdict
        cwe_groups = defaultdict(list)
        for f in cwe_findings:
            cwe_groups[f.get("cwe_id", "CWE-???")].append(f)

        report += "### CWE Summary\n\n"
        report += "| CWE ID | Count | Max Severity |\n"
        report += "|--------|-------|-------------|\n"
        for cwe_id, items in sorted(cwe_groups.items()):
            max_sev = max(items, key=lambda f: _severity_order(f.get("severity", "info")))
            report += f"| {cwe_id} | {len(items)} | **{_severity_label(max_sev.get('severity', 'info'))}** |\n"

        report += "\n### CWE Details\n\n"
        for cwe_id, items in sorted(cwe_groups.items()):
            report += f"#### {cwe_id} ({len(items)} occurrence(s))\n\n"
            report += "| # | Severity | File | Line | Matched |\n"
            report += "|---|----------|------|------|---------|\n"
            for idx, f in enumerate(items[:20], 1):
                sev = _severity_label(f.get("severity", "info"))
                file_path = f.get("file_path", "-")
                line = f.get("line_number", 0)
                evidence = f.get("evidence", {})
                matched = evidence.get("matched_text", "")[:60] if isinstance(evidence, dict) else str(evidence)[:60]
                report += f"| {idx} | **{sev}** | `{file_path}` | {line} | `{matched}` |\n"

            report += "\n**Recommendation:** " + items[0].get("remediation", "Review and fix the identified weakness.") + "\n\n---\n\n"
    else:
        report += "No CWE patterns detected.\n\n"

    # ── Part 3: Bad Practices & Exploitations ──
    report += """## Part 3 — Mauvaises Pratiques & Exploitations Reelles

Bad practices, dynamic testing results, and AI-discovered vulnerabilities.

"""

    if practice_findings:
        # Group by category
        from collections import defaultdict
        cat_groups = defaultdict(list)
        for f in practice_findings:
            cat = f.get("category", "other")
            cat_groups[cat].append(f)

        report += "### Categories\n\n"
        report += "| Category | Count | Max Severity |\n"
        report += "|----------|-------|-------------|\n"
        for cat, items in sorted(cat_groups.items()):
            max_sev = max(items, key=lambda f: _severity_order(f.get("severity", "info")))
            cat_label = cat.replace("_", " ").title()
            report += f"| {cat_label} | {len(items)} | **{_severity_label(max_sev.get('severity', 'info'))}** |\n"

        report += "\n### Detailed Findings\n\n"
        for idx, f in enumerate(practice_findings, 1):
            sev = _severity_label(f.get("severity", "info"))
            title = f.get("title", "No title")
            description = f.get("description", "")
            cat = f.get("category", "other")
            file_path = f.get("file_path", "N/A")
            line = f.get("line_number", 0)
            remediation = f.get("remediation", "")
            evidence = f.get("evidence", {})
            if isinstance(evidence, str):
                try:
                    import json as _json
                    evidence = _json.loads(evidence)
                except Exception:
                    evidence = {}
            ai_analysis = f.get("ai_analysis", "")

            location = f"`{file_path}`"
            if line:
                location += f":{line}"

            report += f"""### Finding #{idx}: {title}

| | |
|---|---|
| **Severity** | **{sev}** |
| **Category** | {cat.replace('_', ' ').title()} |
| **Location** | {location} |

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
    else:
        report += "No bad practices or exploitations detected.\n\n"

    # ── Remediation Roadmap ──
    critical_total = cve_counts.get("critical", 0) + cwe_counts.get("critical", 0) + practice_counts.get("critical", 0)
    high_total = cve_counts.get("high", 0) + cwe_counts.get("high", 0) + practice_counts.get("high", 0)
    medium_total = cve_counts.get("medium", 0) + cwe_counts.get("medium", 0) + practice_counts.get("medium", 0)

    report += f"""## Remediation Roadmap

### Immediate (0-7 days)
- Address **{critical_total} Critical** findings
- Update vulnerable dependencies with known CVEs
- Fix hardcoded credentials and exposed secrets
- Enable security headers (HSTS, CSP, X-Frame-Options)

### Short-term (7-30 days)
- Address **{high_total} High** severity findings
- Implement proper input validation across all endpoints
- Fix authentication and authorization weaknesses
- Remove debug/development configurations

### Long-term (30-90 days)
- Address **{medium_total} Medium** severity findings
- Implement automated SAST/SCA in CI/CD pipeline
- Conduct regular dependency vulnerability scanning
- Establish secure coding guidelines and developer training

---

## Appendices

### A. Scan Configuration

| Parameter | Value |
|-----------|-------|
| **Repository** | `{repo_url}` |
| **Branch** | {scan.get('repo_branch', 'main')} |
| **Language** | {language} |
| **Framework** | {framework} |
| **Target Endpoint** | {target} |
| **Scan Depth** | {scan.get('scan_depth', 'full')} |

### B. Glossary

| Term | Definition |
|------|------------|
| CVE | Common Vulnerabilities and Exposures — standardized identifier for known vulnerabilities |
| CWE | Common Weakness Enumeration — classification of software security weaknesses |
| CVSS | Common Vulnerability Scoring System — standard for rating vulnerability severity |
| SAST | Static Application Security Testing — analyzing source code for vulnerabilities |
| SCA | Software Composition Analysis — identifying vulnerabilities in third-party dependencies |
| IAST | Interactive Application Security Testing — combining static and dynamic analysis |
| OWASP | Open Web Application Security Project — industry standard for web security |

---

*Report generated by Elyria Purple Team Engine on {_now()}*
*This report is confidential and intended for authorized recipients only.*
"""
    return report


def _format_json(obj, indent=2):
    import json as _json
    return _json.dumps(obj, indent=indent, default=str, ensure_ascii=False)
