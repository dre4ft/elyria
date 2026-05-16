"""
AI-enhanced pentest analysis — leverages the existing AI infrastructure to
provide deeper vulnerability analysis, exploitation guidance, and business logic assessment.
"""

import json


async def analyze_findings(findings, campaign_target):
    """
    Use AI to analyze pentest findings and provide enhanced insights.
    Falls back to rule-based analysis if AI is unavailable.
    """
    if not findings:
        return "No findings to analyze. The target API appears to have a clean baseline security posture based on automated checks. Manual penetration testing is still recommended for business logic flaws."

    try:
        return await _ai_analysis(findings, campaign_target)
    except Exception:
        return _rule_based_analysis(findings)


async def _ai_analysis(findings, target):
    """Use the AI chat infrastructure for deep analysis."""
    import sys
    sys.path.insert(0, "..")
    try:
        from ai_core.ai_wrapper import AIWrapper
        wrapper = AIWrapper()
    except Exception:
        raise RuntimeError("AI unavailable")

    findings_summary = []
    for f in findings[:20]:
        findings_summary.append({
            "title": f.get("title"),
            "severity": f.get("severity"),
            "category": f.get("category"),
            "description": f.get("description", "")[:300],
        })

    prompt = f"""You are a senior API security penetration tester. Analyze these findings from a pentest against {target}.

Findings ({len(findings)} total):
{json.dumps(findings_summary, indent=2)}

Provide:
1. Overall risk assessment (2-3 sentences)
2. Top 3 most critical issues and their business impact
3. Recommended exploitation paths to demonstrate risk
4. Specific remediation priorities
5. Any business logic flaws you can infer from the findings

Keep it concise and actionable. Use professional pentest report language."""

    response = await wrapper.chat(prompt, None)
    return response.get("content", "") if isinstance(response, dict) else str(response)


def _rule_based_analysis(findings):
    """Rule-based fallback when AI is unavailable."""
    critical = [f for f in findings if f.get("severity") == "critical"]
    high = [f for f in findings if f.get("severity") == "high"]
    medium = [f for f in findings if f.get("severity") == "medium"]

    categories = {}
    for f in findings:
        cat = f.get("category", "Other")
        categories[cat] = categories.get(cat, 0) + 1

    lines = []

    if critical:
        lines.append(f"**{len(critical)} critical finding(s)** require immediate attention. These vulnerabilities could lead to full system compromise.")
        for f in critical:
            lines.append(f"- {f.get('title')}")

    if high:
        lines.append(f"\n**{len(high)} high-severity finding(s)** represent significant risk to the organization.")
        top_high = sorted(high, key=lambda f: f.get("cvss_score", 0), reverse=True)[:3]
        for f in top_high:
            lines.append(f"- {f.get('title')} (CVSS {f.get('cvss_score', 'N/A')})")

    if medium:
        lines.append(f"\n**{len(medium)} medium-severity finding(s)** increase the attack surface and should be addressed within 30 days.")

    # Category distribution
    lines.append(f"\n**Vulnerability distribution by category:**")
    for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
        lines.append(f"- {cat}: {count} finding(s)")

    # Business logic assessment
    has_business = any("Business Logic" in f.get("category", "") or "business flow" in f.get("description", "").lower() for f in findings)
    if has_business:
        lines.append(f"\n**Business Logic Assessment:** Potential business logic flaws were detected. These are high-impact vulnerabilities that automated scanners often miss. Manual verification of critical business flows (purchase, booking, transfer workflows) is strongly recommended.")
    else:
        lines.append(f"\n**Business Logic Assessment:** Automated checks did not detect obvious business logic flaws. However, business logic vulnerabilities are inherently difficult to detect automatically. Manual testing of critical workflows is recommended, particularly for: price manipulation, quantity abuse, workflow step bypass, and race conditions on transactional endpoints.")

    return "\n".join(lines)


async def generate_ai_report_section(campaign_name, target, findings_summary):
    """Generate an executive summary using AI."""
    try:
        return await _ai_executive_summary(campaign_name, target, findings_summary)
    except Exception:
        return ""


async def _ai_executive_summary(name, target, summary):
    import sys
    sys.path.insert(0, "..")
    try:
        from ai_core.ai_wrapper import AIWrapper
        wrapper = AIWrapper()
    except Exception:
        return ""

    prompt = f"""Write an executive summary for a professional API pentest report.

Campaign: {name}
Target: {target}

Key findings:
{json.dumps(summary, indent=2)}

Write 3-4 paragraphs in the style of a top-tier security consulting firm (e.g., Bishop Fox, NCC Group, Praetorian). Use professional language, highlight business risk, and provide clear actionable guidance."""

    response = await wrapper.chat(prompt, None)
    return response.get("content", "") if isinstance(response, dict) else str(response)
