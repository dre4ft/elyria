# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Grey Team — OSINT deterministic domain scanner (Phase 1).

Passive reconnaissance against a target domain. Collects maximum
information without interacting with target infrastructure beyond
simple HTTP GET requests (human-like browsing).

12 collection modules:
  1. DNS Records      — A, AAAA, MX, NS, TXT (SPF/DMARC), SOA
  2. WHOIS            — Registrar, dates, nameservers
  3. SSL/TLS          — Certificate, SANs, weak ciphers, TLS versions
  4. Cert Transparency — crt.sh subdomain enumeration
  5. HTTP Headers     — Security headers analysis
  6. Web Paths        — robots.txt, sitemap.xml, security.txt
  7. Tech Fingerprint — Server, framework, CDN/WAF detection
  8. Email Enumeration — From WHOIS, DNS, website
  9. Wayback Machine  — Historical URLs from archive.org
 10. GitHub Dorks     — Code search for domain references
 11. Google Dorks     — site:domain via DuckDuckGo
 12. Frontend Code    — JS/CSS analysis, CVE lookup, secrets, deobfuscation
"""

import json
import re
import socket
import ssl
import subprocess
import time
import hashlib
import os
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone

# SSL context that skips verification — used for public API queries (crt.sh,
# Wayback, GitHub, NVD) where the corporate proxy may inject self-signed certs.
_UNVERIFIED_CTX = ssl.create_default_context()
_UNVERIFIED_CTX.check_hostname = False
_UNVERIFIED_CTX.verify_mode = ssl.CERT_NONE

try:
    from core.logging import get_logger
    _log = get_logger("greyteam.scanner")
except Exception:
    import logging
    _log = logging.getLogger("greyteam.scanner")

# ── helpers ──

def _safe_domain(domain: str) -> str:
    """Strip protocol, path, port — return bare domain."""
    d = domain.strip().lower()
    d = re.sub(r'^https?://', '', d)
    d = d.split('/')[0].split(':')[0]
    return d


def _http_get(url: str, timeout: int = 10, headers: dict = None, context=None) -> str | None:
    """Simple HTTP GET. Returns response body or None on failure."""
    try:
        req = urllib.request.Request(url, headers=headers or {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
        })
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None


def _http_get_headers(url: str, timeout: int = 10, context=None) -> dict | None:
    """HTTP GET — return response headers dict, or None."""
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            return dict(resp.headers)
    except Exception:
        return None


def _run(cmd: list[str], timeout: int = 15) -> tuple[str, str, int]:
    """Run a subprocess. Returns (stdout, stderr, exit_code)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.stdout.strip(), proc.stderr.strip(), proc.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except FileNotFoundError:
        return "", "command not found", -2
    except Exception as e:
        return "", str(e)[:500], -1


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ═══════════════════════════════════════════════════════════════
# MODULE 1 — DNS Records
# ═══════════════════════════════════════════════════════════════

def _collect_dns(domain: str) -> list[dict]:
    findings = []
    ftype = "dns"

    # A / AAAA via socket
    try:
        addrs = socket.getaddrinfo(domain, 80, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ipv4 = sorted(set(a[4][0] for a in addrs if a[0] == socket.AF_INET))
        ipv6 = sorted(set(a[4][0] for a in addrs if a[0] == socket.AF_INET6))
        if ipv4:
            findings.append({
                "title": f"DNS A records: {', '.join(ipv4[:8])}",
                "severity": "info", "category": "DNS Records",
                "finding_type": ftype,
                "description": f"Found {len(ipv4)} IPv4 address(es) for {domain}.",
                "file_path": "N/A", "line_number": 0,
                "evidence": f"A: {', '.join(ipv4[:8])}",
                "remediation": "Ensure all IPs point to expected infrastructure.",
                "cwe_id": "", "source": "deterministic",
            })
        if ipv6:
            findings.append({
                "title": f"DNS AAAA records present ({', '.join(ipv6[:4])})",
                "severity": "info", "category": "DNS Records",
                "finding_type": ftype,
                "description": f"IPv6 addresses found. Ensure IPv6 infrastructure is secured.",
                "file_path": "N/A", "line_number": 0,
                "evidence": f"AAAA: {', '.join(ipv6[:4])}",
                "remediation": "Review IPv6 security posture.",
                "cwe_id": "", "source": "deterministic",
            })
    except Exception as e:
        findings.append({
            "title": f"DNS resolution failed for {domain}",
            "severity": "medium", "category": "DNS Records",
            "finding_type": ftype,
            "description": f"Could not resolve {domain}: {e}",
            "file_path": "N/A", "line_number": 0,
            "evidence": str(e)[:200],
            "remediation": "Verify DNS configuration and ensure the domain resolves.",
            "cwe_id": "", "source": "deterministic",
        })

    # MX / NS / TXT / SOA via dig
    for rtype in ["MX", "NS", "TXT", "SOA"]:
        stdout, stderr, rc = _run(["dig", "+short", domain, rtype])
        if rc != 0:
            stdout, stderr, rc = _run(["nslookup", "-type=" + rtype, domain])
        if rc == 0 and stdout:
            records = [l.strip() for l in stdout.split("\n") if l.strip() and not l.startswith(";;")]
            findings.append({
                "title": f"DNS {rtype} records found ({len(records)} entries)",
                "severity": "info", "category": "DNS Records",
                "finding_type": ftype,
                "description": f"{rtype} records discovered for {domain}.",
                "file_path": "N/A", "line_number": 0,
                "evidence": "\n".join(records[:10]),
                "remediation": "Review that all listed records are authorized.",
                "cwe_id": "", "source": "deterministic",
            })
        elif rc == -2:
            findings.append({
                "title": "dig/nslookup not available for deep DNS",
                "severity": "info", "category": "DNS Records",
                "finding_type": ftype,
                "description": "Install dnsutils for MX/NS/TXT/SOA enumeration.",
                "file_path": "N/A", "line_number": 0,
                "evidence": "dig/nslookup not found",
                "remediation": "apt-get install dnsutils",
                "cwe_id": "", "source": "deterministic",
            })
            break  # only report once

    # SPF / DMARC analysis from TXT
    stdout, _, rc = _run(["dig", "+short", domain, "TXT"])
    if rc == 0 and stdout:
        txt_all = stdout.lower()
        has_spf = "v=spf1" in txt_all
        has_dmarc_stdout, _, _ = _run(["dig", "+short", f"_dmarc.{domain}", "TXT"])
        has_dmarc = "v=dmarc1" in has_dmarc_stdout.lower() if has_dmarc_stdout else False

        if not has_spf:
            findings.append({
                "title": "Missing SPF record",
                "severity": "medium", "category": "DNS Records",
                "finding_type": ftype,
                "description": f"No SPF (v=spf1) record found. Domain is vulnerable to email spoofing.",
                "file_path": "N/A", "line_number": 0,
                "evidence": "No v=spf1 in TXT records",
                "remediation": "Add an SPF TXT record: v=spf1 mx -all",
                "cwe_id": "", "source": "deterministic",
            })
        else:
            findings.append({
                "title": "SPF record present",
                "severity": "info", "category": "DNS Records",
                "finding_type": ftype,
                "description": "SPF is configured. Review policy strictness.",
                "file_path": "N/A", "line_number": 0,
                "evidence": "SPF (v=spf1) found in TXT records",
                "remediation": "Use -all (hard fail) instead of ~all (soft fail) for stronger protection.",
                "cwe_id": "", "source": "deterministic",
            })

        if not has_dmarc:
            findings.append({
                "title": "Missing DMARC record",
                "severity": "medium", "category": "DNS Records",
                "finding_type": ftype,
                "description": "No DMARC policy found (_dmarc.{domain}). Email spoofing possible without detection.",
                "file_path": "N/A", "line_number": 0,
                "evidence": "No v=DMARC1 in _dmarc TXT record",
                "remediation": "Add DMARC record: v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}",
                "cwe_id": "", "source": "deterministic",
            })
        else:
            dmarc_policy = "p=reject" if "p=reject" in has_dmarc_stdout.lower() else "p=quarantine" if "p=quarantine" in has_dmarc_stdout.lower() else "p=none"
            findings.append({
                "title": f"DMARC record present ({dmarc_policy})",
                "severity": "info" if "reject" in dmarc_policy else "low",
                "category": "DNS Records",
                "finding_type": ftype,
                "description": f"DMARC configured with {dmarc_policy}. {'Strong — emails failing DMARC are rejected.' if 'reject' in dmarc_policy else 'Consider p=reject for maximum protection.' if 'quarantine' in dmarc_policy else 'Only monitoring — no enforcement.'}",
                "file_path": "N/A", "line_number": 0,
                "evidence": has_dmarc_stdout[:300] if has_dmarc_stdout else "",
                "remediation": "Set p=reject for strongest anti-spoofing protection.",
                "cwe_id": "", "source": "deterministic",
            })

    return findings


# ═══════════════════════════════════════════════════════════════
# MODULE 2 — WHOIS
# ═══════════════════════════════════════════════════════════════

def _collect_whois(domain: str) -> list[dict]:
    findings = []
    ftype = "whois"
    whois_text = ""

    # Try whois CLI first
    stdout, _, rc = _run(["whois", domain], timeout=15)
    if rc == 0 and stdout and len(stdout) > 20:
        whois_text = stdout
    else:
        # Fallback: raw socket to whois.iana.org for referral, then to TLD server
        try:
            # First get referral from IANA
            iana_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            iana_sock.settimeout(10)
            iana_sock.connect(("whois.iana.org", 43))
            iana_sock.sendall((domain + "\r\n").encode())
            iana_resp = b""
            while True:
                chunk = iana_sock.recv(4096)
                if not chunk:
                    break
                iana_resp += chunk
            iana_sock.close()
            whois_text = iana_resp.decode("utf-8", errors="replace")

            # Check for referral
            referral = None
            for line in whois_text.split("\n"):
                if line.strip().startswith("refer:"):
                    referral = line.strip().split("refer:")[-1].strip()
                    break
                if line.strip().startswith("whois:"):
                    referral = line.strip().split("whois:")[-1].strip()
                    break

            if referral:
                ref_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ref_sock.settimeout(10)
                ref_sock.connect((referral, 43))
                ref_sock.sendall((domain + "\r\n").encode())
                ref_resp = b""
                while True:
                    chunk = ref_sock.recv(4096)
                    if not chunk:
                        break
                    ref_resp += chunk
                ref_sock.close()
                whois_text = ref_resp.decode("utf-8", errors="replace")
        except Exception as e:
            whois_text = f"WHOIS lookup failed: {e}"

    if not whois_text or "failed" in whois_text.lower():
        findings.append({
            "title": "WHOIS lookup incomplete",
            "severity": "info", "category": "WHOIS",
            "finding_type": ftype,
            "description": f"Could not retrieve complete WHOIS data for {domain}.",
            "file_path": "N/A", "line_number": 0,
            "evidence": whois_text[:500] if whois_text else "No data",
            "remediation": "Install whois CLI: apt-get install whois",
            "cwe_id": "", "source": "deterministic",
        })
        return findings

    # Parse key fields
    registrar = ""
    creation_date = ""
    expiry_date = ""
    nameservers = []
    registrant_email = ""

    for line in whois_text.split("\n"):
        ll = line.lower().strip()
        if not registrar:
            if "registrar:" in ll and "url" not in ll and "iana" not in ll:
                registrar = line.split(":", 1)[-1].strip()
        if not creation_date:
            if "creation date:" in ll or "created:" in ll:
                creation_date = line.split(":", 1)[-1].strip()
        if not expiry_date:
            if "registry expiry date:" in ll or "expiry date:" in ll or "paid-till:" in ll:
                expiry_date = line.split(":", 1)[-1].strip()
        if "name server:" in ll:
            ns = line.split(":", 1)[-1].strip().lower()
            if ns not in nameservers:
                nameservers.append(ns)
        if "registrant email:" in ll:
            registrant_email = line.split(":", 1)[-1].strip()

    evidence_parts = []
    if registrar:
        evidence_parts.append(f"Registrar: {registrar}")
    if creation_date:
        evidence_parts.append(f"Created: {creation_date}")
    if expiry_date:
        evidence_parts.append(f"Expires: {expiry_date}")
    if nameservers:
        evidence_parts.append(f"NS: {', '.join(nameservers[:5])}")

    # Check expiry
    if expiry_date:
        try:
            exp_date = None
            for fmt in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"]:
                try:
                    exp_date = datetime.strptime(expiry_date[:26], fmt)
                    break
                except ValueError:
                    continue
            if exp_date:
                days_left = (exp_date.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
                if days_left < 30:
                    findings.append({
                        "title": f"Domain expires in {days_left} days",
                        "severity": "high" if days_left < 7 else "medium",
                        "category": "WHOIS", "finding_type": ftype,
                        "description": f"Domain {domain} expires on {expiry_date}. Risk of domain loss.",
                        "file_path": "N/A", "line_number": 0,
                        "evidence": f"Expiry: {expiry_date} ({days_left} days)",
                        "remediation": "Renew the domain immediately. Enable auto-renewal.",
                        "cwe_id": "", "source": "deterministic",
                    })
        except Exception:
            pass

    findings.append({
        "title": f"WHOIS data for {domain}",
        "severity": "info", "category": "WHOIS",
        "finding_type": ftype,
        "description": f"WHOIS lookup complete. Registrar: {registrar or 'unknown'}.",
        "file_path": "N/A", "line_number": 0,
        "evidence": "\n".join(evidence_parts)[:500],
        "remediation": "Review WHOIS data. Consider WHOIS privacy protection.",
        "cwe_id": "", "source": "deterministic",
    })

    if registrant_email:
        findings.append({
            "title": f"Registrant email exposed in WHOIS: {registrant_email}",
            "severity": "low", "category": "Email Enumeration",
            "finding_type": "email",
            "description": f"Registrant email found in WHOIS. This is a target for phishing and social engineering.",
            "file_path": "N/A", "line_number": 0,
            "evidence": registrant_email,
            "remediation": "Enable WHOIS privacy protection to hide registrant contact details.",
            "cwe_id": "CWE-200", "source": "deterministic",
        })

    return findings


# ═══════════════════════════════════════════════════════════════
# MODULE 3 — SSL/TLS Certificate
# ═══════════════════════════════════════════════════════════════

def _collect_ssl(domain: str) -> list[dict]:
    findings = []
    ftype = "ssl"
    cert_text = ""

    # Try openssl s_client for detailed cert info (merge stdout+stderr)
    stdout, stderr, rc = _run([
        "openssl", "s_client", "-connect", f"{domain}:443",
        "-servername", domain, "-showcerts",
    ], timeout=15)
    if rc == 0 and (stdout or stderr):
        cert_text = stdout + stderr
    else:
        # Fallback: Python ssl module
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cert_text = json.dumps(cert, indent=2, default=str)
        except Exception as e:
            findings.append({
                "title": f"SSL connection failed for {domain}:443",
                "severity": "medium", "category": "SSL/TLS",
                "finding_type": ftype,
                "description": f"Could not establish TLS connection: {e}",
                "file_path": "N/A", "line_number": 0,
                "evidence": str(e)[:300],
                "remediation": "Verify port 443 is open and TLS is properly configured.",
                "cwe_id": "", "source": "deterministic",
            })

    if cert_text:
        # Parse with openssl x509
        stdout2, _, rc2 = _run([
            "openssl", "s_client", "-connect", f"{domain}:443",
            "-servername", domain,
        ], timeout=15)
        if rc2 == 0 and stdout2:
            # Pipe through x509
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as tf:
                tf.write(stdout2)
                temp_path = tf.name
            try:
                x509_out, _, rc3 = _run([
                    "openssl", "x509", "-in", temp_path, "-text", "-noout",
                    "-dates", "-subject", "-issuer",
                ], timeout=10)
                if rc3 == 0 and x509_out:
                    cert_text = x509_out
            finally:
                os.unlink(temp_path)

        # Parse key fields from cert text
        issuer = re.search(r'(?:issuer|Issuer)\s*[=:]\s*(.+)', cert_text, re.IGNORECASE)
        subject = re.search(r'(?:subject|Subject)\s*[=:]\s*(.+)', cert_text, re.IGNORECASE)
        not_before = re.search(r'(?:notBefore|Not Before)\s*[=:]\s*(.+)', cert_text, re.IGNORECASE)
        not_after = re.search(r'(?:notAfter|Not After)\s*[=:]\s*(.+)', cert_text, re.IGNORECASE)
        sans = re.findall(r'DNS:([\w.\-*]+)', cert_text)

        # SANs are highly valuable for subdomain enum
        if sans:
            unique_sans = sorted(set(s.strip() for s in sans if s.strip()))
            findings.append({
                "title": f"SSL Certificate SANs: {len(unique_sans)} subdomains",
                "severity": "info", "category": "SSL/TLS",
                "finding_type": ftype,
                "description": f"Subject Alternative Names reveal {len(unique_sans)} subdomains/domains covered by the certificate.",
                "file_path": "N/A", "line_number": 0,
                "evidence": "\n".join(unique_sans[:20]),
                "remediation": "Review SAN list. Remove any domains no longer owned or used.",
                "cwe_id": "CWE-200", "source": "deterministic",
            })

        # Expiry
        if not_after:
            exp_str = not_after.group(1).strip()
            # strip leading dot+whitespace (common in x509 output indentation)
            exp_str = re.sub(r'^\.\s*', '', exp_str)
            for fmt in ["%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z", "%Y-%m-%d %H:%M:%S",
                        "%b %d %H:%M:%S %Y", "%b  %d %H:%M:%S %Y"]:
                try:
                    exp_date = datetime.strptime(exp_str, fmt)
                    days = (exp_date - datetime.now()).days
                    sev = "critical" if days < 7 else "high" if days < 30 else "medium" if days < 90 else "info"
                    findings.append({
                        "title": f"SSL Certificate expires in {days} days ({exp_str})",
                        "severity": sev, "category": "SSL/TLS",
                        "finding_type": ftype,
                        "description": f"Certificate expires on {exp_str}. Service outage risk if not renewed.",
                        "file_path": "N/A", "line_number": 0,
                        "evidence": f"Not After: {exp_str}",
                        "remediation": "Renew certificate before expiry. Set up auto-renewal (Let's Encrypt / ACME).",
                        "cwe_id": "", "source": "deterministic",
                    })
                    break
                except ValueError:
                    continue

        issuer_str = re.sub(r'^\s*\.?\s*', '', issuer.group(1).strip()) if issuer else "unknown"
        findings.append({
            "title": f"SSL Certificate issued by: {issuer_str[:80]}",
            "severity": "info", "category": "SSL/TLS",
            "finding_type": ftype,
            "description": f"Certificate issuer identified.",
            "file_path": "N/A", "line_number": 0,
            "evidence": f"Issuer: {issuer_str}"[:300],
            "remediation": "",
            "cwe_id": "", "source": "deterministic",
        })

        # Weak TLS versions — merge stdout+stderr because openssl s_client
        # writes handshake/cert data to stderr
        old_tls_enabled = []
        for tls_ver, tls_name in [("tls1", "TLS 1.0"), ("tls1_1", "TLS 1.1")]:
            tls_out, tls_err, _ = _run([
                "openssl", "s_client", f"-{tls_ver}", "-connect", f"{domain}:443",
                "-servername", domain,
            ], timeout=10)
            combined = (tls_out + tls_err).lower()
            if combined and ("begin certificate" in combined or "server certificate" in combined):
                old_tls_enabled.append(tls_name)
                findings.append({
                    "title": f"{tls_name} enabled on {domain}",
                    "severity": "high", "category": "SSL/TLS",
                    "finding_type": ftype,
                    "description": f"{tls_name} is deprecated and vulnerable to attacks (POODLE, BEAST). Should be disabled.",
                    "file_path": "N/A", "line_number": 0,
                    "evidence": f"{tls_name} connection succeeded",
                    "remediation": f"Disable {tls_name}. Only allow TLS 1.2 and TLS 1.3.",
                    "cwe_id": "CWE-327", "source": "deterministic",
                })

        # Positive confirmation when both are disabled
        if not old_tls_enabled:
            findings.append({
                "title": "TLS 1.0/1.1 disabled",
                "severity": "info", "category": "SSL/TLS",
                "finding_type": ftype,
                "description": "TLS 1.0 and TLS 1.1 are not enabled. Only TLS 1.2+ accepted.",
                "file_path": "N/A", "line_number": 0,
                "evidence": "Neither TLS 1.0 nor TLS 1.1 connection succeeded",
                "remediation": "",
                "cwe_id": "", "source": "deterministic",
            })

    return findings


# ═══════════════════════════════════════════════════════════════
# MODULE 4 — Certificate Transparency (crt.sh + fallbacks)
# ═══════════════════════════════════════════════════════════════

def _try_crtsh(domain: str) -> tuple[set, set, int, str]:
    """Try crt.sh primary source. Returns (all_names, issuers, cert_count, source_name)."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=20, context=_UNVERIFIED_CTX) as resp:
        data = json.loads(resp.read())
    if not isinstance(data, list) or len(data) == 0:
        return set(), set(), 0, "crt.sh (empty)"
    all_names = set()
    issuers = set()
    for entry in data:
        name_val = entry.get("name_value", "").strip()
        issuer = entry.get("issuer_name", "").strip()
        if name_val:
            for n in name_val.split("\n"):
                n = n.strip().lower()
                if n and not n.startswith("*."):
                    all_names.add(n)
        if issuer:
            issuers.add(issuer)
    return all_names, issuers, len(data), "crt.sh"


def _try_certspotter(domain: str) -> tuple[set, set, int, str]:
    """Try Cert Spotter as fallback #1."""
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=15, context=_UNVERIFIED_CTX) as resp:
        data = json.loads(resp.read())
    if not isinstance(data, list):
        return set(), set(), 0, "certspotter (invalid)"
    all_names = set()
    for entry in data:
        dns_names = entry.get("dns_names") or []
        for n in dns_names:
            n = n.strip().lower()
            if n and not n.startswith("*."):
                all_names.add(n)
    return all_names, set(), len(data), "certspotter"


def _try_alienvault_otx(domain: str) -> tuple[set, set, int, str]:
    """Try AlienVault OTX passive DNS as fallback #2."""
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=15, context=_UNVERIFIED_CTX) as resp:
        data = json.loads(resp.read())
    if not isinstance(data, dict) or "passive_dns" not in data:
        return set(), set(), 0, "alienvault (invalid)"
    all_names = set()
    for entry in data["passive_dns"]:
        hostname = (entry.get("hostname") or "").strip().lower()
        if hostname and not hostname.startswith("*."):
            all_names.add(hostname)
    return all_names, set(), len(data.get("passive_dns", [])), "alienvault OTX"


def _collect_crtsh(domain: str) -> list[dict]:
    findings = []
    ftype = "ct"
    all_names = set()
    issuers = set()
    cert_count = 0
    sources_used = []
    errors = []

    for try_fn in [_try_crtsh, _try_certspotter, _try_alienvault_otx]:
        try:
            names, iss, count, src = try_fn(domain)
            if names:
                all_names.update(names)
                issuers.update(iss)
                cert_count += count
                sources_used.append(src)
                if len(all_names) >= 30:  # enough data, stop
                    break
            else:
                errors.append(f"{src}: no results")
        except Exception as e:
            errors.append(f"{try_fn.__name__}: {e}")

    if not all_names and not sources_used:
        findings.append({
            "title": "All certificate transparency sources failed",
            "severity": "info", "category": "Certificate Transparency",
            "finding_type": ftype,
            "description": f"No subdomain data from any source. Errors: {'; '.join(errors)}",
            "file_path": "N/A", "line_number": 0,
            "evidence": "; ".join(errors)[:500],
            "remediation": "Check crt.sh, certspotter.com, or otx.alienvault.com manually.",
            "cwe_id": "", "source": "deterministic",
        })
        return findings

    subdomains = sorted(n for n in all_names if n.endswith("." + domain) and n != domain)
    other_domains = sorted(n for n in all_names if not n.endswith("." + domain) and n != domain)

    source_label = " + ".join(sources_used)
    findings.append({
        "title": f"Certificate Transparency: {len(all_names)} names, {len(subdomains)} subdomains",
        "severity": "info", "category": "Certificate Transparency",
        "finding_type": ftype,
        "description": f"Found {len(all_names)} unique names from {source_label} ({cert_count} entries). {len(subdomains)} subdomains discovered.",
        "file_path": "N/A", "line_number": 0,
        "evidence": json.dumps({
            "sources": sources_used,
            "total_entries": cert_count,
            "unique_names": len(all_names),
            "subdomains": subdomains[:50],
            "other_domains": other_domains[:20],
            "issuers": sorted(issuers)[:10],
            "errors": errors[:5] if errors else [],
        }, indent=2),
        "remediation": "Review subdomains. Unknown subdomains may indicate shadow IT or forgotten infrastructure.",
        "cwe_id": "CWE-200", "source": "deterministic",
    })

    if len(subdomains) > 10:
        findings.append({
            "title": f"Large subdomain surface: {len(subdomains)} subdomains exposed via CT",
            "severity": "medium", "category": "Certificate Transparency",
            "finding_type": ftype,
            "description": f"{len(subdomains)} subdomains discovered. A large subdomain footprint increases the attack surface.",
            "file_path": "N/A", "line_number": 0,
            "evidence": f"First 20 subdomains: {', '.join(subdomains[:20])}",
            "remediation": "Audit subdomains. Remove DNS entries and certs for unused subdomains.",
            "cwe_id": "CWE-200", "source": "deterministic",
        })

    return findings


# ═══════════════════════════════════════════════════════════════
# MODULE 5 — HTTP Headers
# ═══════════════════════════════════════════════════════════════

def _collect_http_headers(domain: str) -> list[dict]:
    findings = []
    ftype = "http"
    headers = _http_get_headers(f"https://{domain}", timeout=10)
    if headers is None:
        headers = _http_get_headers(f"http://{domain}", timeout=10)
    if headers is None:
        findings.append({
            "title": f"Could not connect to {domain} via HTTP/HTTPS",
            "severity": "medium", "category": "HTTP Headers",
            "finding_type": ftype,
            "description": f"HTTP GET to {domain} failed. The server might be down, blocking requests, or using a non-standard port.",
            "file_path": "N/A", "line_number": 0,
            "evidence": "Connection failed",
            "remediation": "Verify web server is running and accessible.",
            "cwe_id": "", "source": "deterministic",
        })
        return findings

    # Normalize header keys to lowercase
    h = {k.lower(): v for k, v in headers.items()}

    # Security headers checklist
    checks = [
        ("strict-transport-security", "HSTS (HTTP Strict Transport Security)",
         "Prevents downgrade attacks and cookie hijacking. Ensures HTTPS-only communication.",
         "high", "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"),
        ("content-security-policy", "CSP (Content Security Policy)",
         "Prevents XSS, clickjacking, and code injection by restricting resource sources.",
         "high", "Add: Content-Security-Policy: default-src 'self'; script-src 'self'"),
        ("x-content-type-options", "X-Content-Type-Options",
         "Prevents MIME type sniffing that could lead to XSS.",
         "medium", "Add: X-Content-Type-Options: nosniff"),
        ("x-frame-options", "X-Frame-Options",
         "Prevents clickjacking by controlling iframe embedding.",
         "medium", "Add: X-Frame-Options: DENY or SAMEORIGIN"),
        ("referrer-policy", "Referrer-Policy",
         "Controls how much referrer information is sent with requests.",
         "low", "Add: Referrer-Policy: strict-origin-when-cross-origin"),
        ("permissions-policy", "Permissions-Policy",
         "Restricts browser features (camera, mic, geolocation).",
         "low", "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"),
    ]

    present_headers = []
    missing_headers = []
    for header_key, name, desc, sev, remediation in checks:
        if header_key not in h:
            missing_headers.append(name)
            findings.append({
                "title": f"Missing security header: {name}",
                "severity": sev, "category": "HTTP Headers",
                "finding_type": ftype,
                "description": f"{desc}",
                "file_path": "N/A", "line_number": 0,
                "evidence": f"Header '{header_key}' not found in response",
                "remediation": remediation,
                "cwe_id": "CWE-693", "source": "deterministic",
            })
        else:
            present_headers.append(name)

    # Summary finding — confirms which headers were checked
    findings.append({
        "title": f"HTTP security headers: {len(present_headers)} present, {len(missing_headers)} missing",
        "severity": "info", "category": "HTTP Headers",
        "finding_type": ftype,
        "description": f"Checked {len(checks)} security headers. "
                       f"Present: {', '.join(present_headers) if present_headers else 'none'}. "
                       f"Missing: {', '.join(missing_headers) if missing_headers else 'none'}.",
        "file_path": "N/A", "line_number": 0,
        "evidence": f"Present: {len(present_headers)}/{len(checks)}",
        "remediation": "",
        "cwe_id": "", "source": "deterministic",
    })

    # Check for header value weaknesses
    if "strict-transport-security" in h:
        hsts = h["strict-transport-security"].lower()
        if "max-age=" in hsts:
            try:
                max_age = int(re.search(r'max-age=(\d+)', hsts).group(1))
                if max_age < 31536000:
                    findings.append({
                        "title": f"HSTS max-age too short: {max_age}s (min recommended: 31536000s)",
                        "severity": "low", "category": "HTTP Headers",
                        "finding_type": ftype,
                        "description": "Short HSTS max-age reduces protection window.",
                        "file_path": "N/A", "line_number": 0,
                        "evidence": f"HSTS: {h['strict-transport-security'][:120]}",
                        "remediation": "Set max-age to at least 31536000 (1 year).",
                        "cwe_id": "CWE-693", "source": "deterministic",
                    })
            except Exception:
                pass
            if "includeSubDomains" not in hsts:
                findings.append({
                    "title": "HSTS missing includeSubDomains directive",
                    "severity": "low", "category": "HTTP Headers",
                    "finding_type": ftype,
                    "description": "Without includeSubDomains, subdomains are not protected by HSTS.",
                    "file_path": "N/A", "line_number": 0,
                    "evidence": f"HSTS: {h['strict-transport-security'][:120]}",
                    "remediation": "Add includeSubDomains to HSTS header.",
                    "cwe_id": "CWE-693", "source": "deterministic",
                })

    # Server / technology disclosure
    if "server" in h:
        findings.append({
            "title": f"Server header leaks version info: {h['server']}",
            "severity": "low", "category": "HTTP Headers",
            "finding_type": ftype,
            "description": "The Server header reveals the web server and version, helping attackers target version-specific exploits.",
            "file_path": "N/A", "line_number": 0,
            "evidence": f"Server: {h['server']}",
            "remediation": "Configure the web server to hide or genericize the Server header.",
            "cwe_id": "CWE-200", "source": "deterministic",
        })
    if "x-powered-by" in h:
        findings.append({
            "title": f"X-Powered-By leaks framework info: {h['x-powered-by']}",
            "severity": "low", "category": "HTTP Headers",
            "finding_type": ftype,
            "description": "X-Powered-By header reveals backend technology stack.",
            "file_path": "N/A", "line_number": 0,
            "evidence": f"X-Powered-By: {h['x-powered-by']}",
            "remediation": "Remove X-Powered-By header from server configuration.",
            "cwe_id": "CWE-200", "source": "deterministic",
        })

    # Cookies security check
    cookies = h.get("set-cookie", "")
    if cookies:
        cookie_issues = []
        if "secure" not in cookies.lower():
            cookie_issues.append("missing Secure flag")
        if "httponly" not in cookies.lower():
            cookie_issues.append("missing HttpOnly flag")
        if "samesite" not in cookies.lower():
            cookie_issues.append("missing SameSite attribute")
        if cookie_issues:
            findings.append({
                "title": f"Cookie security issues: {', '.join(cookie_issues)}",
                "severity": "medium", "category": "HTTP Headers",
                "finding_type": ftype,
                "description": "Cookies set without proper security attributes are vulnerable to theft and session hijacking.",
                "file_path": "N/A", "line_number": 0,
                "evidence": cookies[:300],
                "remediation": "Set Secure, HttpOnly, and SameSite=Lax/Strict on all cookies.",
                "cwe_id": "CWE-614", "source": "deterministic",
            })

    return findings


# ═══════════════════════════════════════════════════════════════
# MODULE 6 — robots.txt / sitemap.xml / security.txt
# ═══════════════════════════════════════════════════════════════

def _collect_web_paths(domain: str) -> list[dict]:
    findings = []
    ftype = "paths"

    # robots.txt
    robots_url = f"https://{domain}/robots.txt"
    robots_txt = _http_get(robots_url, timeout=8)
    if robots_txt is None:
        robots_txt = _http_get(f"http://{domain}/robots.txt", timeout=8)

    if robots_txt:
        disallowed = re.findall(r'Disallow:\s*(/.+)', robots_txt, re.IGNORECASE)
        sitemaps = re.findall(r'^Sitemap:\s*(.+)$', robots_txt, re.IGNORECASE | re.MULTILINE)
        if disallowed:
            findings.append({
                "title": f"robots.txt: {len(disallowed)} disallowed paths",
                "severity": "info", "category": "Web Paths",
                "finding_type": ftype,
                "description": "robots.txt reveals paths the site owner wants hidden from crawlers. Attackers check these first.",
                "file_path": "N/A", "line_number": 0,
                "evidence": "\n".join(disallowed[:15]),
                "remediation": "Sensitive paths should be protected by authentication, not just robots.txt.",
                "cwe_id": "CWE-200", "source": "deterministic",
            })
        if sitemaps:
            findings.append({
                "title": f"robots.txt references {len(sitemaps)} sitemap(s)",
                "severity": "info", "category": "Web Paths",
                "finding_type": ftype,
                "description": f"Sitemap URLs found: {', '.join(sitemaps[:5])}",
                "file_path": "N/A", "line_number": 0,
                "evidence": "\n".join(sitemaps[:5]),
                "remediation": "Review sitemap content. Ensure no internal/dev endpoints are exposed.",
                "cwe_id": "CWE-200", "source": "deterministic",
            })
    else:
        findings.append({
            "title": "No robots.txt found",
            "severity": "info", "category": "Web Paths",
            "finding_type": ftype,
            "description": f"No robots.txt at {domain}. The site is fully crawlable (or the file is blocked).",
            "file_path": "N/A", "line_number": 0,
            "evidence": "No robots.txt",
            "remediation": "Add robots.txt to guide legitimate crawlers. Do NOT use it for security.",
            "cwe_id": "", "source": "deterministic",
        })

    # sitemap.xml
    sitemap_url = f"https://{domain}/sitemap.xml"
    sitemap_txt = _http_get(sitemap_url, timeout=10)
    if sitemap_txt:
        urls = re.findall(r'<loc>\s*(https?://[^<]+)\s*</loc>', sitemap_txt)
        findings.append({
            "title": f"sitemap.xml: {len(urls)} URLs exposed",
            "severity": "info", "category": "Web Paths",
            "finding_type": ftype,
            "description": f"Sitemap enumerates {len(urls)} URLs, providing a map of the site structure to attackers.",
            "file_path": "N/A", "line_number": 0,
            "evidence": "\n".join(urls[:20]),
            "remediation": "Review sitemap content. Remove any staging, admin, or internal URLs.",
            "cwe_id": "CWE-200", "source": "deterministic",
        })

    # security.txt
    sec_url = f"https://{domain}/.well-known/security.txt"
    sec_txt = _http_get(sec_url, timeout=8)
    if sec_txt:
        contact = re.search(r'^Contact:\s*(.+)$', sec_txt, re.IGNORECASE | re.MULTILINE)
        expiry = re.search(r'^Expires:\s*(.+)$', sec_txt, re.IGNORECASE | re.MULTILINE)
        findings.append({
            "title": f"security.txt found" + (f" — Contact: {contact.group(1)}" if contact else ""),
            "severity": "info", "category": "Web Paths",
            "finding_type": ftype,
            "description": "security.txt provides vulnerability disclosure contact information.",
            "file_path": "N/A", "line_number": 0,
            "evidence": sec_txt[:500],
            "remediation": "Keep security.txt up-to-date with accurate contact and expiry.",
            "cwe_id": "", "source": "deterministic",
        })
    else:
        findings.append({
            "title": "No security.txt found",
            "severity": "low", "category": "Web Paths",
            "finding_type": ftype,
            "description": "Missing .well-known/security.txt. Security researchers have no clear way to report vulnerabilities.",
            "file_path": "N/A", "line_number": 0,
            "evidence": "No security.txt",
            "remediation": "Add /.well-known/security.txt per RFC 9116 with a Contact field.",
            "cwe_id": "", "source": "deterministic",
        })

    return findings


# ═══════════════════════════════════════════════════════════════
# MODULE 7 — Technology Fingerprinting
# ═══════════════════════════════════════════════════════════════

def _collect_tech_fingerprint(domain: str) -> list[dict]:
    findings = []
    ftype = "tech"
    html = _http_get(f"https://{domain}", timeout=10)
    if html is None:
        html = _http_get(f"http://{domain}", timeout=10)

    # Also fetch HTTP response headers for server/framework leaks
    resp_headers = _http_get_headers(f"https://{domain}", timeout=10)
    if resp_headers is None:
        resp_headers = _http_get_headers(f"http://{domain}", timeout=10)
    resp_headers = resp_headers or {}

    detected = []

    # ── nmap service detection ──
    nmap_out, _, nmap_rc = _run([
        "nmap", "-sV", "--top-ports", "20", "--open", "-T4", domain,
    ], timeout=60)
    if nmap_rc == 0 and nmap_out:
        for line in nmap_out.split("\n"):
            # Parse lines like: "80/tcp   open  http    nginx 1.18.0"
            m = re.match(r'(\d+/tcp)\s+open\s+(\S+)\s+(.+)', line)
            if m:
                port = m.group(1)
                service = m.group(2)
                version = m.group(3).strip()
                label = f"{service}/{port}" if version == service else f"{service}/{port}: {version}"
                detected.append((f"nmap: {label}", version))

    if html is None and not resp_headers and not detected:
        return findings

    # ── Header-based detection ──
    h = {k.lower(): v for k, v in resp_headers.items()}

    if "server" in h:
        detected.append(("Web Server", h["server"]))

    if "x-powered-by" in h:
        detected.append(("Framework (header)", h["x-powered-by"]))

    if "x-generator" in h:
        detected.append(("Generator (header)", h["x-generator"]))

    # WAF / CDN from headers
    waf_headers = {
        "x-cdn": "CDN",
        "cf-ray": "Cloudflare",
        "x-amz-cf-id": "CloudFront",
        "x-sucuri-id": "Sucuri WAF",
        "x-waf": "WAF",
        "x-fw": "Firewall",
        "x-akamai": "Akamai",
        "x-fastly": "Fastly",
        "x-varnish": "Varnish",
    }
    for hdr, label in waf_headers.items():
        if hdr in h:
            detected.append((f"CDN/WAF: {label}", h[hdr][:80]))

    # Cookies can reveal framework
    cookies = h.get("set-cookie", "")
    cookie_frameworks = {
        "PHPSESSID": "PHP",
        "JSESSIONID": "Java/JSP",
        "ASP.NET_SessionId": "ASP.NET",
        "laravel_session": "Laravel",
        "SSESS": "Drupal",
        "wp-settings": "WordPress",
        "wordpress_logged_in": "WordPress",
        "django_language": "Django",
        "rack.session": "Ruby/Rack",
        "_rails": "Ruby on Rails",
    }
    for ck, label in cookie_frameworks.items():
        if ck.lower() in cookies.lower():
            detected.append((f"Framework (cookie): {label}", ck))

    if not html:
        if detected:
            findings.append({
                "title": f"Technology fingerprint: {len(detected)} components detected",
                "severity": "info", "category": "Technology Fingerprinting",
                "finding_type": ftype,
                "description": f"Detected technologies from {domain} response headers.",
                "file_path": "N/A", "line_number": 0,
                "evidence": json.dumps([f"{name}: {ver}" for name, ver in detected], indent=1),
                "remediation": "Review technology stack. Ensure all components are up-to-date with security patches.",
                "cwe_id": "CWE-200", "source": "deterministic",
            })
        return findings

    # ── Frontend build tooling from HTML comments & source maps ──
    build_tools = {
        "Vite": r'(?:vite|@vite)\s*\(|/assets/.*?\.[a-f0-9]{8,}\.|type=["\']module["\'].*?src=["\']/assets/',
        "Webpack": r'webpack(?:Jsonp|Bootstrap|Chunk)|/js/bundle\.[a-f0-9]{8,}\.js|webpack-dev-server',
        "esbuild": r'esbuild|/esbuild/',
        "Parcel": r'/dist/.*?\.[a-f0-9]{8,}\.|parcelRequire',
        "Rollup": r'rollup',
        "Gulp": r'gulp',
        "Grunt": r'grunt',
    }
    for tool, pattern in build_tools.items():
        if re.search(pattern, html, re.IGNORECASE):
            detected.append((f"Build tool: {tool}", ""))

    # Source map references
    sm = re.search(r'sourceMappingURL=([^\s"\']+)', html, re.IGNORECASE)
    if sm:
        detected.append(("Source Map", sm.group(1)[:80]))

    # ── Meta generator ──
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
    if gen:
        detected.append(("Meta Generator", gen.group(1)))

    # ── CMS / Framework detection from HTML ──
    cms_patterns = {
        "WordPress": [
            r'wp-content/(?:uploads|plugins|themes)/',
            r'wp-json/',
            r'wp-includes/',
            r'<link[^>]+wp-content/themes/',
            r'name=["\']generator["\']\s*content=["\']WordPress',
        ],
        "Drupal": [
            r'drupal\.js|drupal\.css',
            r'/sites/default/files/',
            r'misc/drupal\.js',
        ],
        "Joomla": [
            r'/media/jui/',
            r'/templates/.*?joomla',
            r'name=["\']generator["\']\s*content=["\']Joomla',
        ],
        "Django": [
            r'csrftoken\s*=',
            r'__django|django\.jet',
        ],
        "Ruby on Rails": [
            r'<meta[^>]+name=["\']csrf-param["\']',
            r'data-turbolinks|rails-ujs',
        ],
        "Laravel": [
            r'laravel\s*=\s*\{',
            r'csrf-token.*?content=["\']',
            r'vendor/laravel',
        ],
        "Next.js": [
            r'/_next/static/',
            r'__NEXT_DATA__',
            r'<div\s+id=["\']__next["\']',
        ],
        "Nuxt.js": [
            r'__NUXT__',
            r'/_nuxt/',
        ],
        "Gatsby": [
            r'<div\s+id=["\']___gatsby["\']',
            r'/_gatsby/',
        ],
        "Shopify": [
            r'cdn\.shopify\.com',
            r'myshopify\.com',
            r'Shopify\.',
        ],
    }
    for cms_name, patterns in cms_patterns.items():
        for pat in patterns:
            if re.search(pat, html, re.IGNORECASE):
                detected.append((f"CMS: {cms_name}", ""))
                break

    # ── JS frameworks from script src (enhanced) ──
    js_libs = {
        "React": r'react(?:\.production\.min)?\.js[\"\'](?:\s+[^>]*)?>|React(?:\.version)?\s*=\s*["\'](\d+\.\d+\.\d+)["\']|react-dom(?:\.production\.min)?\.js',
        "Vue.js": r'vue(?:\.runtime)?(?:\.[\d.]+)?(?:\.prod)?\.js|Vue(?:\.version)?\s*=\s*["\'](\d+\.\d+\.\d+)["\']',
        "Angular": r'angular(?:\.min)?\.js|ng-app|ng-version=["\']([^"\']+)["\']|@angular/',
        "jQuery": r'jquery(?:\.min)?\.js\?(?:v=)?(\d+\.\d+\.\d+)|jQuery\s+v(\d+\.\d+\.\d+)',
        "Bootstrap": r'bootstrap(?:\.bundle)?(?:\.min)?\.(?:js|css)\?(?:v=)?(\d+\.\d+\.\d+)|Bootstrap\s+v?(\d+\.\d+\.\d+)',
        "Tailwind CSS": r'tailwindcss\s*(?:@)?(\d+\.\d+\.\d+)|tailwind\.config|tailwindcss',
        "Svelte": r'svelte(?:@|/)?(\d+\.\d+\.\d+)?',
        "Alpine.js": r'alpine(?:js)?\s*(?:@)?(\d+\.\d+\.\d+)|x-data\s*=',
        "HTMX": r'htmx\.org|htmx(?:@|/)?(\d+\.\d+\.\d+)?|hx-get|hx-post',
        "jQuery UI": r'jquery-ui(?:\.min)?\.(?:js|css)',
        "Moment.js": r'moment(?:\.min)?\.js|moment-with-locales',
        "Chart.js": r'chart(?:\.min)?\.js|Chart\.js',
        "Three.js": r'three(?:\.min)?\.js|three\.module',
        "D3.js": r'd3(?:\.min)?\.js|d3\.v\d+',
        "Axios": r'axios(?:\.min)?\.js|axios(?:@|/)?(\d+\.\d+\.\d+)',
        "Lodash": r'lodash(?:\.min)?\.js|lodash\.core',
        "GSAP": r'gsap(?:\.min)?\.js|TweenMax|TweenLite',
        "Framer Motion": r'framer-motion|framerMotion',
        "Redux": r'redux(?:\.min)?\.js|redux\.js',
        "Socket.IO": r'socket\.io\.js|socket\.io-client',
        "Google Analytics": r'google-analytics\.com/analytics\.js|gtag\s*\(\s*["\']config["\']',
        "Google Tag Manager": r'googletagmanager\.com/gtm\.js',
        "Hotjar": r'hotjar\.com|hjSettings',
        "Sentry": r'@sentry/|sentry\.init|sentry-cdn\.com',
        "Stripe": r'stripe\.com|@stripe/|js\.stripe\.com',
        "Livewire": r'livewire(?:\.min)?\.js|@livewire',
    }
    for lib, pattern in js_libs.items():
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            ver = ""
            if m.lastindex and m.lastindex >= 1:
                for g in m.groups():
                    if g:
                        ver = g
                        break
            detected.append((lib, ver or "detected"))

    # ── CSS frameworks ──
    css_libs = {
        "Bootstrap CSS": r'bootstrap(?:\.min)?\.css\?(?:v=)?(\d+\.\d+\.\d+)',
        "Tailwind CSS": r'tailwindcss(?:\s*@)?(\d+\.\d+\.\d+)|tailwind\.config',
        "Bulma": r'bulma(?:\.min)?\.css\?(?:v=)?(\d+\.\d+\.\d+)',
        "Foundation": r'foundation(?:\.min)?\.css',
        "Material UI": r'mui|material-ui|@mui/',
        "Semantic UI": r'semantic(?:\.min)?\.css|semantic-ui',
        "Ant Design": r'antd(?:\.min)?\.css|ant-design',
        "Chakra UI": r'@chakra-ui/',
        "Font Awesome": r'font-?awesome(?:\.min)?\.css|fontawesome',
    }
    for lib, pattern in css_libs.items():
        m = re.search(pattern, html, re.IGNORECASE)
        if m and lib not in [d[0] for d in detected]:
            ver = m.group(1) if m.lastindex and m.group(1) else ""
            detected.append((lib, ver or "detected"))

    # ── Server-side tech from HTML comments ──
    ss_patterns = {
        "PHP": r'<!--\s*(?:This is|Powered by|Generated by).*PHP',
        "ASP.NET": r'<!--\s*(?:This is|\.NET)',
        "nginx": r'<!--\s*nginx',
    }

    # ── CDN detection ──
    cdn_patterns = {
        "Cloudflare": r'cdn\.cloudflare\.com|cloudflareinsights\.com|cfl\.ly',
        "CloudFront": r'cloudfront\.net|d\w+\.cloudfront\.net',
        "Fastly": r'fastly\.net|fastly-insights\.com',
        "Akamai": r'akamai(?:hd)?\.net|akamaized\.net|aks-\w+\.',
        "Bunny CDN": r'bunny\.net|b-cdn\.net|bunnycdn\.ru',
        "KeyCDN": r'cdn\.keycdn\.com|kxcdn\.com',
        "Google CDN": r'ajax\.googleapis\.com|fonts\.googleapis\.com',
        "jsDelivr": r'cdn\.jsdelivr\.net|jsdelivr\.net',
        "Unpkg": r'unpkg\.com/',
        "Skypack": r'cdn\.skypack\.dev',
    }
    for cdn, pattern in cdn_patterns.items():
        if re.search(pattern, html, re.IGNORECASE):
            detected.append((f"CDN: {cdn}", ""))

    if detected:
        # Deduplicate by name
        seen_names = set()
        unique_detected = []
        for name, ver in detected:
            base = name.split(":")[0].strip()
            if base not in seen_names:
                seen_names.add(base)
                unique_detected.append((name, ver))

        findings.append({
            "title": f"Technology fingerprint: {len(unique_detected)} components detected",
            "severity": "info", "category": "Technology Fingerprinting",
            "finding_type": ftype,
            "description": f"Detected technologies from {domain} frontend and response headers.",
            "file_path": "N/A", "line_number": 0,
            "evidence": json.dumps([f"{name}: {ver}" for name, ver in unique_detected], indent=1),
            "remediation": "Review technology stack. Ensure all components are up-to-date with security patches.",
            "cwe_id": "CWE-200", "source": "deterministic",
        })

        findings.append({
            "title": f"Detected components for CVE analysis",
            "severity": "info", "category": "Technology Fingerprinting",
            "finding_type": ftype,
            "description": f"Components detected that will be checked for known CVEs.",
            "file_path": "N/A", "line_number": 0,
            "evidence": json.dumps({name: ver for name, ver in unique_detected}),
            "remediation": "",
            "cwe_id": "", "source": "deterministic",
        })

    return findings


# ═══════════════════════════════════════════════════════════════
# MODULE 8 — Email Enumeration
# ═══════════════════════════════════════════════════════════════

def _collect_emails(domain: str) -> list[dict]:
    findings = []
    ftype = "email"

    # From website HTML
    html = _http_get(f"https://{domain}", timeout=10)
    if html:
        mailtos = re.findall(r'mailto:([\w.\-+]+@[\w.\-]+)', html, re.IGNORECASE)
        email_pattern = re.findall(r'[\w.\-+]+@[\w.\-]+\.\w{2,}', html)
        all_found = sorted(set(mailtos + email_pattern))
        domain_emails = [e for e in all_found if e.lower().endswith("@" + domain)]

        if domain_emails:
            findings.append({
                "title": f"Email addresses exposed on website: {len(domain_emails)} found",
                "severity": "low", "category": "Email Enumeration",
                "finding_type": ftype,
                "description": f"Email addresses found in {domain}'s HTML. These are targets for phishing, spam, and social engineering.",
                "file_path": "N/A", "line_number": 0,
                "evidence": ", ".join(domain_emails[:15]),
                "remediation": "Obfuscate email addresses on public pages or use contact forms instead.",
                "cwe_id": "CWE-200", "source": "deterministic",
            })

        if all_found:
            external_emails = [e for e in all_found if not e.lower().endswith("@" + domain)]
            if external_emails:
                findings.append({
                    "title": f"External email references: {len(external_emails)} found",
                    "severity": "info", "category": "Email Enumeration",
                    "finding_type": ftype,
                    "description": "External email addresses referenced — potential third-party relationships exposed.",
                    "file_path": "N/A", "line_number": 0,
                    "evidence": ", ".join(external_emails[:10]),
                    "remediation": "Review external email references for unintended disclosure.",
                    "cwe_id": "CWE-200", "source": "deterministic",
                })

    return findings


# ═══════════════════════════════════════════════════════════════
# MODULE 9 — Wayback Machine
# ═══════════════════════════════════════════════════════════════

def _collect_wayback(domain: str) -> list[dict]:
    findings = []
    ftype = "wayback"
    url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original,timestamp,statuscode&limit=500"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30, context=_UNVERIFIED_CTX) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        findings.append({
            "title": "Wayback Machine lookup failed",
            "severity": "info", "category": "Wayback Machine",
            "finding_type": ftype,
            "description": f"Could not query web.archive.org: {e}",
            "file_path": "N/A", "line_number": 0,
            "evidence": str(e)[:300],
            "remediation": "Check manually: https://web.archive.org/web/*/{domain}",
            "cwe_id": "", "source": "deterministic",
        })
        return findings

    if not isinstance(data, list) or len(data) <= 1:
        findings.append({
            "title": "No Wayback Machine snapshots found",
            "severity": "info", "category": "Wayback Machine",
            "finding_type": ftype,
            "description": f"No historical snapshots for {domain}.",
            "file_path": "N/A", "line_number": 0,
            "evidence": "No archives",
            "remediation": "",
            "cwe_id": "", "source": "deterministic",
        })
        return findings

    # Parse — first row is headers
    rows = data[1:] if len(data) > 1 else []
    urls = set()
    timestamps = []
    for row in rows:
        if len(row) >= 3:
            urls.add(row[0])
            timestamps.append(row[1])

    unique_urls = sorted(urls)

    if timestamps:
        oldest = min(timestamps)
        newest = max(timestamps)
        findings.append({
            "title": f"Wayback Machine: {len(rows)} snapshots, {len(unique_urls)} unique URLs",
            "severity": "info", "category": "Wayback Machine",
            "finding_type": ftype,
            "description": f"Historical snapshots from {oldest} to {newest}. Old versions may expose since-removed endpoints, secrets, or vulnerable code.",
            "file_path": "N/A", "line_number": 0,
            "evidence": json.dumps({
                "total_snapshots": len(rows),
                "unique_urls": len(unique_urls),
                "oldest_snapshot": oldest,
                "newest_snapshot": newest,
                "sample_urls": unique_urls[:30],
            }, indent=2),
            "remediation": "Review historical URLs for exposed sensitive information. Consider requesting removal of sensitive snapshots from archive.org.",
            "cwe_id": "CWE-200", "source": "deterministic",
        })

    return findings


# ═══════════════════════════════════════════════════════════════
# MODULE 10 — GitHub Dorks
# ═══════════════════════════════════════════════════════════════

def _collect_github_dorks(domain: str) -> list[dict]:
    findings = []
    ftype = "github"

    queries = [domain, f"{domain} password", f"{domain} secret", f"{domain} api_key",
               f"{domain} token", f"{domain} config", f"{domain} .env"]

    total_hits = 0
    samples = []

    for query in queries[:3]:  # limit to avoid rate limiting
        try:
            encoded = urllib.parse.quote(query)
            req = urllib.request.Request(
                f"https://api.github.com/search/code?q={encoded}&per_page=10",
                headers={"Accept": "application/vnd.github.v3+json", "User-Agent": "Elyria-OSINT"}
            )
            with urllib.request.urlopen(req, timeout=10, context=_UNVERIFIED_CTX) as resp:
                result = json.loads(resp.read())
                count = result.get("total_count", 0)
                total_hits += count
                for item in result.get("items", [])[:3]:
                    samples.append({
                        "repo": item.get("repository", {}).get("full_name", ""),
                        "path": item.get("path", ""),
                    })
        except Exception:
            pass
        time.sleep(1.5)  # rate limit respect

    if total_hits > 0:
        findings.append({
            "title": f"GitHub code search: {total_hits} matches for '{domain}'",
            "severity": "medium" if total_hits > 5 else "low",
            "category": "GitHub Dorks",
            "finding_type": ftype,
            "description": f"Code referencing {domain} was found on GitHub. May include leaked configs, keys, or internal documentation.",
            "file_path": "N/A", "line_number": 0,
            "evidence": json.dumps({"total_hits": total_hits, "samples": samples}, indent=2),
            "remediation": "Search GitHub for leaked secrets related to your organization. Use git-secrets or truffleHog to scan your own repos.",
            "cwe_id": "CWE-200", "source": "deterministic",
        })
    else:
        findings.append({
            "title": f"No GitHub code references found for '{domain}'",
            "severity": "info", "category": "GitHub Dorks",
            "finding_type": ftype,
            "description": f"No public GitHub code matches for {domain}.",
            "file_path": "N/A", "line_number": 0,
            "evidence": "0 results from GitHub code search",
            "remediation": "",
            "cwe_id": "", "source": "deterministic",
        })

    return findings


# ═══════════════════════════════════════════════════════════════
# MODULE 11 — Google Dorks (via DuckDuckGo)
# ═══════════════════════════════════════════════════════════════

def _collect_google_dorks(domain: str) -> list[dict]:
    findings = []
    ftype = "google"

    dorks = [
        f"site:{domain}",
        f"site:{domain} filetype:pdf",
        f"site:{domain} filetype:env",
        f'site:{domain} "api key"',
        f'site:{domain} "password"',
        f'site:{domain} "config"',
        f'site:{domain} "admin"',
    ]

    results_summary = []
    total_indexed = 0

    for dork in dorks[:4]:  # limit to be respectful
        try:
            encoded = urllib.parse.quote(dork)
            html = _http_get(f"https://html.duckduckgo.com/html/?q={encoded}", timeout=10)
            if html:
                snippets = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', html, re.DOTALL)
                clean = [re.sub(r'<[^>]+>', '', s).strip()[:200] for s in snippets[:5]]
                count = len(clean)
                total_indexed += count
                if clean:
                    results_summary.append({"dork": dork, "results": count, "samples": clean[:3]})
        except Exception:
            pass
        time.sleep(1)  # rate limit

    findings.append({
        "title": f"Dork scan: ~{total_indexed} results across {len(dorks)} queries",
        "severity": "info", "category": "Google Dorks",
        "finding_type": ftype,
        "description": f"Search engine reconnaissance for {domain}. Publicly indexed pages may expose sensitive information.",
        "file_path": "N/A", "line_number": 0,
        "evidence": json.dumps(results_summary, indent=2),
        "remediation": "Use robots.txt + noindex for sensitive pages. Regularly audit what search engines have indexed (site:domain).",
        "cwe_id": "CWE-200", "source": "deterministic",
    })

    return findings


# ═══════════════════════════════════════════════════════════════
# MODULE 12 — Frontend Code Analysis
# ═══════════════════════════════════════════════════════════════
# Fetches HTML, JS, CSS from target. Runs:
#   1. Hardcoded secret scan on frontend code
#   2. API endpoint discovery in JS
#   3. CVE lookup on detected JS components
#   4. AI deobfuscator for minified JS (if AI configured)

def _collect_frontend(domain: str, ai_provider=None) -> list[dict]:
    findings = []
    ftype = "frontend"

    html = _http_get(f"https://{domain}", timeout=10)
    if html is None:
        html = _http_get(f"http://{domain}", timeout=10)
    if html is None:
        findings.append({
            "title": "Could not fetch frontend code for analysis",
            "severity": "info", "category": "Frontend Code",
            "finding_type": ftype,
            "description": f"HTTP GET to {domain} failed. Cannot analyze frontend.",
            "file_path": "N/A", "line_number": 0,
            "evidence": "HTTP request failed",
            "remediation": "Verify web server is running.",
            "cwe_id": "", "source": "deterministic",
        })
        return findings

    # Extract script sources
    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
    link_hrefs = re.findall(r'<link[^>]+href=["\']([^"\']+\.css[^"\']*)["\']', html, re.IGNORECASE)
    inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)

    all_js_code = ""
    all_css_code = ""

    # Collect external JS
    js_files_found = []
    for src in script_srcs[:20]:
        full_url = src
        if src.startswith("//"):
            full_url = "https:" + src
        elif src.startswith("/"):
            full_url = f"https://{domain}{src}"
        elif not src.startswith("http"):
            full_url = f"https://{domain}/{src}"
        js_content = _http_get(full_url, timeout=8)
        if js_content:
            js_files_found.append({"url": full_url, "size": len(js_content)})
            all_js_code += "\n" + js_content

    # Collect external CSS
    for href in link_hrefs[:10]:
        full_url = href
        if href.startswith("//"):
            full_url = "https:" + href
        elif href.startswith("/"):
            full_url = f"https://{domain}{href}"
        elif not href.startswith("http"):
            full_url = f"https://{domain}/{href}"
        css_content = _http_get(full_url, timeout=8)
        if css_content:
            all_css_code += "\n" + css_content

    # Add inline scripts
    for s in inline_scripts:
        all_js_code += "\n" + s.strip()

    # 1. Hardcoded secrets in frontend code
    secret_findings = _scan_frontend_secrets(html, all_js_code, domain)
    findings.extend(secret_findings)

    # 2. API endpoint discovery in JS
    endpoint_findings = _scan_frontend_endpoints(all_js_code, domain)
    findings.extend(endpoint_findings)

    # 3. JS file summary
    findings.append({
        "title": f"Frontend code collected: {len(js_files_found)} JS files, {len(script_srcs)} scripts total",
        "severity": "info", "category": "Frontend Code",
        "finding_type": ftype,
        "description": f"JS files fetched from {domain}. Total JS code size: {len(all_js_code)} chars.",
        "file_path": "N/A", "line_number": 0,
        "evidence": json.dumps(js_files_found[:20], indent=2),
        "remediation": "Review each JS file for sensitive logic, API keys, and internal endpoints.",
        "cwe_id": "", "source": "deterministic",
    })

    # 4. CVE lookup on detected components
    cve_findings = _check_frontend_cves(html, all_js_code, domain)
    findings.extend(cve_findings)

    # 5. AI deobfuscation of minified JS
    if ai_provider and all_js_code:
        deob_findings = _ai_deobfuscate(ai_provider, all_js_code, domain)
        findings.extend(deob_findings)

    return findings


def _scan_frontend_secrets(html: str, js_code: str, domain: str) -> list[dict]:
    """Scan frontend code for hardcoded secrets."""
    findings = []
    ftype = "frontend"

    combined = html + "\n" + js_code

    patterns = [
        (r'(?:api[_-]?key|apiKey|API_KEY)\s*[:=]\s*["\']([\w\-._]{20,})["\']', "Hardcoded API key in frontend", "high"),
        (r'(?:secret|SECRET)\s*[:=]\s*["\']([\w\-._]{12,})["\']', "Hardcoded secret in frontend", "high"),
        (r'(?:token|TOKEN|authToken)\s*[:=]\s*["\']([\w\-._]{16,})["\']', "Hardcoded token in frontend", "high"),
        (r'(?:password|passwd)\s*[:=]\s*["\']([^"\']{4,})["\']', "Hardcoded password in frontend", "critical"),
        (r'(?:bearer|Bearer)\s+([\w\-._]{20,})', "Bearer token in frontend code", "high"),
        (r'https?://[\w.\-]+/api/[^\s"\'<>]+', "API endpoint reference in frontend", "info"),
        (r'(?:authorization|Authorization)\s*[:=]\s*["\']([^"\']{8,})["\']', "Authorization value in frontend", "high"),
        (r'(?:firebase|FIREBASE)\s*[:=].*["\']([\w\-]+\.firebaseio\.com)["\']', "Firebase project reference", "medium"),
        (r'(?:s3\.amazonaws\.com|storage\.googleapis\.com)[^\s"\'<>]+', "Cloud storage bucket reference in frontend", "medium"),
        (r'(?:access[_-]?key|ACCESS_KEY)\s*[:=]\s*["\']([\w\-._]{16,})["\']', "Access key in frontend", "high"),
    ]

    for pat, title, sev in patterns:
        for m in re.finditer(pat, combined, re.IGNORECASE):
            matched = m.group(1) if m.lastindex else m.group(0)
            if len(matched) > 50:
                matched = matched[:50] + "..."
            findings.append({
                "title": title,
                "severity": sev, "category": "Frontend Code",
                "finding_type": ftype,
                "description": f"Found potential secret in {domain} frontend code.",
                "file_path": "N/A", "line_number": 0,
                "evidence": matched[:200],
                "remediation": "Remove all secrets from client-side code. Use server-side API proxies with authenticated sessions.",
                "cwe_id": "CWE-798", "source": "deterministic",
            })

    return findings


def _scan_frontend_endpoints(js_code: str, domain: str) -> list[dict]:
    """Discover API endpoints from JS code."""
    findings = []
    ftype = "frontend"

    patterns = [
        r'["\'`](/api/[^"\'`\s]+)["\'`]',
        r'["\'`](/v\d+/[^"\'`\s]+)["\'`]',
        r'["\'`](/graphql[^"\'`]*)["\'`]',
        r'["\'`](/ws[^"\'`]*)["\'`]',
        r'["\'`](https?://[^"\'`]+/api/[^"\'`]+)["\'`]',
        r'baseURL\s*:\s*["\'`]([^"\'`]+)["\'`]',
        r'API_URL\s*[:=]\s*["\'`]([^"\'`]+)["\'`]',
        r'endpoint\s*:\s*["\'`]([^"\'`]+)["\'`]',
    ]

    all_endpoints = set()
    for pat in patterns:
        for m in re.finditer(pat, js_code, re.IGNORECASE):
            ep = m.group(1).strip()
            if len(ep) > 3 and len(ep) < 200:
                all_endpoints.add(ep)

    if all_endpoints:
        findings.append({
            "title": f"API endpoints exposed in frontend JS: {len(all_endpoints)} found",
            "severity": "medium", "category": "Frontend Code",
            "finding_type": ftype,
            "description": f"Frontend JavaScript code reveals {len(all_endpoints)} API endpoints. Attackers can enumerate these without access to backend code.",
            "file_path": "N/A", "line_number": 0,
            "evidence": "\n".join(sorted(all_endpoints)[:30]),
            "remediation": "Review endpoints exposed in frontend. Ensure all require proper authentication and authorization.",
            "cwe_id": "CWE-200", "source": "deterministic",
        })

    return findings


def _check_frontend_cves(html: str, js_code: str, domain: str) -> list[dict]:
    """Detect JS libraries and versions, check for known CVEs."""
    findings = []
    ftype = "frontend"

    # Detect libraries with version patterns
    detected = []

    # React (from HTML or JS)
    m = re.search(r'React\s*(?:\.version)?\s*=\s*["\'](\d+\.\d+\.\d+)["\']', html + js_code, re.IGNORECASE)
    if m:
        detected.append(("react", m.group(1)))

    # Vue
    m = re.search(r'Vue\.version\s*=\s*["\'](\d+\.\d+\.\d+)["\']', js_code, re.IGNORECASE)
    if m:
        detected.append(("vue", m.group(1)))

    # jQuery
    m = re.search(r'jQuery\s+v(\d+\.\d+\.\d+)', js_code, re.IGNORECASE)
    if not m:
        m = re.search(r'jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js', html + js_code, re.IGNORECASE)
    if m:
        detected.append(("jquery", m.group(1)))

    # Lodash
    m = re.search(r'lodash\s*(?:@|v)?(\d+\.\d+\.\d+)', js_code + html, re.IGNORECASE)
    if m:
        detected.append(("lodash", m.group(1)))

    # Axios
    m = re.search(r'axios\s*(?:@|v)?(\d+\.\d+\.\d+)', js_code + html, re.IGNORECASE)
    if m:
        detected.append(("axios", m.group(1)))

    # Bootstrap JS
    m = re.search(r'[Bb]ootstrap\s*(?:[Vv])?(\d+\.\d+\.\d+)', js_code + html, re.IGNORECASE)
    if m:
        detected.append(("bootstrap", m.group(1)))

    if detected:
        # Quick CVE check via NVD API
        for lib_name, lib_ver in detected:
            cves = _lookup_cves_nvd(lib_name, lib_ver)
            if cves:
                findings.append({
                    "title": f"{lib_name} v{lib_ver} — {len(cves)} known CVE(s)",
                    "severity": "high" if any("critical" in c.lower() or "9." in c for c in cves) else "medium",
                    "category": "Frontend Code",
                    "finding_type": ftype,
                    "description": f"Detected {lib_name} v{lib_ver} in frontend. {len(cves)} CVEs found: {', '.join(cves[:5])}",
                    "file_path": "N/A", "line_number": 0,
                    "evidence": json.dumps({"library": lib_name, "version": lib_ver, "cves": cves[:10]}, indent=2),
                    "remediation": f"Upgrade {lib_name} to the latest version. Check: npm audit or yarn audit.",
                    "cwe_id": "CWE-1104", "source": "deterministic",
                })
            else:
                findings.append({
                    "title": f"{lib_name} v{lib_ver} — no known CVEs in quick scan",
                    "severity": "info", "category": "Frontend Code",
                    "finding_type": ftype,
                    "description": f"Detected {lib_name} v{lib_ver}. No critical CVEs found in quick NVD scan.",
                    "file_path": "N/A", "line_number": 0,
                    "evidence": f"{lib_name} v{lib_ver}",
                    "remediation": "Verify version is current with npm outdated or yarn outdated.",
                    "cwe_id": "", "source": "deterministic",
                })

    return findings


def _lookup_cves_nvd(lib_name: str, version: str) -> list[str]:
    """Quick CVE lookup via NVD API 2.0."""
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={lib_name}+{version}&resultsPerPage=5"
        req = urllib.request.Request(url, headers={"User-Agent": "Elyria-OSINT"})
        with urllib.request.urlopen(req, timeout=10, context=_UNVERIFIED_CTX) as resp:
            data = json.loads(resp.read())
        cves = []
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cve", {}).get("id", "")
            sev = vuln.get("cve", {}).get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "")
            if cve_id:
                cves.append(f"{cve_id} ({sev})" if sev else cve_id)
        return cves
    except Exception:
        return []


def _ai_deobfuscate(ai_provider, js_code: str, domain: str) -> list[dict]:
    """Use AI to deobfuscate/deminify suspicious JS code."""
    findings = []
    ftype = "frontend"

    # Only attempt on minified-looking code (long lines, few newlines)
    lines = js_code.split("\n")
    if len(lines) > 50 and len(js_code) / len(lines) < 200:
        return findings  # Already readable

    # Take first 4000 chars of minified code
    sample = js_code[:4000]
    if len(sample) < 200:
        return findings

    prompt = f"""You are a JavaScript deobfuscator. Analyze this minified/obfuscated JavaScript code from {domain}.
Return a JSON object with these fields:
- "is_obfuscated": true/false — is it intentionally obfuscated or just minified?
- "deobfuscated_snippet": a human-readable version of key logic (max 300 chars)
- "suspicious_patterns": list any suspicious patterns (eval, base64, document.write to external domains, hardcoded URLs, hidden iframes, crypto miners, phishing, data exfiltration)
- "api_endpoints": list any API endpoints or URLs found in the code

CODE:
{sample}"""

    try:
        resp = ai_provider.chat([
            {"role": "system", "content": "You are a security-focused JavaScript deobfuscator. Reply with valid JSON only. No markdown."},
            {"role": "user", "content": prompt},
        ])
        content = resp.get("content", "") if isinstance(resp, dict) else str(resp)

        # Extract JSON from response
        json_match = re.search(r'\{[\s\S]*\}', content)
        if json_match:
            result = json.loads(json_match.group(0))
        else:
            result = {}

        if result.get("is_obfuscated"):
            findings.append({
                "title": "Obfuscated JavaScript detected in frontend",
                "severity": "medium", "category": "Frontend Code",
                "finding_type": ftype,
                "description": f"AI analysis detected intentionally obfuscated JavaScript on {domain}. {result.get('deobfuscated_snippet', '')}",
                "file_path": "N/A", "line_number": 0,
                "evidence": json.dumps(result, indent=2, ensure_ascii=False)[:500],
                "remediation": "Investigate why JS is obfuscated. Legitimate uses: license checks, anti-scraping. Malicious uses: hiding phishing, crypto miners, data theft.",
                "cwe_id": "CWE-506", "source": "deterministic",
            })

        suspicious = result.get("suspicious_patterns", [])
        if suspicious:
            findings.append({
                "title": f"Suspicious patterns in frontend JS: {len(suspicious)} found",
                "severity": "high" if any("eval" in str(s).lower() or "exfiltrat" in str(s).lower() for s in suspicious) else "medium",
                "category": "Frontend Code",
                "finding_type": ftype,
                "description": f"AI detected potentially malicious patterns in {domain} frontend JavaScript.",
                "file_path": "N/A", "line_number": 0,
                "evidence": "\n".join(str(s)[:200] for s in suspicious[:10]),
                "remediation": "Audit these patterns. Remove any data exfiltration, hidden scripts, or malicious code.",
                "cwe_id": "CWE-506", "source": "deterministic",
            })

        api_eps = result.get("api_endpoints", [])
        if api_eps:
            findings.append({
                "title": f"AI deobfuscation revealed {len(api_eps)} API endpoints",
                "severity": "low", "category": "Frontend Code",
                "finding_type": ftype,
                "description": f"Deobfuscated JS revealed additional API endpoints not found by regex scan.",
                "file_path": "N/A", "line_number": 0,
                "evidence": "\n".join(str(e)[:200] for e in api_eps[:15]),
                "remediation": "Review these endpoints for proper authentication and authorization.",
                "cwe_id": "CWE-200", "source": "deterministic",
            })

    except Exception as e:
        findings.append({
            "title": f"AI deobfuscation failed: {str(e)[:100]}",
            "severity": "info", "category": "Frontend Code",
            "finding_type": ftype,
            "description": "Could not complete AI-based JS deobfuscation.",
            "file_path": "N/A", "line_number": 0,
            "evidence": str(e)[:300],
            "remediation": "Check AI provider configuration.",
            "cwe_id": "", "source": "deterministic",
        })

    return findings


# ═══════════════════════════════════════════════════════════════
# MODULE 13 — Trivial Page / Sensitive Path Discovery
# ═══════════════════════════════════════════════════════════════

_COMMON_PATHS = [
    # High-value targets
    ("/.env", "critical", "Environment config — may contain DB creds, API keys, secrets"),
    ("/.env.backup", "critical", "Environment config backup"),
    ("/.env.production", "critical", "Production environment config"),
    ("/.env.local", "critical", "Local environment config"),
    ("/.git/config", "high", "Git repository config — reveals repo URL, remotes"),
    ("/.git/HEAD", "high", "Git HEAD — confirms exposed .git directory"),
    ("/.svn/entries", "high", "SVN entries — confirms exposed .svn directory"),
    ("/.docker/config.json", "high", "Docker config — may contain registry credentials"),
    ("/docker-compose.yml", "high", "Docker Compose file — infrastructure layout"),
    ("/docker-compose.yaml", "high", "Docker Compose file — infrastructure layout"),
    ("/package.json", "medium", "NPM dependencies — reveals JS stack and versions"),
    ("/package-lock.json", "medium", "NPM lockfile — exact dependency versions"),
    ("/yarn.lock", "medium", "Yarn lockfile — exact dependency versions"),
    ("/Gemfile", "medium", "Ruby dependencies"),
    ("/Gemfile.lock", "medium", "Ruby lockfile"),
    ("/composer.json", "medium", "PHP Composer dependencies"),
    ("/composer.lock", "medium", "PHP Composer lockfile"),
    ("/requirements.txt", "medium", "Python dependencies"),
    ("/Pipfile", "medium", "Python Pipfile"),
    ("/Pipfile.lock", "medium", "Python Pipfile lock"),
    ("/Cargo.toml", "medium", "Rust dependencies"),

    # Admin panels
    ("/admin", "high", "Admin panel — check authentication"),
    ("/administrator", "high", "Administrator panel (Joomla)"),
    ("/wp-admin", "high", "WordPress admin panel"),
    ("/wp-login.php", "medium", "WordPress login page"),
    ("/user/login", "medium", "Login page (Drupal/Laravel)"),
    ("/login", "medium", "Login page"),
    ("/signin", "medium", "Sign-in page"),
    ("/dashboard", "medium", "Dashboard — may leak internal state"),
    ("/panel", "medium", "Control panel"),
    ("/cpanel", "medium", "cPanel hosting"),
    ("/phpmyadmin", "critical", "phpMyAdmin — database management"),
    ("/phpMyAdmin", "critical", "phpMyAdmin — database management"),
    ("/phpPgAdmin", "critical", "phpPgAdmin — PostgreSQL management"),
    ("/adminer", "critical", "Adminer — single-file DB manager"),
    ("/_drupal/config", "high", "Drupal config"),

    # Debug / dev
    ("/phpinfo.php", "high", "PHP info — full system disclosure"),
    ("/info.php", "high", "PHP info"),
    ("/test.php", "medium", "Test PHP file"),
    ("/debug", "medium", "Debug endpoint"),
    ("/debug/default/view", "high", "Yii debug toolbar"),
    ("/dev", "medium", "Development endpoint"),
    ("/staging", "medium", "Staging environment"),
    ("/api-docs", "medium", "API documentation (Swagger)"),
    ("/swagger", "medium", "Swagger UI"),
    ("/swagger-ui.html", "medium", "Swagger UI"),
    ("/graphql", "medium", "GraphQL endpoint"),
    ("/graphiql", "high", "GraphiQL — interactive GraphQL explorer"),
    ("/api/", "medium", "API base path"),
    ("/api/v1/", "medium", "API v1 base"),

    # Backups
    ("/backup", "high", "Backup directory — may contain source code or DB dumps"),
    ("/backups", "high", "Backups directory"),
    ("/backup.zip", "critical", "Backup archive"),
    ("/backup.tar.gz", "critical", "Backup archive"),
    ("/dump.sql", "critical", "Database dump"),
    ("/db.sql", "critical", "Database dump"),
    ("/database.sql", "critical", "Database dump"),
    ("/export.sql", "critical", "Database export"),

    # Config files
    ("/config.json", "high", "Configuration file — may contain secrets"),
    ("/config.yml", "high", "Configuration file"),
    ("/config.yaml", "high", "Configuration file"),
    ("/settings.json", "high", "Settings file"),
    ("/wp-config.php", "critical", "WordPress config — DB credentials"),
    ("/wp-config.bak", "critical", "WordPress config backup"),
    ("/web.config", "medium", "IIS web.config"),
    ("/app.config", "medium", ".NET app.config"),
    ("/server.cfg", "medium", "Server configuration"),

    # Common CMS paths
    ("/wp-content/", "medium", "WordPress content directory"),
    ("/wp-content/uploads/", "low", "WordPress uploads — may list files"),
    ("/wp-includes/", "low", "WordPress includes"),
    ("/sites/default/settings.php", "high", "Drupal settings"),
    ("/administrator/index.php", "medium", "Joomla admin"),
    ("/robots.txt", "info", "Robots exclusion file"),
    ("/sitemap.xml", "info", "Sitemap — lists site URLs"),
    ("/security.txt", "info", "Security disclosure policy"),
    ("/.well-known/security.txt", "info", "Security disclosure policy"),

    # Monitoring / metrics
    ("/metrics", "high", "Prometheus metrics — infrastructure data"),
    ("/status", "medium", "Status page"),
    ("/health", "medium", "Health check"),
    ("/actuator", "high", "Spring Boot Actuator — app internals"),
    ("/actuator/health", "medium", "Spring Actuator health"),
    ("/actuator/env", "high", "Spring Actuator env — env vars exposed"),

    # Source maps
    ("/static/js/app.js.map", "medium", "JS source map — reveals original source code"),
    ("/js/app.js.map", "medium", "JS source map"),
]


def _collect_trivial_paths(domain: str) -> list[dict]:
    """Probe common/sensitive paths and report exposed ones."""
    findings = []
    ftype = "paths"

    exposed_high = []
    exposed_medium = []
    exposed_info = []

    for path, severity, description in _COMMON_PATHS:
        url = f"https://{domain}{path}"
        try:
            req = urllib.request.Request(url, method="HEAD", headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            })
            with urllib.request.urlopen(req, timeout=5, context=_UNVERIFIED_CTX) as resp:
                status = resp.status
        except urllib.error.HTTPError as e:
            status = e.code
        except Exception:
            continue  # connection failed, skip

        if status in (200, 301, 302, 307, 308, 401, 403):
            entry = {"path": path, "status": status, "severity": severity, "desc": description}
            if severity == "critical":
                findings.append({
                    "title": f"Exposed sensitive path: {path} (HTTP {status})",
                    "severity": severity, "category": "Trivial Page Discovery",
                    "finding_type": ftype,
                    "description": f"CRITICAL: {description}. Accessible at {url} (HTTP {status}).",
                    "file_path": "N/A", "line_number": 0,
                    "evidence": f"HTTP {status} on {url}",
                    "remediation": f"Restrict access to {path} immediately. Use web server rules to block external access.",
                    "cwe_id": "CWE-538", "source": "deterministic",
                })
            elif severity == "high":
                exposed_high.append(entry)
            elif severity == "medium":
                exposed_medium.append(entry)
            else:
                exposed_info.append(entry)

    if exposed_high:
        findings.append({
            "title": f"High-risk paths exposed: {len(exposed_high)} found (e.g. {exposed_high[0]['path']})",
            "severity": "high", "category": "Trivial Page Discovery",
            "finding_type": ftype,
            "description": f"Found {len(exposed_high)} high-risk paths that should not be publicly accessible.",
            "file_path": "N/A", "line_number": 0,
            "evidence": json.dumps(exposed_high[:15], indent=1),
            "remediation": "Restrict access to these paths. Use authentication, IP whitelisting, or web server rules.",
            "cwe_id": "CWE-538", "source": "deterministic",
        })

    if exposed_medium:
        findings.append({
            "title": f"Informative paths exposed: {len(exposed_medium)} medium-risk + {len(exposed_info)} low-risk paths",
            "severity": "low", "category": "Trivial Page Discovery",
            "finding_type": ftype,
            "description": f"Found {len(exposed_medium)} medium-risk and {len(exposed_info)} low-risk paths. These reveal information about the tech stack and structure.",
            "file_path": "N/A", "line_number": 0,
            "evidence": json.dumps((exposed_medium + exposed_info)[:30], indent=1),
            "remediation": "Review exposed paths. Remove debug/test files, restrict access to admin panels and config files.",
            "cwe_id": "CWE-200", "source": "deterministic",
        })

    if not findings:
        findings.append({
            "title": "No trivial/sensitive paths found exposed",
            "severity": "info", "category": "Trivial Page Discovery",
            "finding_type": ftype,
            "description": f"Scanned {len(_COMMON_PATHS)} common paths — no sensitive files or admin panels found accessible.",
            "file_path": "N/A", "line_number": 0,
            "evidence": f"Checked {len(_COMMON_PATHS)} paths",
            "remediation": "",
            "cwe_id": "", "source": "deterministic",
        })

    return findings


# ═══════════════════════════════════════════════════════════════
# MAIN SCANNER CLASS
# ═══════════════════════════════════════════════════════════════

class OSINTDomainScanner:
    """Deterministic domain OSINT scanner — Phase 1."""

    MODULES = {
        "dns":        (_collect_dns, 8),
        "whois":      (_collect_whois, 8),
        "ssl":        (_collect_ssl, 12),
        "ct":         (_collect_crtsh, 12),
        "http":       (_collect_http_headers, 10),
        "paths":      (_collect_web_paths, 8),
        "tech":       (_collect_tech_fingerprint, 8),
        "email":      (_collect_emails, 6),
        "wayback":    (_collect_wayback, 12),
        "github":     (_collect_github_dorks, 10),
        "google":     (_collect_google_dorks, 8),
        "frontend":   (_collect_frontend, 14),
        "trivial":    (_collect_trivial_paths, 10),
    }

    def __init__(self, domain: str, progress_cb=None, log_cb=None,
                 modules: list[str] | None = None, ai_provider=None):
        self.domain = _safe_domain(domain)
        self.progress_cb = progress_cb or (lambda pct, msg: None)
        self.log_cb = log_cb or (lambda **kw: None)
        self.modules_filter = modules or []
        self.ai_provider = ai_provider

    def _active(self, name: str) -> bool:
        return not self.modules_filter or name in self.modules_filter

    def run_all(self, stop_check=None) -> list[dict]:
        if stop_check is None:
            stop_check = lambda: False

        all_findings = []
        active_modules = {
            name: fn for name, (fn, _) in self.MODULES.items()
            if self._active(name)
        }

        if not active_modules:
            active_modules = {
                name: fn for name, (fn, _) in self.MODULES.items()
            }

        total_weight = sum(self.MODULES[name][1] for name in active_modules)
        weight_done = 0

        _log.info(f"[osint] Starting {len(active_modules)} modules for {self.domain}: {', '.join(active_modules.keys())}")

        for name, fn in active_modules.items():
            if stop_check():
                _log.info(f"[osint] Stop check triggered, aborting after {name}")
                break

            pct = int(5 + (weight_done / max(1, total_weight) * 85))
            self.progress_cb(pct, f"OSINT: {name}")

            try:
                _log.debug(f"[osint] Module {name} starting...")
                if name == "frontend" and self.ai_provider:
                    result = fn(self.domain, ai_provider=self.ai_provider)
                else:
                    result = fn(self.domain)
                all_findings.extend(result)
                _log.info(f"[osint] Module {name}: {len(result)} findings")
            except Exception as e:
                _log.error(f"[osint] Module {name} failed: {e}")
                all_findings.append({
                    "title": f"OSINT module failed: {name}",
                    "severity": "info", "category": "Scanner Error",
                    "finding_type": name,
                    "description": f"Module '{name}' raised: {e}",
                    "file_path": "N/A", "line_number": 0,
                    "evidence": str(e)[:500],
                    "remediation": f"Check {name} module configuration.",
                    "cwe_id": "", "source": "deterministic",
                })

            weight_done += self.MODULES[name][1]

        self.progress_cb(90, "OSINT Phase 1 complete")
        return all_findings
