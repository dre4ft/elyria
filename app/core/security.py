# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Security utilities — SSRF protection, URL validation.

All block lists are configured in elyria.cfg [security]:
  blocked_hosts    — hostnames to block
  blocked_tlds     — TLD suffixes to block
  blocked_networks — CIDR ranges to block (private IPs)

Production mode (ELYRIA_PRODUCTION=1): blocks all private/internal IPs.
Local mode (default): allows localhost for development.
"""

import ipaddress
import os
import socket
from urllib.parse import urlparse


def _is_production() -> bool:
    return os.getenv("ELYRIA_PRODUCTION", "") == "1"


def _cfg(key: str, default: str = "") -> str:
    from core.config import get
    return get("security", key, default)


def _load_blocked_hosts() -> set:
    raw = _cfg("blocked_hosts", "")
    hosts = {h.strip() for h in raw.split(",") if h.strip()}
    return hosts or {
        "metadata.google.internal", "169.254.169.254",
        "instance-data", "host.docker.internal", "gateway.docker.internal",
    }


def _load_blocked_tlds() -> set:
    raw = _cfg("blocked_tlds", "")
    tlds = {t.strip() for t in raw.split(",") if t.strip()}
    return tlds or {".local", ".internal", ".corp", ".home", ".lan"}


def _load_blocked_networks() -> list:
    raw = _cfg("blocked_networks", "")
    nets = []
    for cidr in raw.split(","):
        cidr = cidr.strip()
        if cidr:
            try:
                nets.append(ipaddress.ip_network(cidr))
            except ValueError:
                pass
    return nets or [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fc00::/7"),
        ipaddress.ip_network("fe80::/10"),
    ]


def _resolve_host(host: str) -> str:
    """Resolve hostname to IP. Returns empty string on failure."""
    try:
        return socket.getaddrinfo(host, None, socket.AF_UNSPEC)[0][4][0]
    except Exception:
        return ""


def is_url_safe(url: str) -> tuple[bool, str]:
    """
    Check if a URL is safe to fetch from the server.

    Returns (is_safe, reason).

    Production: blocks all private/internal IPs except whitelisted FQDN.
    Local mode: allows localhost, blocks cloud metadata.
    """
    if not url:
        return False, "URL vide"

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "URL invalide"

    host = (parsed.hostname or "").lower()

    if not host:
        return False, "Hostname manquant"

    for blocked in _load_blocked_hosts():
        if blocked in host or host in blocked:
            return False, f"Host bloque: {blocked}"

    for tld in _load_blocked_tlds():
        if host.endswith(tld):
            return False, f"TLD bloque: {tld}"

    from database.app_config import is_fqdn_allowed
    if is_fqdn_allowed(host, "fetch"):
        return True, ""

    # Check for IPv6-mapped IPv4 (::ffff:x.x.x.x)
    if host.startswith("::ffff:"):
        v4_part = host.replace("::ffff:", "").replace("[", "").replace("]", "")
        try:
            ip = ipaddress.ip_address(v4_part)
        except ValueError:
            ip = None
        if ip:
            for net in _load_blocked_networks():
                if ip in net and not ip.is_loopback:
                    return False, f"IPv6-mapped IPv4 bloquee: {ip}"
            return True, ""

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip_str = _resolve_host(host)
        if not ip_str:
            return False, f"Impossible de resoudre: {host}"
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"Adresse IP invalide: {ip_str}"

    for net in _load_blocked_networks():
        if ip in net:
            if not _is_production() and ip.is_loopback:
                return True, ""
            return False, f"IP privee bloquee: {ip} (range {net})"

    return True, ""


def validate_url_or_raise(url: str):
    """Validate URL for SSRF. Raises HTTPException 403 if unsafe."""
    safe, reason = is_url_safe(url)
    if not safe:
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail=f"URL non autorisee: {reason}")


def _is_safe_url(url: str, allow_localhost: bool = True) -> bool:
    """Legacy wrapper for redteam campaign_api compatibility. Returns bool only."""
    if allow_localhost and not _is_production():
        try:
            host = (urlparse(url).hostname or "").lower()
            if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
                return True
        except Exception:
            pass
    safe, _ = is_url_safe(url)
    return safe
