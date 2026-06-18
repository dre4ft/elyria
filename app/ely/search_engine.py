# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Web search engine — uses DuckDuckGo Lite (no JS required, privacy-respecting).
Qwant blocks all headless/programmatic access with captchas.
"""

import re
import requests
from html import unescape as _html_unescape

from core.logging import get_logger

_log = get_logger("ely.search_engine")

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

DDG_LITE_URL = "https://lite.duckduckgo.com/lite/"


def _extract_results(html: str, max_results: int = 10) -> list[dict]:
    """Parse DuckDuckGo Lite HTML search results.

    Structure:
        <a rel="nofollow" href="URL" class='result-link'>Title</a>
        <td class='result-snippet'>Description</td>
    """
    results = []

    # Find all result-link <a> tags with href and title text
    for m in re.finditer(
        r'<a[^>]*href="(https?://[^"]+)"[^>]*class=.result-link.[^>]*>\s*(?:<[^>]+>)*\s*(.*?)\s*(?:</[^>]+>)*\s*</a>',
        html, re.DOTALL,
    ):
        url = m.group(1)
        title = re.sub(r'<[^>]+>', '', m.group(2)).strip()
        title = _html_unescape(title)

        if 'duckduckgo.com' in url or 'duck.com' in url or len(url) < 15:
            continue
        if not title or title.startswith('http'):
            continue

        # Look for the adjacent <td class='result-snippet'> following this link
        after = html[m.end():m.end() + 1500]
        desc_m = re.search(r"<td[^>]*class='result-snippet'[^>]*>(.*?)</td>", after, re.DOTALL)
        desc = ""
        if desc_m:
            desc = re.sub(r'<[^>]+>', ' ', desc_m.group(1))
            desc = _html_unescape(desc)
            desc = re.sub(r'\s+', ' ', desc).strip()

        results.append({"url": url, "title": title, "description": desc})

        if len(results) >= max_results:
            break

    # Deduplicate by URL
    seen = set()
    deduped = []
    for r in results:
        if r["url"] not in seen:
            seen.add(r["url"])
            deduped.append(r)

    return deduped[:max_results]


def search_engine(query: str) -> str | list[dict]:
    """
    Search the web and return a list of {url, title, description} dicts.
    Uses DuckDuckGo Lite — no JavaScript required, privacy-respecting.
    Returns a string error message on failure.
    """
    if not query or not query.strip():
        return "Error: empty query"

    params = {"q": query.strip(), "s": "0"}
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "fr,fr-FR;q=0.9,en;q=0.8",
    }

    from core.config import get as _cfg
    blocked = _cfg("security", "blocked_urls", [])
    if DDG_LITE_URL in blocked:
        _log.error(f"Search URL is blocked by config: {DDG_LITE_URL}")
        return "Error: search engine blocked by configuration"

    try:
        resp = requests.post(DDG_LITE_URL, data=params, headers=headers, timeout=15, verify=True)
    except requests.exceptions.RequestException as e:
        _log.error(f"Request failed: {e}")
        return f"Error: request failed — {e}"

    if not str(resp.status_code).startswith("2"):
        _log.error(f"HTTP {resp.status_code}")
        return f"Error: HTTP {resp.status_code}"

    html = resp.text
    if not html or len(html) < 200:
        return "Error: empty response"

    results = _extract_results(html, max_results=10)
    if not results:
        _log.warning(f"No results for query '{query}'")
        return "No results found"

    _log.info(f"Search '{query}' → {len(results)} results")
    return results


async def search_engine_async(query: str) -> str | list[dict]:
    """Async wrapper — suitable for FastAPI endpoints / async tools."""
    import asyncio
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, search_engine, query)


