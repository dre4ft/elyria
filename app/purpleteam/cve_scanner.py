# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
CVE Scanner — query NIST NVD for known CVEs in dependencies.
Uses the public NVD REST API (no key needed for 5 req/30s),
with headless browser fallback for rate-limited scenarios.
Results cached in SQLite for 24h.
"""

import json
import time
import requests
from core.logging import get_logger
from purpleteam.database import get_cached_cve, set_cached_cve

_log = get_logger("purpleteam.cve")

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_SEARCH = "https://nvd.nist.gov/vuln/search/results"
REQUEST_INTERVAL = 6.1  # seconds between requests (5 req/30s = 6s per req)


class CVEScanner:
    def __init__(self, user_id=""):
        self.user_id = user_id
        self._last_request = 0
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "Elyria-PurpleTeam/1.0",
        })

    def _rate_limit(self):
        elapsed = time.time() - self._last_request
        if elapsed < REQUEST_INTERVAL:
            time.sleep(REQUEST_INTERVAL - elapsed)
        self._last_request = time.time()

    def scan_dependency(self, dep_name, dep_version):
        """Check a single dependency for known CVEs. Returns list of CVE dicts."""
        cached = get_cached_cve(dep_name, dep_version)
        if cached is not None:
            return cached

        cves = self._query_nvd_api(dep_name, dep_version)
        set_cached_cve(dep_name, dep_version, cves)
        return cves

    def _query_nvd_api(self, dep_name, dep_version):
        """Query the NVD REST API for CVEs matching a dependency."""
        cves = []
        keyword = dep_name if not dep_version else f"{dep_name} {dep_version}"

        self._rate_limit()
        try:
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": 20,
            }
            resp = self._session.get(NVD_API, params=params, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "")
                    descriptions = cve.get("descriptions", [])
                    desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
                    if not desc_en and descriptions:
                        desc_en = descriptions[0].get("value", "")

                    metrics = cve.get("metrics", {})
                    cvss_v31 = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
                    cvss_score = 0.0
                    severity = "info"
                    if cvss_v31:
                        cvss_data = cvss_v31[0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore", 0.0)
                    elif metrics.get("cvssMetricV2", []):
                        cvss_score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", 0.0)

                    if cvss_score >= 9.0:
                        severity = "critical"
                    elif cvss_score >= 7.0:
                        severity = "high"
                    elif cvss_score >= 4.0:
                        severity = "medium"
                    elif cvss_score > 0:
                        severity = "low"

                    cves.append({
                        "cve_id": cve_id,
                        "description": desc_en[:500],
                        "cvss_score": cvss_score,
                        "severity": severity,
                        "published": cve.get("published", ""),
                        "last_modified": cve.get("lastModified", ""),
                    })

                total = data.get("totalResults", 0)
                if total > 20:
                    _log.info(f"NVD: {total} total results for '{keyword}', returning top 20")
            elif resp.status_code == 403:
                _log.warning(f"NVD API rate limited for '{keyword}', using browser fallback")
                cves = self._query_via_browser(dep_name, dep_version)
        except requests.RequestException as e:
            _log.error(f"NVD API error for '{keyword}': {e}")
        return cves

    def _query_via_browser(self, dep_name, dep_version):
        """Fallback: query NVD website via headless browser."""
        import asyncio
        from ely.browser import launch_browser, query_page, close_browser

        cves = []
        keyword = dep_name if not dep_version else f"{dep_name} {dep_version}"
        url = f"{NVD_SEARCH}?form_type=Basic&query={requests.utils.quote(keyword)}&search_type=all"

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            browser, playwright = loop.run_until_complete(launch_browser())
            page_text = loop.run_until_complete(query_page(browser, url, "body"))
            loop.run_until_complete(close_browser(browser, playwright))
            loop.close()

            # Parse CVE IDs from page text
            import re
            cve_ids = set(re.findall(r'CVE-\d{4}-\d{4,}', page_text))
            for cve_id in cve_ids:
                cves.append({
                    "cve_id": cve_id,
                    "description": "",
                    "cvss_score": 0.0,
                    "severity": "info",
                    "published": "",
                    "last_modified": "",
                })
        except Exception as e:
            _log.error(f"Browser fallback failed for '{keyword}': {e}")
        return cves

    def scan_dependencies(self, dependencies):
        """Scan a list of dependencies for CVEs. Returns dict name→CVEs."""
        results = {}
        for dep in dependencies:
            name = dep.get("name", "")
            version = dep.get("version", "")
            if not name:
                continue
            _log.info(f"Scanning CVE for {name} {version}")
            cves = self.scan_dependency(name, version)
            if cves:
                results[f"{name}@{version}" if version else name] = cves
        return results

    def generate_findings(self, scan_id, dep_cve_map, add_finding_fn):
        """Convert CVE results to Purple Team findings."""
        for dep_key, cves in dep_cve_map.items():
            for cve in cves:
                add_finding_fn(
                    scan_id=scan_id,
                    title=f"CVE: {cve['cve_id']} in {dep_key}",
                    description=cve.get("description", f"Known CVE in dependency {dep_key}"),
                    severity=cve.get("severity", "info"),
                    category="cve",
                    file_path=dep_key,
                    evidence={"cve_id": cve["cve_id"], "cvss_score": cve["cvss_score"]},
                    cvss_score=cve.get("cvss_score", 0.0),
                    cve_id=cve["cve_id"],
                    finding_part="cves",
                )
