# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Static Scanner — deterministic static code analysis.
Detects languages, parses dependencies, and finds bad practices.
"""

import os
import re
from core.logging import get_logger
from purpleteam.repo_manager import detect_language, parse_dependencies, list_repo_files
from purpleteam.cve_scanner import CVEScanner
from purpleteam.cwe_scanner import CWEScanner

_log = get_logger("purpleteam.static")

# Bad practice patterns: (severity, title, regex, description, remediation)
BAD_PRACTICES = [
    # ── Debug / Development ──
    ("high", "Debug mode enabled", r"(?:DEBUG|debug)\s*=\s*(?:True|true|1|'on'|'true')",
     "Application is running in debug mode. This can expose stack traces, environment variables, and internal state to attackers.",
     "Set DEBUG=False in production environments."),

    ("high", "Flask debug mode enabled", r"app\.run\s*\([^)]*debug\s*=\s*True",
     "Flask development server with debug mode exposes an interactive debugger that allows remote code execution.",
     "Never use app.run(debug=True) in production. Use a production WSGI server (gunicorn, uvicorn)."),

    ("medium", "CORS allow all origins", r"(?:Access-Control-Allow-Origin|allow_origins|CORS_ORIGIN_ALLOW_ALL|allow_origins)\s*[=:]\s*\[?\s*['\"]\*['\"]",
     "CORS is configured to allow all origins (*), enabling any website to make authenticated requests to your API.",
     "Restrict CORS to specific trusted origins."),

    ("medium", "Missing CORS configuration", r"(?:ALLOWED_HOSTS|CORS_ALLOWED_ORIGINS)\s*=\s*\[\s*['\"]\*['\"]",
     "ALLOWED_HOSTS or CORS origins set to wildcard, allowing any host to access the application.",
     "Restrict to specific hostnames."),

    # ── Authentication / Authorization ──
    ("critical", "Hardcoded secret key", r"(?:SECRET_KEY|JWT_SECRET|ENCRYPTION_KEY|API_KEY|MASTER_KEY)\s*=\s*['\"][a-zA-Z0-9_\-+/=]{8,}['\"]",
     "A cryptographic secret key is hardcoded in the source code. This key will be exposed in version control history.",
     "Use environment variables or a secrets manager. Never hardcode secrets in source code."),

    ("high", "Password in configuration", r"(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{3,}['\"]\s*[,;\n]",
     "A plain-text password appears to be hardcoded in configuration or source code.",
     "Store passwords in environment variables or a secrets vault."),

    ("high", "Disabled authentication", r"(?:authentication_classes|auth_required|login_required)\s*=\s*\[\]\s*$|@api_view\s*\([^)]*authentication_classes\s*=\s*\[\]",
     "Authentication has been explicitly disabled for an API endpoint.",
     "Ensure all sensitive endpoints require authentication."),

    ("medium", "Missing rate limiting", r"@app\.(?:get|post|put|delete|patch)\s*\([^)]*\)\s*\n(?:(?!.*rate|.*limit|.*throttle).)*?\n\s*def",
     "API endpoint without visible rate limiting protection.",
     "Add rate limiting (e.g., slowapi, flask-limiter, express-rate-limit)."),

    # ── Input Validation ──
    ("high", "Missing input validation", r"@app\.(?:post|put|patch)\s*\([^)]*\)\s*\n\s*(?:async\s+)?def\s+\w+\s*\([^)]*\):\s*\n\s*(?!#)\s*\w",
     "POST/PUT endpoint without visible input validation or schema enforcement.",
     "Use Pydantic models (FastAPI), marshmallow schemas (Flask), or Joi/class-validator (Node.js)."),

    ("medium", "Direct request data usage", r"(?:request\.(?:json|data|body|form|args)|req\.(?:body|query|params))\[",
     "Direct dictionary access on request data without validation can lead to KeyError or unvalidated input usage.",
     "Use .get() with defaults or schema-based validation."),

    # ── Error Handling ──
    ("medium", "Bare except clause", r"except\s*:",
     "Bare except catches all exceptions including KeyboardInterrupt and SystemExit, hiding critical errors.",
     "Use 'except Exception:' to only catch expected error types."),

    ("low", "print() used instead of logging", r"\bprint\s*\(.*(?:error|err|warning|warn|info|debug|exception|traceback)",
     "Using print() for error/debug output instead of proper logging. Logs can't be filtered or routed.",
     "Use the logging module (Python), log4j (Java), or winston (Node.js)."),

    # ── Security Headers / Configuration ──
    ("medium", "Missing HTTPS redirect", r"app\.run\s*\(.*ssl_context\s*=\s*None|ssl_context\s*=\s*None",
     "Application configured without SSL/TLS, running on plain HTTP.",
     "Enable HTTPS with proper SSL certificate. Use a reverse proxy (nginx, caddy) for production."),

    ("low", "Missing security headers middleware", r"app\s*=\s*(?:FastAPI|Flask|Express|create_app)\s*\(\s*\)\s*\n(?:(?!.*helmet|.*security|.*HTTPS|.*CORS).)*?\n\s*(?:app\.|@app)",
     "Application created without security middleware (helmet, secure headers).",
     "Add security headers middleware: helmet (Express), secure-headers (Django), etc."),

    # ── Dependency / Configuration ──
    ("medium", "Outdated dependency pinned to old version", r"(?:django|flask|fastapi|express|spring|react|angular|vue|requests|axios)\s*[=><~^]+\s*['\"]?\d{1,2}\.",
     "Pinned dependency with a very old major version. This may contain known vulnerabilities.",
     "Update to the latest stable version and review the changelog for breaking changes."),

    ("low", "Missing requirements.txt or package.json lock", r"^(?:(?!(?:requirements\.txt|Pipfile|poetry\.lock|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|go\.sum)).)*$",
     "No dependency lock file found. Dependencies may resolve to different versions across environments.",
     "Use lock files (package-lock.json, poetry.lock, Pipfile.lock) to ensure reproducible builds."),

    # ── File Operations ──
    ("high", "Unsafe file write", r"open\s*\(\s*(?:request|input|user|body|params|query|form)",
     "File is opened with a path derived from user input, enabling path traversal or arbitrary file writes.",
     "Never use user input directly in file paths. Validate and sanitize, or use a whitelist of allowed paths."),

    # ── Cryptography ──
    ("medium", "Non-cryptographic RNG for tokens", r"(?:random\.(?:choice|randint|random)|Math\.random)\s*\(.*(?:token|secret|password|reset|verify|auth)",
     "Non-cryptographic random number generator used for security tokens. These are predictable.",
     "Use secrets module (Python), crypto.randomBytes (Node.js), or SecureRandom (Java)."),

    # ── Database ──
    ("medium", "Raw SQL with string formatting", r"(?:execute|query|raw)\s*\(\s*f['\"]",
     "SQL query built with f-strings. User input could enable SQL injection.",
     "Use parameterized queries with placeholders (? or :param)."),

    ("medium", "MongoDB without auth", r"mongodb://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?/(?!\?)",
     "MongoDB connection string without authentication credentials.",
     "Enable MongoDB authentication and use strong credentials."),
]


class StaticScanner:
    def __init__(self, repo_path, user_id=""):
        self.repo_path = repo_path
        self.user_id = user_id
        self.language, self.framework = detect_language(repo_path)
        self.cve_scanner = CVEScanner(user_id)
        self.cwe_scanner = CWEScanner()

    def run(self, scan_id, add_finding_fn, progress_cb=None):
        """Run the full static analysis pipeline."""
        _log.info(f"Static scan: language={self.language}, framework={self.framework}")

        total_findings = 0

        # Phase 1a: Dependency analysis + CVE lookup
        if progress_cb:
            progress_cb(10, "Analyzing dependencies...")
        deps = parse_dependencies(self.repo_path, self.language)
        _log.info(f"Found {len(deps)} dependencies")

        if deps:
            if progress_cb:
                progress_cb(20, f"Scanning {len(deps)} dependencies for CVEs...")
            cve_results = self.cve_scanner.scan_dependencies(deps)
            cve_count = 0
            for dep_key, cves in cve_results.items():
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
                    cve_count += 1
            _log.info(f"CVE scan: {cve_count} findings")
            total_findings += cve_count

        # Phase 1b: CWE pattern scanning
        if progress_cb:
            progress_cb(40, "Scanning for CWE patterns...")
        files = list_repo_files(self.repo_path)
        _log.info(f"Scanning {len(files)} files for CWE patterns")
        cwe_count = self.cwe_scanner.generate_findings(scan_id, self.repo_path, add_finding_fn, lambda p: files)
        total_findings += cwe_count
        _log.info(f"CWE scan: {cwe_count} findings")

        # Phase 1c: Bad practice detection
        if progress_cb:
            progress_cb(60, "Scanning for bad practices...")
        bp_count = self._scan_bad_practices(scan_id, add_finding_fn, files)
        total_findings += bp_count
        _log.info(f"Bad practice scan: {bp_count} findings")

        if progress_cb:
            progress_cb(80, f"Static analysis complete ({total_findings} findings)")
        return total_findings

    def _scan_bad_practices(self, scan_id, add_finding_fn, files):
        """Scan repo for bad practices."""
        count = 0
        # Patterns that apply to specific files (config, main app, etc.)
        key_files = self._find_key_files(files)
        for file_rel, content in key_files.items():
            for severity, title, pattern, description, remediation in BAD_PRACTICES:
                try:
                    for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                        line_num = content[:match.start()].count("\n") + 1
                        matched = match.group(0)[:120]
                        add_finding_fn(
                            scan_id=scan_id,
                            title=title,
                            description=f"{description}\n\nMatched: `{matched}`",
                            severity=severity,
                            category="bad_practice",
                            file_path=file_rel,
                            line_number=line_num,
                            evidence={"matched_text": matched, "line": line_num},
                            remediation=remediation,
                            finding_part="practices",
                        )
                        count += 1
                except Exception:
                    pass

        # Whole-repo patterns
        self._scan_repo_wide_patterns(scan_id, add_finding_fn, files, count)
        return count

    def _find_key_files(self, files):
        """Load content of key configuration files."""
        key_files = {}
        key_patterns = [
            "settings.py", "config.py", "configuration.py", "app.py", "main.py",
            "server.py", "entrypoint.py", "manage.py", "wsgi.py", "asgi.py",
            ".env", ".env.example", "application.properties", "application.yml",
            "application.yaml", "web.config", "nginx.conf", "Dockerfile",
            "docker-compose.yml", "docker-compose.yaml", "Makefile",
        ]
        for f in files:
            basename = os.path.basename(f).lower()
            if any(basename == kp.lower() for kp in key_patterns) or basename.endswith(("rc", ".cfg", ".conf", ".ini")):
                try:
                    full = os.path.join(self.repo_path, f)
                    with open(full, "r", errors="replace") as fh:
                        key_files[f] = fh.read()
                except Exception:
                    pass
        return key_files

    def _scan_repo_wide_patterns(self, scan_id, add_finding_fn, files, count):
        """Repo-wide checks that don't need file content."""
        # Check for missing lock file
        if self.language == "python":
            has_lock = any("poetry.lock" in f.lower() or "pipfile.lock" in f.lower() for f in files)
            has_req = any("requirements.txt" in f.lower() for f in files)
            if has_req and not has_lock:
                add_finding_fn(
                    scan_id=scan_id,
                    title="Missing dependency lock file",
                    description="requirements.txt found without a lock file (poetry.lock, Pipfile.lock). Dependencies are not pinned to exact versions.",
                    severity="low",
                    category="bad_practice",
                    file_path="requirements.txt",
                    remediation="Use pip freeze > requirements.txt with exact versions, or adopt Poetry/Pipenv for deterministic builds.",
                    finding_part="practices",
                )
                count += 1

        elif self.language == "javascript":
            has_lock = any(f.endswith("package-lock.json") or f.endswith("yarn.lock") or f.endswith("pnpm-lock.yaml") for f in files)
            if not has_lock:
                add_finding_fn(
                    scan_id=scan_id,
                    title="Missing package lock file",
                    description="No package-lock.json or yarn.lock found. Dependencies may resolve inconsistently.",
                    severity="low",
                    category="bad_practice",
                    file_path="package.json",
                    remediation="Commit package-lock.json or yarn.lock to version control.",
                    finding_part="practices",
                )
                count += 1
        return count
