# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
CWE Scanner — detect Common Weakness Enumeration patterns in source code.
Uses pattern matching against known CWE categories with CWE API enrichment.
"""

import re
import os
from core.logging import get_logger

_log = get_logger("purpleteam.cwe")

# CWE patterns organized by category
# Each pattern: (cwe_id, severity, regex_pattern, description)
CWE_PATTERNS = [
    # ── CWE-79: Cross-Site Scripting (XSS) ──
    ("CWE-79", "high", r"innerHTML\s*=|document\.write\s*\(|eval\s*\(.*\+|dangerouslySetInnerHTML|v-html=|unsafeHTML", "XSS: unsafe DOM manipulation detected"),
    ("CWE-79", "medium", r"\.html\s*\(.*\+|\.append\s*\(.*<|\.prepend\s*\(.*<|insertAdjacentHTML", "XSS: potential HTML injection via jQuery/JS"),

    # ── CWE-89: SQL Injection ──
    ("CWE-89", "critical", r"(?:cursor\.)?execute\s*\(\s*(?:f?['\"].*%|.*\.format|.*\s*\+\s*|.*\bf\b['\"])", "SQL Injection: string formatting in SQL query"),
    ("CWE-89", "high", r"(?:execute|executemany)\s*\(\s*['\"].*\{.*\}.*['\"]", "SQL Injection: f-string or format in query"),
    ("CWE-89", "high", r"Statement\.execute(?:Query|Update)?\s*\(\s*.*\+", "SQL Injection: string concatenation in JDBC"),
    ("CWE-89", "medium", r"cursor\.execute\s*\(\s*[a-zA-Z_]", "SQL: verify parameterized queries are used"),

    # ── CWE-78: Command Injection ──
    ("CWE-78", "critical", r"os\.system\s*\(|subprocess\.(?:call|Popen|run)\s*\(.*\+|exec\s*\(|system\s*\(.*\$", "Command Injection: user input in shell command"),
    ("CWE-78", "high", r"shell\s*=\s*True|shell=True", "Command Injection: shell=True in subprocess"),

    # ── CWE-22: Path Traversal ──
    ("CWE-22", "high", r"os\.path\.join\s*\(.*request|open\s*\(.*\.\.\/|readFile\s*\(.*\.\.\/|\.\.\/.*request|path\.resolve\s*\(.*user", "Path Traversal: user input in file path"),

    # ── CWE-502: Deserialization of Untrusted Data ──
    ("CWE-502", "high", r"pickle\.(?:loads?|dump)|yaml\.load\s*\(|marshal\.loads?\s*\(|unserialize\s*\(|objectinputstream", "Insecure Deserialization: unsafe unpickling/deserialization"),

    # ── CWE-798: Hardcoded Credentials ──
    ("CWE-798", "critical", r"(?:password|passwd|pwd|secret|api_key|apikey|api[_-]?key)\s*=\s*['\"][^'\"]{4,}['\"]", "Hardcoded Credentials: password/secret in source"),  # noqa
    ("CWE-798", "high", r"(?:DATABASE_URL|MONGO_URI|REDIS_URL)\s*=\s*['\"]", "Hardcoded Credentials: database connection string"),
    ("CWE-798", "high", r"(?:JWT_SECRET|SECRET_KEY|ENCRYPTION_KEY)\s*=\s*['\"]", "Hardcoded Credentials: crypto key in source"),

    # ── CWE-200: Information Exposure ──
    ("CWE-200", "medium", r"print\s*\(.*(?:password|secret|token|key)|console\.log\s*\(.*(?:password|secret|token)", "Information Exposure: sensitive data logged"),
    ("CWE-200", "medium", r"debug\s*=\s*True|DEBUG\s*=\s*True|DEBUG\s*:\s*true", "Information Exposure: debug mode enabled"),
    ("CWE-200", "low", r"traceback\.print_exc|console\.error\s*\(.*err|\.stack", "Information Exposure: stack traces may leak in production"),

    # ── CWE-209: Verbose Error Messages ──
    ("CWE-209", "low", r"return\s+(?:str|repr)\s*\(\s*(?:err|error|e|exception)\s*\)|\.message\s*\)", "Verbose Error: raw error returned to client"),

    # ── CWE-327: Weak Cryptography ──
    ("CWE-327", "high", r"hashlib\.md5\s*\(|hashlib\.sha1\s*\(|MD5|SHA-?1|DES\b|RC4|ECB\s*mode", "Weak Cryptography: MD5/SHA1/DES/RC4/ECB detected"),
    ("CWE-327", "medium", r"random\.(?:random|choice|randint)\s*\(|Math\.random\s*\(|urandom", "Weak Cryptography: non-cryptographic RNG for security"),

    # ── CWE-287: Improper Authentication ──
    ("CWE-287", "high", r"if\s+(?:username|user|login)\s*==\s*['\"]|if\s+(?:password|passwd)\s*==\s*['\"]", "Improper Auth: hardcoded credential comparison"),
    ("CWE-287", "medium", r"@app\.route.*auth.*=.*False|skip.*auth|bypass.*auth|auth\s*=\s*None", "Improper Auth: authentication bypass marker"),

    # ── CWE-862: Missing Authorization ──
    ("CWE-862", "medium", r"@app\.(?:get|post|put|delete|patch)\s*\([^)]*\)\s*\n\s*def", "Missing Auth: endpoint without visible auth decorator"),

    # ── CWE-611: XML External Entity (XXE) ──
    ("CWE-611", "high", r"etree\.(?:parse|fromstring|iterparse)\s*\(|xml\.sax\.parse|DocumentBuilder|SAXParser|XMLReader", "XXE: XML parsing without external entity protection"),

    # ── CWE-918: Server-Side Request Forgery (SSRF) ──
    ("CWE-918", "high", r"requests\.(?:get|post|put)\s*\(.*(?:request|params|body|input|user|query)|fetch\s*\(.*(?:request|params|body|input)", "SSRF: user-controlled URL in HTTP request"),
    ("CWE-918", "medium", r"urllib\.request\.(?:urlopen|Request)\s*\(.*(?:request|params|input)", "SSRF: user input in urllib request"),

    # ── CWE-434: Unrestricted File Upload ──
    ("CWE-434", "medium", r"\.save\s*\(.*(?:filename|file\.name)|move_uploaded_file|upload\s*\(|write\s*\(.*upload", "Unrestricted Upload: file saved with user-controlled name"),

    # ── CWE-601: Open Redirect ──
    ("CWE-601", "medium", r"redirect\s*\(.*(?:request|params|query|url|next)|(?:location|Location)\s*=\s*.*request", "Open Redirect: user input in redirect target"),

    # ── CWE-352: Cross-Site Request Forgery ──
    ("CWE-352", "medium", r"csrf\s*=\s*False|csrf_exempt|@csrf_exempt|csrf\.disable", "CSRF: protection explicitly disabled"),

    # ── CWE-639: Insecure Direct Object Reference (IDOR) ──
    ("CWE-639", "medium", r"\.get\s*\(\s*(?:id|user_id|pk)\s*\)\s*$|findById\s*\(.*request|\.find\s*\(\s*\{\s*_id", "IDOR: resource accessed by user-supplied ID without ownership check"),

    # ── CWE-770: Unrestricted Resource Consumption ──
    ("CWE-770", "low", r"while\s+True|time\.sleep\s*\(.*input|range\s*\(.*(?:request|input|body)", "DoS: unbounded loop or resource consumption"),

    # ── CWE-732: Insecure Permissions ──
    ("CWE-732", "medium", r"chmod\s*\(.*0o?777|os\.chmod\s*\(.*0o?777|mode\s*=\s*0o?777", "Insecure Permissions: world-writable file (777)"),
]


class CWEScanner:
    def __init__(self):
        self._patterns = CWE_PATTERNS

    def scan_file(self, file_path, content):
        """Scan a single source file for CWE patterns. Returns list of finding dicts."""
        findings = []
        lines = content.split("\n")
        for cwe_id, severity, pattern, description in self._patterns:
            try:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    # Find line number
                    pos = match.start()
                    line_num = content[:pos].count("\n") + 1
                    matched_text = match.group(0)[:100]
                    findings.append({
                        "cwe_id": cwe_id,
                        "severity": severity,
                        "title": f"{cwe_id}: {description}",
                        "description": f"Detected pattern matching {cwe_id} in {file_path}:{line_num}\n\nMatched: `{matched_text}`",
                        "file_path": file_path,
                        "line_number": line_num,
                        "evidence": {
                            "matched_text": matched_text,
                            "line_number": line_num,
                            "cwe_id": cwe_id,
                        },
                    })
            except Exception as e:
                _log.debug(f"Pattern error in {file_path}: {e}")
        return findings

    def scan_repo(self, repo_path, list_files_fn=None, read_file_fn=None):
        """Scan an entire repository for CWE patterns."""
        all_findings = []
        files = list_files_fn(repo_path) if list_files_fn else _default_list_files(repo_path)
        for file_rel in files:
            full_path = os.path.join(repo_path, file_rel)
            # Skip non-source files
            if not _is_source_file(file_rel):
                continue
            try:
                if read_file_fn:
                    content = read_file_fn(full_path)
                else:
                    with open(full_path, "r", errors="replace") as f:
                        content = f.read()
                findings = self.scan_file(file_rel, content)
                all_findings.extend(findings)
            except Exception as e:
                _log.debug(f"Error scanning {file_rel}: {e}")
        return all_findings

    def generate_findings(self, scan_id, repo_path, add_finding_fn, list_files_fn=None):
        """Scan repo and save findings to database."""
        findings = self.scan_repo(repo_path, list_files_fn)
        for f in findings:
            add_finding_fn(
                scan_id=scan_id,
                title=f["title"],
                description=f["description"],
                severity=f["severity"],
                category="cwe",
                file_path=f.get("file_path", ""),
                line_number=f.get("line_number", 0),
                evidence=f.get("evidence", {}),
                cwe_id=f.get("cwe_id", ""),
                finding_part="cwes",
            )
        return len(findings)


def _default_list_files(repo_path):
    """Default file listing for CWE scanning."""
    from purpleteam.repo_manager import list_repo_files
    return list_repo_files(repo_path)


def _is_source_file(filepath):
    """Check if a file is a scannable source file."""
    ext = os.path.splitext(filepath)[1].lower()
    source_exts = {".py", ".java", ".kt", ".js", ".ts", ".jsx", ".tsx", ".go",
                   ".rs", ".rb", ".php", ".c", ".cpp", ".h", ".hpp", ".cs",
                   ".swift", ".scala", ".groovy", ".vue", ".svelte", ".toml",
                   ".yaml", ".yml", ".xml", ".properties", ".conf", ".cfg",
                   ".env", ".gradle", ".pom"}
    return ext in source_exts
