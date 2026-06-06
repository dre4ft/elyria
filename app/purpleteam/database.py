# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Purple Team module — database operations (profiles, scans, findings, repos).
Integrates into the main SQLite database.
"""

import uuid
import json
from datetime import datetime, timezone
from database.connection import get_connection


def _connect():
    return get_connection()


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def init_purpleteam_db():
    conn = _connect()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS purpleteam_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            repo_source TEXT DEFAULT 'github',
            repo_url TEXT DEFAULT '',
            repo_auth_type TEXT DEFAULT '',
            repo_auth_key TEXT DEFAULT '',
            repo_branch TEXT DEFAULT 'main',
            target_endpoint TEXT DEFAULT '',
            openapi_spec_url TEXT DEFAULT '',
            collection_id TEXT DEFAULT '',
            user_id TEXT DEFAULT '',
            team_ids TEXT DEFAULT '',
            scan_depth TEXT DEFAULT 'full',
            status TEXT DEFAULT 'pending',
            scan_progress INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS purpleteam_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE NOT NULL,
            profile_id TEXT DEFAULT '',
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            repo_source TEXT DEFAULT 'github',
            repo_url TEXT DEFAULT '',
            repo_auth_type TEXT DEFAULT '',
            repo_auth_key TEXT DEFAULT '',
            repo_branch TEXT DEFAULT 'main',
            target_endpoint TEXT DEFAULT '',
            openapi_spec_url TEXT DEFAULT '',
            collection_id TEXT DEFAULT '',
            repo_path TEXT DEFAULT '',
            user_id TEXT DEFAULT '',
            team_ids TEXT DEFAULT '',
            scan_depth TEXT DEFAULT 'full',
            status TEXT DEFAULT 'pending',
            scan_progress INTEGER DEFAULT 0,
            phase TEXT DEFAULT '',
            flash_model TEXT DEFAULT '',
            pro_model TEXT DEFAULT '',
            tokens_used INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS purpleteam_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id TEXT UNIQUE NOT NULL,
            scan_id TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            severity TEXT NOT NULL DEFAULT 'info',
            category TEXT DEFAULT '',
            file_path TEXT DEFAULT '',
            line_number INTEGER DEFAULT 0,
            evidence TEXT DEFAULT '{}',
            remediation TEXT DEFAULT '',
            cvss_score REAL DEFAULT 0,
            cve_id TEXT DEFAULT '',
            cwe_id TEXT DEFAULT '',
            ai_analysis TEXT DEFAULT '',
            finding_part TEXT DEFAULT 'practices',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES purpleteam_scans(scan_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS purpleteam_repos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_id TEXT UNIQUE NOT NULL,
            user_id TEXT NOT NULL,
            repo_source TEXT NOT NULL DEFAULT 'local',
            repo_url TEXT DEFAULT '',
            repo_path TEXT NOT NULL,
            size_bytes INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS purpleteam_cve_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dependency_name TEXT NOT NULL,
            dependency_version TEXT DEFAULT '',
            cve_data TEXT DEFAULT '{}',
            queried_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_cve_cache_lookup ON purpleteam_cve_cache(dependency_name, dependency_version);
    """)
    conn.commit()
    conn.close()


# ── Profile CRUD ──

def create_profile(name, repo_source="github", repo_url="", repo_auth_type="", repo_auth_key="",
                   repo_branch="main", target_endpoint="", openapi_spec_url="", collection_id="",
                   user_id="", team_ids="", description="", scan_depth="full"):
    conn = _connect()
    pid = str(uuid.uuid4())
    now = _now()
    conn.execute(
        "INSERT INTO purpleteam_profiles (profile_id, name, description, repo_source, repo_url, repo_auth_type, repo_auth_key, repo_branch, target_endpoint, openapi_spec_url, collection_id, user_id, team_ids, scan_depth, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (pid, name, description, repo_source, repo_url, repo_auth_type, repo_auth_key, repo_branch,
         target_endpoint, openapi_spec_url, collection_id, user_id, team_ids, scan_depth, "pending", now, now),
    )
    conn.commit()
    conn.close()
    return pid


def list_profiles(user_id=None, team_ids=None, team_filter=None):
    conn = _connect()
    if team_filter:
        rows = conn.execute(
            "SELECT * FROM purpleteam_profiles WHERE team_ids LIKE ? ORDER BY updated_at DESC",
            (f"%{team_filter}%",),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    q = "SELECT * FROM purpleteam_profiles WHERE 1=1"
    args = []
    if user_id:
        q += " AND (user_id=? OR user_id=''"
        args.append(user_id)
        if team_ids:
            for t in team_ids.split(","):
                t = t.strip()
                if t:
                    q += " OR team_ids LIKE ?"
                    args.append(f"%{t}%")
        q += ")"
    q += " ORDER BY updated_at DESC"
    rows = conn.execute(q, args).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_profile(profile_id):
    conn = _connect()
    row = conn.execute("SELECT * FROM purpleteam_profiles WHERE profile_id=?", (profile_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_profile(profile_id, **kwargs):
    conn = _connect()
    now = _now()
    sets = ["updated_at=?"]
    args = [now]
    for k, v in kwargs.items():
        if k in ("name", "description", "repo_source", "repo_url", "repo_auth_type",
                  "repo_auth_key", "repo_branch", "target_endpoint", "openapi_spec_url",
                  "collection_id", "team_ids", "scan_depth", "status"):
            sets.append(f"{k}=?")
            args.append(v)
        elif k in ("scan_progress",):
            sets.append(f"{k}=?")
            args.append(int(v))
    args.append(profile_id)
    conn.execute(f"UPDATE purpleteam_profiles SET {', '.join(sets)} WHERE profile_id=?", args)
    conn.commit()
    conn.close()


def delete_profile(profile_id):
    conn = _connect()
    conn.execute("DELETE FROM purpleteam_profiles WHERE profile_id=?", (profile_id,))
    conn.commit()
    conn.close()


# ── Scan CRUD ──

def create_scan(profile_id, name, repo_source="github", repo_url="", repo_auth_type="", repo_auth_key="",
                repo_branch="main", target_endpoint="", openapi_spec_url="", collection_id="",
                user_id="", team_ids="", description="", scan_depth="full"):
    conn = _connect()
    sid = str(uuid.uuid4())
    now = _now()
    conn.execute(
        "INSERT INTO purpleteam_scans (scan_id, profile_id, name, description, repo_source, repo_url, repo_auth_type, repo_auth_key, repo_branch, target_endpoint, openapi_spec_url, collection_id, user_id, team_ids, scan_depth, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (sid, profile_id, name, description, repo_source, repo_url, repo_auth_type, repo_auth_key,
         repo_branch, target_endpoint, openapi_spec_url, collection_id, user_id, team_ids, scan_depth,
         "pending", now, now),
    )
    conn.commit()
    conn.close()
    return sid


def get_scan(scan_id):
    conn = _connect()
    row = conn.execute("SELECT * FROM purpleteam_scans WHERE scan_id=?", (scan_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_scans(user_id=None, team_ids=None, profile_id=None):
    conn = _connect()
    q = "SELECT * FROM purpleteam_scans WHERE 1=1"
    args = []
    if profile_id:
        q += " AND profile_id=?"
        args.append(profile_id)
    if user_id:
        q += " AND (user_id=? OR user_id=''"
        args.append(user_id)
        if team_ids:
            for t in team_ids.split(","):
                t = t.strip()
                if t:
                    q += " OR team_ids LIKE ?"
                    args.append(f"%{t}%")
        q += ")"
    q += " ORDER BY created_at DESC"
    rows = conn.execute(q, args).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_scan(scan_id, **kwargs):
    conn = _connect()
    now = _now()
    sets = ["updated_at=?"]
    args = [now]
    for k, v in kwargs.items():
        if k in ("status", "phase", "repo_path", "flash_model", "pro_model", "scan_depth"):
            sets.append(f"{k}=?")
            args.append(v)
        elif k in ("scan_progress", "tokens_used"):
            sets.append(f"{k}=?")
            args.append(int(v))
    args.append(scan_id)
    conn.execute(f"UPDATE purpleteam_scans SET {', '.join(sets)} WHERE scan_id=?", args)
    conn.commit()
    conn.close()


def delete_scan(scan_id):
    conn = _connect()
    conn.execute("DELETE FROM purpleteam_findings WHERE scan_id=?", (scan_id,))
    conn.execute("DELETE FROM purpleteam_scans WHERE scan_id=?", (scan_id,))
    conn.commit()
    conn.close()


# ── Findings CRUD ──

def add_finding(scan_id, title, description, severity="info", category="", file_path="",
                line_number=0, evidence=None, remediation="", cvss_score=0.0, cve_id="",
                cwe_id="", ai_analysis="", finding_part="practices"):
    conn = _connect()
    # Dedup by title + file_path
    existing = conn.execute(
        "SELECT finding_id FROM purpleteam_findings WHERE scan_id=? AND title=? AND file_path=?",
        (scan_id, title, file_path),
    ).fetchone()
    if existing:
        conn.close()
        return existing["finding_id"]
    fid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO purpleteam_findings (finding_id, scan_id, title, description, severity, category, file_path, line_number, evidence, remediation, cvss_score, cve_id, cwe_id, ai_analysis, finding_part) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (fid, scan_id, title, description, severity, category, file_path, line_number,
         json.dumps(evidence or {}), remediation, cvss_score, cve_id, cwe_id, ai_analysis, finding_part),
    )
    conn.commit()
    conn.close()
    return fid


def get_scan_findings(scan_id):
    conn = _connect()
    rows = conn.execute(
        """SELECT * FROM purpleteam_findings WHERE scan_id=?
           ORDER BY CASE severity
             WHEN 'critical' THEN 1
             WHEN 'high' THEN 2
             WHEN 'medium' THEN 3
             WHEN 'low' THEN 4
             WHEN 'info' THEN 5
             ELSE 99 END, created_at""",
        (scan_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_finding_counts(scan_id):
    conn = _connect()
    rows = conn.execute(
        "SELECT severity, COUNT(*) as cnt FROM purpleteam_findings WHERE scan_id=? GROUP BY severity",
        (scan_id,),
    ).fetchall()
    conn.close()
    return {r["severity"]: r["cnt"] for r in rows}


# ── Repo storage tracking ──

def register_repo(user_id, repo_source, repo_path, repo_url="", size_bytes=0):
    conn = _connect()
    rid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO purpleteam_repos (repo_id, user_id, repo_source, repo_url, repo_path, size_bytes) VALUES (?,?,?,?,?,?)",
        (rid, user_id, repo_source, repo_url, repo_path, size_bytes),
    )
    conn.commit()
    conn.close()
    return rid


def get_user_repo_usage(user_id):
    """Return total storage bytes used by a user across all repos."""
    conn = _connect()
    row = conn.execute(
        "SELECT COALESCE(SUM(size_bytes), 0) FROM purpleteam_repos WHERE user_id=?", (user_id,)
    ).fetchone()
    conn.close()
    return row[0] if row else 0


def delete_repo_by_path(repo_path):
    conn = _connect()
    conn.execute("DELETE FROM purpleteam_repos WHERE repo_path=?", (repo_path,))
    conn.commit()
    conn.close()


# ── CVE cache ──

def get_cached_cve(dependency_name, dependency_version=""):
    conn = _connect()
    row = conn.execute(
        "SELECT cve_data, queried_at FROM purpleteam_cve_cache WHERE dependency_name=? AND dependency_version=? ORDER BY queried_at DESC LIMIT 1",
        (dependency_name, dependency_version),
    ).fetchone()
    conn.close()
    if row:
        queried_at = row["queried_at"]
        try:
            from datetime import datetime as dt
            age_hours = (dt.utcnow() - dt.strptime(queried_at, "%Y-%m-%d %H:%M:%S")).total_seconds() / 3600
            if age_hours < 24:
                return json.loads(row["cve_data"])
        except Exception:
            pass
    return None


def set_cached_cve(dependency_name, dependency_version, cve_data):
    conn = _connect()
    conn.execute(
        "INSERT INTO purpleteam_cve_cache (dependency_name, dependency_version, cve_data) VALUES (?,?,?)",
        (dependency_name, dependency_version, json.dumps(cve_data)),
    )
    conn.commit()
    conn.close()
