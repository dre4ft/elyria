# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Grey Team (OSINT) — database operations (profiles, reports, findings).
Follows the same pattern as redteam/database.py and blueteam/database.py.
"""

import uuid
import json
from datetime import datetime, timezone
from database.connection import get_connection


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def init_greyteam_db():
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS greyteam_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            target_domain TEXT DEFAULT '',
            target_path TEXT DEFAULT '',
            categories TEXT DEFAULT '[]',
            user_id TEXT DEFAULT '',
            team_ids TEXT DEFAULT '',
            explore_rounds INTEGER DEFAULT 15,
            analysis_rounds INTEGER DEFAULT 5,
            scan_progress INTEGER DEFAULT 0,
            tokens_used INTEGER DEFAULT 0,
            target_domain TEXT DEFAULT '',
            status TEXT DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS greyteam_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT UNIQUE NOT NULL,
            profile_id TEXT NOT NULL,
            name TEXT DEFAULT '',
            description TEXT DEFAULT '',
            categories TEXT DEFAULT '[]',
            target_domain TEXT DEFAULT '',
            target_path TEXT DEFAULT '',
            status TEXT DEFAULT 'running',
            scan_progress INTEGER DEFAULT 0,
            total_findings INTEGER DEFAULT 0,
            deterministic_findings INTEGER DEFAULT 0,
            ai_findings INTEGER DEFAULT 0,
            analysis_rounds INTEGER DEFAULT 0,
            tokens_used INTEGER DEFAULT 0,
            pro_model TEXT DEFAULT '',
            report_markdown TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (profile_id) REFERENCES greyteam_profiles(profile_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS greyteam_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id TEXT UNIQUE NOT NULL,
            report_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT DEFAULT 'medium',
            category TEXT DEFAULT '',
            description TEXT DEFAULT '',
            file_path TEXT DEFAULT '',
            line_number INTEGER DEFAULT 0,
            evidence TEXT DEFAULT '',
            remediation TEXT DEFAULT '',
            cwe_id TEXT DEFAULT '',
            source TEXT DEFAULT 'deterministic',
            ai_description TEXT DEFAULT '',
            finding_type TEXT DEFAULT 'osint',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (report_id) REFERENCES greyteam_reports(report_id) ON DELETE CASCADE
        );
    """)
    conn.commit()
    conn.close()


# ── Profiles CRUD ──


def create_profile(name, user_id="", team_ids="", description="",
                   target_path="", target_domain="", categories=None, explore_rounds=15, analysis_rounds=5):
    conn = get_connection()
    pid = str(uuid.uuid4())
    now = _now()
    conn.execute(
        """INSERT INTO greyteam_profiles
           (profile_id, name, description, target_path, target_domain, categories,
            user_id, team_ids, explore_rounds, analysis_rounds, status, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (pid, name, description, target_path, target_domain,
         json.dumps(categories or []), user_id, team_ids,
         explore_rounds, analysis_rounds, "pending", now, now),
    )
    conn.commit()
    conn.close()
    return pid


def list_profiles(user_id="", team_ids="", personal_only=False, team_filter=""):
    conn = get_connection()
    params = []
    if team_filter:
        rows = conn.execute(
            "SELECT * FROM greyteam_profiles WHERE team_ids LIKE ? ORDER BY updated_at DESC",
            (f"%{team_filter}%",),
        ).fetchall()
    elif personal_only:
        rows = conn.execute(
            "SELECT * FROM greyteam_profiles WHERE user_id=? ORDER BY updated_at DESC",
            (user_id,),
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT * FROM greyteam_profiles
               WHERE user_id=? OR team_ids LIKE ? OR team_ids=''
               ORDER BY updated_at DESC""",
            (user_id, f"%{team_ids}%"),
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_profile(profile_id):
    conn = get_connection()
    r = conn.execute("SELECT * FROM greyteam_profiles WHERE profile_id=?", (profile_id,)).fetchone()
    conn.close()
    return dict(r) if r else None


def update_profile(profile_id, **kw):
    conn = get_connection()
    sets = []
    vals = []
    for k, v in kw.items():
        if k in ("name", "description", "target_path", "target_domain", "categories",
                 "user_id", "team_ids", "explore_rounds", "analysis_rounds", "status"):
            sets.append(f"{k}=?")
            vals.append(json.dumps(v) if isinstance(v, list) else v)
    if sets:
        vals.append(profile_id)
        conn.execute(f"UPDATE greyteam_profiles SET {', '.join(sets)}, updated_at=? WHERE profile_id=?", (*vals, _now()))
    conn.commit()
    conn.close()


def delete_profile(profile_id):
    conn = get_connection()
    conn.execute("DELETE FROM greyteam_profiles WHERE profile_id=?", (profile_id,))
    conn.commit()
    conn.close()


# ── Reports CRUD ──


def create_report(profile_id, name="", description="", categories=None, target_path="", target_domain=""):
    conn = get_connection()
    rid = str(uuid.uuid4())
    now = _now()
    conn.execute(
        """INSERT INTO greyteam_reports
           (report_id, profile_id, name, description, categories, target_path, target_domain, status, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (rid, profile_id, name, description, json.dumps(categories or []),
         target_path, target_domain, "running", now, now),
    )
    conn.commit()
    conn.close()
    return rid


def get_report(report_id):
    conn = get_connection()
    r = conn.execute("SELECT * FROM greyteam_reports WHERE report_id=?", (report_id,)).fetchone()
    conn.close()
    return dict(r) if r else None

def get_last_report_by_user(user_id):
    conn = get_connection()
    row = conn.execute(
        """SELECT r.* FROM greyteam_reports r
           JOIN greyteam_profiles p ON r.profile_id = p.profile_id
           WHERE p.user_id=? OR p.team_ids LIKE ? OR p.team_ids=''
           ORDER BY r.created_at DESC LIMIT 1""",
        (user_id, f"%{user_id}%"),
    ).fetchone()
    conn.close()
    return dict(row) if row else None




def list_reports(profile_id="", user_id="", team_ids=""):
    conn = get_connection()
    if profile_id:
        rows = conn.execute(
            "SELECT * FROM greyteam_reports WHERE profile_id=? ORDER BY created_at DESC",
            (profile_id,),
        ).fetchall()
    else:
        # Join with profiles for ownership
        rows = conn.execute(
            """SELECT r.* FROM greyteam_reports r
               JOIN greyteam_profiles p ON r.profile_id = p.profile_id
               WHERE p.user_id=? OR p.team_ids LIKE ? OR p.team_ids=''
               ORDER BY r.created_at DESC""",
            (user_id, f"%{team_ids}%"),
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_report(report_id, **kw):
    conn = get_connection()
    sets = []
    vals = []
    for k, v in kw.items():
        if k in ("status", "scan_progress", "total_findings", "deterministic_findings",
                 "ai_findings", "analysis_rounds", "tokens_used", "report_markdown", "pro_model",
                 "name", "description", "target_domain"):
            sets.append(f"{k}=?")
            vals.append(v)
    if sets:
        vals.append(report_id)
        conn.execute(f"UPDATE greyteam_reports SET {', '.join(sets)}, updated_at=? WHERE report_id=?", (*vals, _now()))
    conn.commit()
    conn.close()


def delete_report(report_id):
    conn = get_connection()
    conn.execute("DELETE FROM greyteam_findings WHERE report_id=?", (report_id,))
    conn.execute("DELETE FROM greyteam_reports WHERE report_id=?", (report_id,))
    conn.commit()
    conn.close()


def delete_reports_for_profile(profile_id):
    conn = get_connection()
    rows = conn.execute("SELECT report_id FROM greyteam_reports WHERE profile_id=?", (profile_id,)).fetchall()
    for r in rows:
        conn.execute("DELETE FROM greyteam_findings WHERE report_id=?", (r["report_id"],))
    conn.execute("DELETE FROM greyteam_reports WHERE profile_id=?", (profile_id,))
    conn.commit()
    conn.close()




# ── Findings CRUD ──


def add_finding(report_id, title, severity="medium", category="", description="",
                file_path="", line_number=0, evidence="", remediation="",
                cwe_id="", source="deterministic", ai_description="", finding_type="osint"):
    conn = get_connection()
    fid = str(uuid.uuid4())
    conn.execute(
        """INSERT INTO greyteam_findings
           (finding_id, report_id, title, severity, category, description,
            file_path, line_number, evidence, remediation, cwe_id, source, ai_description, finding_type)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (fid, report_id, title, severity, category, description,
         file_path, line_number, evidence, remediation, cwe_id, source, ai_description, finding_type),
    )
    # Update counts
    conn.execute(
        "UPDATE greyteam_reports SET total_findings = total_findings + 1, "
        "deterministic_findings = CASE WHEN ?='deterministic' THEN deterministic_findings + 1 ELSE deterministic_findings END, "
        "ai_findings = CASE WHEN ?='ai' THEN ai_findings + 1 ELSE ai_findings END "
        "WHERE report_id=?",
        (source, source, report_id),
    )
    conn.commit()
    conn.close()
    return fid


def get_report_findings(report_id):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM greyteam_findings WHERE report_id=? ORDER BY "
        "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, created_at",
        (report_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_finding_counts(report_id):
    conn = get_connection()
    r = conn.execute(
        "SELECT severity, COUNT(*) as cnt FROM greyteam_findings WHERE report_id=? GROUP BY severity",
        (report_id,),
    ).fetchall()
    conn.close()
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for row in r:
        sev = row["severity"].lower()
        if sev in counts:
            counts[sev] = row["cnt"]
    return counts


def get_finding(finding_id):
    conn = get_connection()
    r = conn.execute("SELECT * FROM greyteam_findings WHERE finding_id=?", (finding_id,)).fetchone()
    conn.close()
    return dict(r) if r else None


def delete_finding(finding_id):
    conn = get_connection()
    f = conn.execute("SELECT finding_id, report_id, source FROM greyteam_findings WHERE finding_id=?", (finding_id,)).fetchone()
    if f:
        conn.execute("DELETE FROM greyteam_findings WHERE finding_id=?", (finding_id,))
        dec = "deterministic_findings" if f["source"] == "deterministic" else "ai_findings"
        conn.execute(f"UPDATE greyteam_reports SET total_findings = total_findings - 1, {dec} = {dec} - 1 WHERE report_id=?", (f["report_id"],))
        conn.commit()
    conn.close()
