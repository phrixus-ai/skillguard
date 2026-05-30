"""SkillGuard Logger — SQLite-based scan logging."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).parent.parent.parent / "data" / "skillguard.db"


def _get_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    conn = _get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip_address TEXT,
            scan_type TEXT NOT NULL,
            target TEXT NOT NULL,
            risk_score INTEGER DEFAULT 0,
            risk_level TEXT DEFAULT 'LOW',
            files_scanned INTEGER DEFAULT 0,
            findings_count INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            warning_count INTEGER DEFAULT 0,
            duration_seconds REAL DEFAULT 0,
            top_categories TEXT,
            user_agent TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
        CREATE INDEX IF NOT EXISTS idx_scans_ip ON scans(ip_address);
        CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
    """)
    conn.commit()
    conn.close()


def log_scan(
    scan_type: str,
    target: str,
    risk_score: int = 0,
    risk_level: str = "LOW",
    files_scanned: int = 0,
    findings_count: int = 0,
    critical_count: int = 0,
    high_count: int = 0,
    warning_count: int = 0,
    duration_seconds: float = 0,
    top_categories: list[str] | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> int:
    conn = _get_db()
    cursor = conn.execute(
        """INSERT INTO scans
           (timestamp, ip_address, scan_type, target, risk_score, risk_level,
            files_scanned, findings_count, critical_count, high_count,
            warning_count, duration_seconds, top_categories, user_agent)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            datetime.now(timezone.utc).isoformat(),
            ip_address,
            scan_type,
            target[:500],
            risk_score,
            risk_level,
            files_scanned,
            findings_count,
            critical_count,
            high_count,
            warning_count,
            duration_seconds,
            json.dumps(top_categories or []),
            (user_agent or "")[:500],
        ),
    )
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def get_recent_scans(limit: int = 50) -> list[dict]:
    conn = _get_db()
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_scan_stats() -> dict:
    conn = _get_db()
    total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    avg_risk = conn.execute("SELECT AVG(risk_score) FROM scans").fetchone()[0] or 0
    by_type = conn.execute(
        "SELECT scan_type, COUNT(*) as cnt FROM scans GROUP BY scan_type"
    ).fetchall()
    conn.close()
    return {
        "total_scans": total,
        "avg_risk_score": round(avg_risk, 1),
        "by_type": {r["scan_type"]: r["cnt"] for r in by_type},
    }
