"""
storage.py
SQLite persistence layer for the API: stores scan jobs and the
certificates found in each one, so results survive a server restart
and can be queried later (e.g. "give me the latest state of every
certificate ever scanned").
"""

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "api.db"

_lock = threading.Lock()


def _get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _lock:
        conn = _get_connection()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL,
                target_count INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                subject TEXT,
                issuer TEXT,
                not_after TEXT,
                days_until_expiry INTEGER,
                status TEXT,
                signature_algorithm TEXT,
                key_size INTEGER,
                flags TEXT,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            )
            """
        )
        conn.commit()
        conn.close()


def create_scan(scan_id: str, target_count: int) -> None:
    with _lock:
        conn = _get_connection()
        conn.execute(
            "INSERT INTO scans (id, created_at, status, target_count) VALUES (?, ?, ?, ?)",
            (scan_id, datetime.now(timezone.utc).isoformat(), "pending", target_count),
        )
        conn.commit()
        conn.close()


def complete_scan(scan_id: str, results: list[dict]) -> None:
    with _lock:
        conn = _get_connection()
        conn.execute("UPDATE scans SET status = ? WHERE id = ?", ("completed", scan_id))
        for r in results:
            conn.execute(
                """
                INSERT INTO certificates
                    (scan_id, host, port, subject, issuer, not_after,
                     days_until_expiry, status, signature_algorithm, key_size, flags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    r["host"],
                    r["port"],
                    r.get("subject"),
                    r.get("issuer"),
                    r.get("not_after"),
                    r.get("days_until_expiry"),
                    r.get("status"),
                    r.get("signature_algorithm"),
                    r.get("key_size"),
                    ";".join(r.get("flags", [])),
                ),
            )
        conn.commit()
        conn.close()


def fail_scan(scan_id: str, error: str) -> None:
    with _lock:
        conn = _get_connection()
        conn.execute("UPDATE scans SET status = ? WHERE id = ?", (f"failed: {error}", scan_id))
        conn.commit()
        conn.close()


def get_scan(scan_id: str) -> dict | None:
    conn = _get_connection()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not scan:
        conn.close()
        return None
    certs = conn.execute("SELECT * FROM certificates WHERE scan_id = ?", (scan_id,)).fetchall()
    conn.close()
    return {"scan": dict(scan), "certificates": [dict(c) for c in certs]}


def list_latest_certificates() -> list[dict]:
    """Returns the most recent known result for every host:port pair ever scanned."""
    conn = _get_connection()
    rows = conn.execute(
        """
        SELECT c.* FROM certificates c
        INNER JOIN (
            SELECT host, port, MAX(id) AS max_id
            FROM certificates
            GROUP BY host, port
        ) latest ON c.host = latest.host AND c.port = latest.port AND c.id = latest.max_id
        """
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
