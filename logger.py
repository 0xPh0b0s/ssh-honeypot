"""
logger.py — SQLite-backed session logger for the SSH honeypot.
"""

import sqlite3
import threading
import time
from pathlib import Path

DB_PATH = Path(__file__).parent / "honeypot.db"
_lock = threading.Lock()


def _connect():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they don't exist."""
    with _connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS attempts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          REAL    NOT NULL,
                ip          TEXT    NOT NULL,
                port        INTEGER NOT NULL,
                username    TEXT    NOT NULL,
                password    TEXT    NOT NULL,
                success     INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                attempt_id  INTEGER NOT NULL REFERENCES attempts(id),
                started_at  REAL    NOT NULL,
                ended_at    REAL,
                FOREIGN KEY(attempt_id) REFERENCES attempts(id)
            );

            CREATE TABLE IF NOT EXISTS commands (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id  INTEGER NOT NULL REFERENCES sessions(id),
                ts          REAL    NOT NULL,
                command     TEXT    NOT NULL
            );
        """)


def log_attempt(ip: str, port: int, username: str, password: str, success: bool) -> int:
    """Log a login attempt and return the attempt ID."""
    with _lock, _connect() as conn:
        cur = conn.execute(
            "INSERT INTO attempts (ts, ip, port, username, password, success) VALUES (?,?,?,?,?,?)",
            (time.time(), ip, port, username, password, int(success))
        )
        return cur.lastrowid


def open_session(attempt_id: int) -> int:
    """Open a new session for a successful login; return session ID."""
    with _lock, _connect() as conn:
        cur = conn.execute(
            "INSERT INTO sessions (attempt_id, started_at) VALUES (?,?)",
            (attempt_id, time.time())
        )
        return cur.lastrowid


def close_session(session_id: int):
    """Mark a session as ended."""
    with _lock, _connect() as conn:
        conn.execute(
            "UPDATE sessions SET ended_at=? WHERE id=?",
            (time.time(), session_id)
        )


def log_command(session_id: int, command: str):
    """Log a command typed during a session."""
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO commands (session_id, ts, command) VALUES (?,?,?)",
            (session_id, time.time(), command)
        )


# ---------------------------------------------------------------------------
# Read helpers (used by the dashboard)
# ---------------------------------------------------------------------------

def get_recent_attempts(limit: int = 100):
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM attempts ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_sessions():
    with _connect() as conn:
        rows = conn.execute("""
            SELECT s.id, s.started_at, s.ended_at,
                   a.ip, a.username, a.password
            FROM sessions s
            JOIN attempts a ON a.id = s.attempt_id
            ORDER BY s.started_at DESC
        """).fetchall()
    return [dict(r) for r in rows]


def get_commands(session_id: int):
    with _connect() as conn:
        rows = conn.execute(
            "SELECT ts, command FROM commands WHERE session_id=? ORDER BY ts",
            (session_id,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_stats():
    with _connect() as conn:
        total    = conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]
        success  = conn.execute("SELECT COUNT(*) FROM attempts WHERE success=1").fetchone()[0]
        unique   = conn.execute("SELECT COUNT(DISTINCT ip) FROM attempts").fetchone()[0]
        sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    return {
        "total_attempts":  total,
        "successful_logins": success,
        "unique_ips":      unique,
        "total_sessions":  sessions,
        "fail_rate":       round((total - success) / total * 100, 1) if total else 0,
    }
