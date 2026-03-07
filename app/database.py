import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "guardian.db"


def get_connection():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = get_connection()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            region TEXT NOT NULL,
            services TEXT NOT NULL,
            work_situation TEXT NOT NULL,
            primary_concern TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            input_summary TEXT,
            output_summary TEXT,
            latency_ms INTEGER,
            model_used TEXT
        );
    """
    )
    conn.close()


def create_profile(region, services, work_situation, primary_concern):
    now = datetime.now(timezone.utc).isoformat()
    conn = get_connection()
    cursor = conn.execute(
        "INSERT INTO profiles (region, services, work_situation, primary_concern, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        (region, json.dumps(services), work_situation, primary_concern, now, now),
    )
    profile_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return profile_id


def get_profile(profile_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM profiles WHERE id = ?", (profile_id,)).fetchone()
    conn.close()
    if row is None:
        return None
    profile = dict(row)
    profile["services"] = json.loads(profile["services"])
    return profile


def update_profile(profile_id, region, services, work_situation, primary_concern):
    now = datetime.now(timezone.utc).isoformat()
    conn = get_connection()
    conn.execute(
        "UPDATE profiles SET region = ?, services = ?, work_situation = ?, primary_concern = ?, updated_at = ? WHERE id = ?",
        (
            region,
            json.dumps(services),
            work_situation,
            primary_concern,
            now,
            profile_id,
        ),
    )
    conn.commit()
    conn.close()


def list_profiles():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM profiles ORDER BY updated_at DESC").fetchall()
    conn.close()
    profiles = []
    for row in rows:
        p = dict(row)
        p["services"] = json.loads(p["services"])
        profiles.append(p)
    return profiles


def log_audit(tool_name, input_summary, output_summary, latency_ms, model_used):
    now = datetime.now(timezone.utc).isoformat()
    conn = get_connection()
    conn.execute(
        "INSERT INTO audit_log (timestamp, tool_name, input_summary, output_summary, latency_ms, model_used) VALUES (?, ?, ?, ?, ?, ?)",
        (now, tool_name, input_summary, output_summary, latency_ms, model_used),
    )
    conn.commit()
    conn.close()


def get_audit_log():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM audit_log ORDER BY timestamp DESC").fetchall()
    conn.close()
    return [dict(row) for row in rows]
