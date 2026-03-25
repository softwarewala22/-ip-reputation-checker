from db import get_connection
from datetime import datetime, timedelta, timezone
import json


# 🟢 CREATE TABLES
def create_table():
    with get_connection() as conn:
        # 🔹 IP CACHE TABLE
        conn.execute("""
        CREATE TABLE IF NOT EXISTS ip_data (
            ip TEXT PRIMARY KEY,
            data TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """)

        # 🔹 USER REQUEST LOG TABLE
        conn.execute("""
        CREATE TABLE IF NOT EXISTS request_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            searched_ip TEXT,
            user_ip TEXT,
            user_agent TEXT,
            created_at TEXT
        )
        """)


# 🔍 GET IP DATA (VALID FOR LAST 2 DAYS)
def get_ip_data(ip: str):
    five_days_ago = datetime.now(timezone.utc) - timedelta(days=5)

    with get_connection() as conn:
        cursor = conn.execute("""
        SELECT data FROM ip_data
        WHERE ip = ? AND created_at >= ?
        """, (ip, five_days_ago.isoformat()))

        row = cursor.fetchone()

    if row:
        try:
            return json.loads(row["data"])
        except json.JSONDecodeError:
            return None

    return None


# 💾 SAVE / UPDATE IP DATA
def save_ip_data(ip: str, data: dict):
    now = datetime.now(timezone.utc).isoformat()

    with get_connection() as conn:
        conn.execute("""
        INSERT INTO ip_data (ip, data, created_at)
        VALUES (?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            data = excluded.data,
            created_at = excluded.created_at
        """, (ip, json.dumps(data), now))


# 📝 SAVE USER REQUEST LOG
def save_request_log(searched_ip: str, user_ip: str, user_agent: str):
    now = datetime.now(timezone.utc).isoformat()

    with get_connection() as conn:
        conn.execute("""
        INSERT INTO request_logs (searched_ip, user_ip, user_agent, created_at)
        VALUES (?, ?, ?, ?)
        """, (searched_ip, user_ip, user_agent, now))


# 🧹 CLEANUP OLD DATA (OLDER THAN 2 DAYS)
def cleanup_old_data():
    cutoff = datetime.now(timezone.utc) - timedelta(days=5)

    with get_connection() as conn:
        conn.execute("""
        DELETE FROM ip_data
        WHERE created_at < ?
        """, (cutoff.isoformat(),))

        conn.execute("""
        DELETE FROM request_logs
        WHERE created_at < ?
        """, (cutoff.isoformat(),))