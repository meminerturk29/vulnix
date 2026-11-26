import sqlite3
import os
import hashlib
from datetime import datetime, date, timedelta
from typing import List, Dict, Any, Optional

DB_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(DB_DIR, "vms.db")
UPLOAD_DIR = os.path.join(DB_DIR, "static", "uploads")

os.makedirs(UPLOAD_DIR, exist_ok=True)


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _hash_pw(password: str) -> str:
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.hex() + ':' + key.hex()


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # ── Users table ──
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        department TEXT DEFAULT '',
        is_active INTEGER DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """)

    # ── Sessions table ──
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    # ── Vulnerabilities table ──
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        record_no TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        cvss_score REAL DEFAULT 0.0,
        cvss_vector TEXT DEFAULT '',
        department TEXT NOT NULL,
        assignee_name TEXT NOT NULL,
        assignee_email TEXT NOT NULL,
        assignee_user_id INTEGER,
        status TEXT NOT NULL DEFAULT 'Açık',
        due_date TEXT,
        closed_date TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        tool_source TEXT NOT NULL DEFAULT 'OpenVAS',
        target_host TEXT NOT NULL,
        target_port TEXT DEFAULT '',
        target_os TEXT DEFAULT '',
        description TEXT NOT NULL,
        threat_assessment TEXT NOT NULL,
        remediation TEXT NOT NULL,
        image_path TEXT DEFAULT '',
        cve_id TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        FOREIGN KEY (assignee_user_id) REFERENCES users(id)
    )
    """)

    # ── Response / Action history table ──
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS responses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vuln_id INTEGER NOT NULL,
        user_id INTEGER,
        author_name TEXT NOT NULL,
        action_type TEXT NOT NULL,
        message TEXT NOT NULL,
        attachment_path TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # ── Email notification logs ──
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS email_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vuln_id INTEGER,
        sent_by_user_id INTEGER,
        recipient_email TEXT NOT NULL,
        recipient_name TEXT NOT NULL,
        subject TEXT NOT NULL,
        body TEXT NOT NULL,
        status TEXT NOT NULL,
        error_message TEXT DEFAULT '',
        sent_at TEXT NOT NULL
    )
    """)

    # ── System settings ──
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS system_settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    """)

    conn.commit()

    # ── Seed default settings (OpenVAS at 10.10.1.12 on VMware NAT VMnet8) ──
    default_settings = {
        "company_name": "Kurumsal Siber Güvenlik Birimi",
        "smtp_host": "",
        "smtp_port": "587",
        "smtp_user": "",
        "smtp_pass": "",
        "smtp_from": "",
        "smtp_tls": "1",
        "openvas_url": "https://10.10.1.12",
        "openvas_username": "admin",
        "openvas_password": "admin",
        "openvas_auto_sync": "1",
        "openvas_sync_interval": "15",
        "openvas_include_logs": "0",
        "openvas_last_sync": "",
        "openvas_last_status": "Hazır - Bekleniyor",
        "openvas_last_findings_count": "0",
        "nessus_url": "",
        "nessus_access_key": "",
        "nessus_secret_key": ""
    }
    for key, val in default_settings.items():
        cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES (?, ?)", (key, val))

    # Update openvas_url to 10.10.1.12 for NAT mode
    cursor.execute("UPDATE system_settings SET value = 'https://10.10.1.12' WHERE key = 'openvas_url' AND (value LIKE '%192.168.1.180%' OR value LIKE '%127.0.0.1%' OR value = '')")
    cursor.execute("UPDATE system_settings SET value = 'admin' WHERE key = 'openvas_password' AND (value = '' OR value IS NULL)")
    conn.commit()

    # ── Seed users if empty ──
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        seed_users(conn)

    # Note: Mock vulnerabilities seeding is permanently disabled per user request!
    # Real data only comes from OpenVAS or manual user input.

    conn.close()


def clear_all_vulnerabilities():
    """Wipes all test/sample vulnerabilities and response records."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM responses")
    cursor.execute("DELETE FROM vulnerabilities")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name IN ('vulnerabilities', 'responses')")
    conn.commit()
    conn.close()


def generate_next_record_no(conn: sqlite3.Connection) -> str:
    cursor = conn.cursor()
    year = datetime.now().year
    prefix = f"VULN-{year}-"
    cursor.execute("SELECT record_no FROM vulnerabilities WHERE record_no LIKE ? ORDER BY id DESC LIMIT 1", (f"{prefix}%",))
    row = cursor.fetchone()
    if row:
        last_num = int(row[0].split("-")[-1])
        next_num = last_num + 1
    else:
        next_num = 1
    return f"{prefix}{next_num:04d}"


def calculate_severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "Kritik"
    elif score >= 7.0:
        return "Yüksek"
    elif score >= 4.0:
        return "Orta"
    elif score > 0.0:
        return "Düşük"
    else:
        return "Bilgi"


def seed_users(conn: sqlite3.Connection):
    cursor = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Only default Administrator account is seeded. All team members are added via /users UI.
    cursor.execute("""
        INSERT OR IGNORE INTO users (username, password_hash, full_name, email, role, department, is_active, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'admin', ?, 1, ?, ?)
    """, ("admin", _hash_pw("admin123"), "Sistem Yöneticisi (Admin)", "admin@sirket.com", "Bilgi Güvenliği / SOC", now_str, now_str))

    conn.commit()
