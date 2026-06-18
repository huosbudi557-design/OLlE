"""
وحدة قاعدة البيانات
تستخدم SQLite لتخزين بيانات المستخدمين وسجل الفحوصات (روابط، ملفات، IP)
"""

import sqlite3
import json
from datetime import datetime
from contextlib import contextmanager

DB_PATH = "security_bot.db"


@contextmanager
def get_connection():
    """فتح اتصال بقاعدة البيانات وإغلاقه تلقائياً"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    """إنشاء الجداول إذا لم تكن موجودة"""
    with get_connection() as conn:
        cur = conn.cursor()

        # جدول المستخدمين
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                username TEXT,
                first_name TEXT,
                joined_at TEXT,
                is_banned INTEGER DEFAULT 0,
                scan_count INTEGER DEFAULT 0
            )
        """)

        # جدول سجل الفحوصات
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                scan_type TEXT,          -- url / file / ip
                target TEXT,             -- الرابط أو اسم الملف أو IP
                result_summary TEXT,     -- ملخص نصي للنتيجة
                raw_result TEXT,         -- JSON كامل بالنتيجة
                is_malicious INTEGER DEFAULT 0,
                created_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        """)

        # جدول إعدادات عامة (مفاتيح API وغيرها يديرها الأدمن عبر البوت)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        conn.commit()


def add_user(user_id: int, username: str, first_name: str):
    """إضافة مستخدم جديد إذا لم يكن موجوداً"""
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT user_id FROM users WHERE user_id = ?", (user_id,))
        if cur.fetchone() is None:
            cur.execute(
                "INSERT INTO users (user_id, username, first_name, joined_at) VALUES (?, ?, ?, ?)",
                (user_id, username, first_name, datetime.utcnow().isoformat())
            )


def is_user_banned(user_id: int) -> bool:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT is_banned FROM users WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        return bool(row["is_banned"]) if row else False


def ban_user(user_id: int, banned: bool = True):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE users SET is_banned = ? WHERE user_id = ?", (1 if banned else 0, user_id))


def log_scan(user_id: int, scan_type: str, target: str, result_summary: str,
             raw_result: dict, is_malicious: bool):
    """تسجيل عملية فحص جديدة وزيادة عداد فحوصات المستخدم"""
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO scans (user_id, scan_type, target, result_summary, raw_result, is_malicious, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id, scan_type, target, result_summary,
            json.dumps(raw_result, ensure_ascii=False), 1 if is_malicious else 0,
            datetime.utcnow().isoformat()
        ))
        cur.execute("UPDATE users SET scan_count = scan_count + 1 WHERE user_id = ?", (user_id,))
        return cur.lastrowid


def get_scan_by_id(scan_id: int):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
        return cur.fetchone()


def get_user_scans(user_id: int, limit: int = 10):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM scans WHERE user_id = ? ORDER BY scan_id DESC LIMIT ?",
            (user_id, limit)
        )
        return cur.fetchall()


def get_stats():
    """إحصائيات عامة للوحة تحكم الأدمن"""
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as c FROM users")
        total_users = cur.fetchone()["c"]

        cur.execute("SELECT COUNT(*) as c FROM scans")
        total_scans = cur.fetchone()["c"]

        cur.execute("SELECT COUNT(*) as c FROM scans WHERE is_malicious = 1")
        malicious_found = cur.fetchone()["c"]

        cur.execute("SELECT COUNT(*) as c FROM scans WHERE scan_type = 'url'")
        url_scans = cur.fetchone()["c"]

        cur.execute("SELECT COUNT(*) as c FROM scans WHERE scan_type = 'file'")
        file_scans = cur.fetchone()["c"]

        cur.execute("SELECT COUNT(*) as c FROM scans WHERE scan_type = 'ip'")
        ip_scans = cur.fetchone()["c"]

        return {
            "total_users": total_users,
            "total_scans": total_scans,
            "malicious_found": malicious_found,
            "url_scans": url_scans,
            "file_scans": file_scans,
            "ip_scans": ip_scans,
        }


def get_all_users(limit: int = 50):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users ORDER BY joined_at DESC LIMIT ?", (limit,))
        return cur.fetchall()


def set_setting(key: str, value: str):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value)
        )


def get_setting(key: str, default=None):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = cur.fetchone()
        return row["value"] if row else default
