"""
db.py
-----
All database access goes through this module. EVERY query uses `?`
placeholders with parameters passed separately -- never Python string
formatting/concatenation into SQL. This is what actually prevents SQL
injection (parameterized queries make it structurally impossible for
user input to be interpreted as SQL syntax, regardless of what
characters it contains).

Example of what we deliberately never do:
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")   # VULNERABLE

What we do instead everywhere in this file:
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))  # SAFE
"""

import sqlite3
import time
from contextlib import contextmanager

DB_PATH = "secure_login.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def db_cursor():
    conn = get_connection()
    try:
        cur = conn.cursor()
        yield cur
        conn.commit()
    finally:
        conn.close()


def init_db():
    with db_cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                username            TEXT UNIQUE NOT NULL,
                email               TEXT UNIQUE NOT NULL,
                password_hash       TEXT NOT NULL,
                otp_secret          TEXT,
                is_2fa_enabled      INTEGER NOT NULL DEFAULT 0,
                failed_attempts     INTEGER NOT NULL DEFAULT 0,
                locked_until        REAL,
                created_at          REAL NOT NULL
            )
        """)


def create_user(username: str, email: str, password_hash: str) -> int | None:
    """Returns new user id, or None if username/email already taken."""
    try:
        with db_cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, email, password_hash, created_at) "
                "VALUES (?, ?, ?, ?)",
                (username, email, password_hash, time.time()),
            )
            return cur.lastrowid
    except sqlite3.IntegrityError:
        return None


def get_user_by_username(username: str):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cur.fetchone()


def get_user_by_id(user_id: int):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return cur.fetchone()


def record_failed_login(user_id: int, failed_attempts: int, locked_until):
    with db_cursor() as cur:
        cur.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
            (failed_attempts, locked_until, user_id),
        )


def reset_failed_login(user_id: int):
    with db_cursor() as cur:
        cur.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (user_id,),
        )


def set_pending_2fa_secret_confirmed(user_id: int, otp_secret: str):
    with db_cursor() as cur:
        cur.execute(
            "UPDATE users SET otp_secret = ?, is_2fa_enabled = 1 WHERE id = ?",
            (otp_secret, user_id),
        )


def disable_2fa(user_id: int):
    with db_cursor() as cur:
        cur.execute(
            "UPDATE users SET otp_secret = NULL, is_2fa_enabled = 0 WHERE id = ?",
            (user_id,),
        )
