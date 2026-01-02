import sqlite3
from typing import Optional, Dict
import threading


class Database:
    def __init__(self, db_name: str = "server.db"):
        self.db_name = db_name
        self._lock = threading.Lock()
        self._init_database()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_name, timeout=10.0)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_database(self):
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    hash TEXT NOT NULL,
                    salt TEXT,
                    totp_secret TEXT
                )
            """
            )
            conn.commit()
        finally:
            conn.close()

    def get_user(self, username: str) -> Optional[Dict]:
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT hash, salt, totp_secret FROM users WHERE username = ?",
                (username,),
            )
            row = cursor.fetchone()

            if row is None:
                return None

            user = {"hash": row[0]}
            if row[1]:  # salt
                user["salt"] = row[1]
            if row[2]:  # totp_secret
                user["totp_secret"] = row[2]

            return user
        finally:
            conn.close()

    def user_exists(self, username: str) -> bool:
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
            exists = cursor.fetchone() is not None
            return exists
        finally:
            conn.close()

    def save_user(
        self,
        username: str,
        hash_value: str,
        salt: Optional[str] = None,
        totp_secret: Optional[str] = None,
    ):
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO users (username, hash, salt, totp_secret)
                VALUES (?, ?, ?, ?)
            """,
                (username, hash_value, salt, totp_secret),
            )
            conn.commit()
        finally:
            conn.close()

    def get_all_users(self) -> Dict:
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT username, hash, salt, totp_secret FROM users")
            rows = cursor.fetchall()

            users = {}
            for row in rows:
                username, hash_value, salt, totp_secret = row
                user = {"hash": hash_value}
                if salt:
                    user["salt"] = salt
                if totp_secret:
                    user["totp_secret"] = totp_secret
                users[username] = user

            return users
        finally:
            conn.close()
