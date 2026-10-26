import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "medimo.db"


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    connection = get_connection()

    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE
                    CHECK (length(trim(username)) > 0),
                password_hash TEXT NOT NULL
                    CHECK (length(trim(password_hash)) > 0)
            )
        """)
        connection.commit()
    finally:
        connection.close()

def create_user(username, password_hash):
    connection = get_connection()

    try:
        connection.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        connection.commit()
    finally:
        connection.close()

def get_user_by_username(username):
    connection = get_connection()

    try:
        return connection.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    finally:
        connection.close()


def get_user_by_id(user_id):
    connection = get_connection()

    try:
        return connection.execute(
            "SELECT id, username FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    finally:
        connection.close()

if __name__ == "__main__":
    init_db()
    print(f"Database siap: {DB_PATH}")