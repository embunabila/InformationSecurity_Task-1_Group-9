
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "medimo.db"


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db():
    connection = get_connection()

    try:
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE
                    CHECK (length(trim(username)) > 0),
                password_hash TEXT NOT NULL
                    CHECK (length(trim(password_hash)) > 0)
            );

            CREATE TABLE IF NOT EXISTS health_profiles (
                user_id INTEGER PRIMARY KEY,
                aes_envelope BLOB NOT NULL,
                des_envelope BLOB NOT NULL,
                rc4_envelope BLOB NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS medical_files (
                id TEXT PRIMARY KEY,
                owner_id INTEGER NOT NULL,
                category TEXT NOT NULL
                    CHECK (
                        category IN ('identity', 'document', 'video')
                    ),
                aes_storage_name TEXT NOT NULL UNIQUE,
                des_storage_name TEXT NOT NULL UNIQUE,
                rc4_storage_name TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (owner_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_medical_files_owner
                ON medical_files(owner_id);

            CREATE INDEX IF NOT EXISTS idx_medical_files_owner_created
                ON medical_files(owner_id, created_at);
        """)
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
            """
            SELECT id, username, password_hash
            FROM users
            WHERE username = ?
            """,
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


def save_health_profile(user_id, aes_envelope, des_envelope, rc4_envelope):
    envelopes = (aes_envelope, des_envelope, rc4_envelope)

    if not all(isinstance(envelope, bytes) for envelope in envelopes):
        raise TypeError("Semua envelope profil harus berupa bytes.")

    connection = get_connection()

    try:
        with connection:
            connection.execute(
                """
                INSERT INTO health_profiles (
                    user_id,
                    aes_envelope,
                    des_envelope,
                    rc4_envelope
                )
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    aes_envelope = excluded.aes_envelope,
                    des_envelope = excluded.des_envelope,
                    rc4_envelope = excluded.rc4_envelope,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (user_id, aes_envelope, des_envelope, rc4_envelope),
            )
    finally:
        connection.close()


def get_health_profile_envelopes(user_id):
    connection = get_connection()

    try:
        return connection.execute(
            """
            SELECT aes_envelope, des_envelope, rc4_envelope, updated_at
            FROM health_profiles
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()
    finally:
        connection.close()


def create_medical_file(
    file_id,
    owner_id,
    category,
    aes_storage_name,
    des_storage_name,
    rc4_storage_name,
):
    if category not in {"identity", "document", "video"}:
        raise ValueError("Kategori berkas tidak valid.")

    storage_names = (
        aes_storage_name,
        des_storage_name,
        rc4_storage_name,
    )

    if not all(
        isinstance(name, str) and name.strip()
        for name in storage_names
    ):
        raise ValueError("Nama penyimpanan berkas tidak valid.")

    if len(set(storage_names)) != 3:
        raise ValueError("Setiap cipher harus memiliki nama file berbeda.")

    connection = get_connection()

    try:
        with connection:
            connection.execute(
                """
                INSERT INTO medical_files (
                    id,
                    owner_id,
                    category,
                    aes_storage_name,
                    des_storage_name,
                    rc4_storage_name
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    file_id,
                    owner_id,
                    category,
                    aes_storage_name,
                    des_storage_name,
                    rc4_storage_name,
                ),
            )
    finally:
        connection.close()


def get_medical_file(file_id, owner_id):
    connection = get_connection()

    try:
        return connection.execute(
            """
            SELECT
                id,
                owner_id,
                category,
                aes_storage_name,
                des_storage_name,
                rc4_storage_name,
                created_at
            FROM medical_files
            WHERE id = ? AND owner_id = ?
            """,
            (file_id, owner_id),
        ).fetchone()
    finally:
        connection.close()


def get_medical_files_for_owner(owner_id):
    connection = get_connection()

    try:
        return connection.execute(
            """
            SELECT
                id,
                category,
                created_at
            FROM medical_files
            WHERE owner_id = ?
            ORDER BY created_at DESC, id DESC
            """,
            (owner_id,),
        ).fetchall()
    finally:
        connection.close()


def delete_medical_file_record(file_id, owner_id):
    connection = get_connection()

    try:
        with connection:
            cursor = connection.execute(
                """
                DELETE FROM medical_files
                WHERE id = ? AND owner_id = ?
                """,
                (file_id, owner_id),
            )
            return cursor.rowcount == 1
    finally:
        connection.close()


if __name__ == "__main__":
    init_db()
    print(f"Database siap: {DB_PATH}")
