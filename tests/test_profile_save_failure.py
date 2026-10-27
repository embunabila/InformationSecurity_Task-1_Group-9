
import importlib
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class ProfileSaveFailureTests(unittest.TestCase):
    def setUp(self):
        self.env_patcher = patch.dict(
            os.environ,
            {
                "SECRET_KEY": "dummy-secret-key-for-testing",
                "MASTER_KEY": "11" * 32,
            },
        )
        self.env_patcher.start()

        self.app_module = importlib.import_module("app")
        self.db_module = importlib.import_module("db")

        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test.db"

        def test_connection():
            connection = sqlite3.connect(self.test_db_path)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            return connection

        self.test_connection = test_connection

        connection = self.test_connection()
        try:
            connection.executescript(
                """
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL,
                    password_hash TEXT NOT NULL
                );

                CREATE TABLE health_profiles (
                    user_id INTEGER PRIMARY KEY,
                    aes_envelope BLOB NOT NULL,
                    des_envelope BLOB NOT NULL,
                    rc4_envelope BLOB NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );

                INSERT INTO users (id, username, password_hash)
                VALUES (1, 'dummy_user', 'dummy_hash');
                """
            )
            connection.commit()
        finally:
            connection.close()

        self.connection_patcher = patch.object(
            self.db_module,
            "get_connection",
            self.test_connection,
        )
        self.connection_patcher.start()

        self.app_module.app.config.update(
            TESTING=True,
            SECRET_KEY="dummy-secret-key-for-testing",
        )

        self.client = self.app_module.app.test_client()

        with self.client.session_transaction() as session:
            session["user_id"] = 1
            session["csrf_token"] = "dummy-csrf-token"

    def tearDown(self):
        self.connection_patcher.stop()
        self.temp_dir.cleanup()
        self.env_patcher.stop()

    def make_profile(self, name):
        return {
            "name": name,
            "birth_date": "2000-01-01",
            "gender": "perempuan",
            "weight": None,
            "height": None,
            "phone": "08123456789",
            "emergency_contact": None,
            "allergies": None,
            "health_conditions": None,
            "routine_medication": None,
        }

    def save_profile(self, profile):
        envelopes = self.app_module.encrypt_profile(profile, 1)

        self.db_module.save_health_profile(
            1,
            envelopes["AES"],
            envelopes["DES"],
            envelopes["RC4"],
        )

        return envelopes

    def get_envelope_values(self):
        envelopes = self.db_module.get_health_profile_envelopes(1)
        self.assertIsNotNone(envelopes)

        return (
            envelopes["aes_envelope"],
            envelopes["des_envelope"],
            envelopes["rc4_envelope"],
        )

    def make_form(self):
        return {
            "csrf_token": "dummy-csrf-token",
            "name": "Nama Baru Dummy",
            "birth_date": "2000-01-01",
            "gender": "perempuan",
            "phone": "08123456789",
        }

    def test_failed_update_keeps_old_envelopes_and_shows_error(self):
        old_profile = self.make_profile("Nama Lama Dummy")
        old_envelopes = self.save_profile(old_profile)
        before = self.get_envelope_values()

        # Paksa UPDATE gagal di dalam transaksi SQLite.
        connection = self.test_connection()
        try:
            connection.execute(
                """
                CREATE TRIGGER fail_profile_update
                BEFORE UPDATE ON health_profiles
                BEGIN
                    SELECT RAISE(ABORT, 'simulated failure');
                END;
                """
            )
            connection.commit()
        finally:
            connection.close()

        with patch.object(
            self.app_module,
            "render_template",
            return_value="Halaman profil",
        ) as render_mock:
            response = self.client.post(
                "/profile",
                data=self.make_form(),
            )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            render_mock.call_args.kwargs["storage_error"]
        )
        self.assertFalse(render_mock.call_args.kwargs["valid"])

        after = self.get_envelope_values()
        self.assertEqual(after, before)

    def test_invalid_old_profile_blocks_post_and_keeps_envelopes(self):
        original_envelopes = self.save_profile(
            self.make_profile("Nama Lama Dummy")
        )

        # Rusak satu byte pada tag autentikasi, tanpa mengubah
        # panjang envelope. Ini seharusnya gagal saat verifikasi MAC.
        valid_aes = original_envelopes["AES"]
        damaged_aes = valid_aes[:-1] + bytes([valid_aes[-1] ^ 1])

        self.db_module.save_health_profile(
            1,
            damaged_aes,
            original_envelopes["DES"],
            original_envelopes["RC4"],
        )

        before = self.get_envelope_values()

        with patch.object(
            self.app_module,
            "save_health_profile",
        ) as save_mock:
            response = self.client.post(
                "/profile",
                data=self.make_form(),
            )

        # Route harus menolak POST karena profil lama tidak bisa
        # diverifikasi, dan tidak boleh menimpa envelope yang ada.
        self.assertEqual(response.status_code, 503)
        self.assertIn(
            "Data profil tidak dapat diverifikasi. Coba lagi nanti.",
            response.get_data(as_text=True),
        )
        self.assertIn(
            "no-store",
            response.headers.get("Cache-Control", ""),
        )
        save_mock.assert_not_called()

        after = self.get_envelope_values()
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
