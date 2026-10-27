import importlib
import io
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from crypto_core import decrypt_blob
from file_payload import unpack_file_payload


class ArchiveUploadTests(unittest.TestCase):
    def setUp(self):
        self.env_patcher = patch.dict(
            os.environ,
            {
                "SECRET_KEY": "dummy-secret-key-for-testing",
                "MASTER_KEY": "11" * 32,
            },
        )
        self.env_patcher.start()
        self.addCleanup(self.env_patcher.stop)

        self.app_module = importlib.import_module("app")
        self.db_module = importlib.import_module("db")
        self.storage_module = importlib.import_module("storage")

        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        temp_path = Path(self.temp_dir.name)
        self.db_path = temp_path / "test.db"
        self.storage_path = temp_path / "storage"

        self.db_path_patcher = patch.object(
            self.db_module,
            "DB_PATH",
            self.db_path,
        )
        self.db_path_patcher.start()
        self.addCleanup(self.db_path_patcher.stop)

        self.storage_patcher = patch.object(
            self.storage_module,
            "STORAGE_DIR",
            self.storage_path,
        )
        self.storage_patcher.start()
        self.addCleanup(self.storage_patcher.stop)

        self.db_module.init_db()

        connection = self.db_module.get_connection()
        try:
            connection.execute(
                """
                INSERT INTO users (id, username, password_hash)
                VALUES (1, 'dummy_user', 'dummy_hash')
                """
            )
            connection.commit()
        finally:
            connection.close()

        self.config_patcher = patch.dict(
            self.app_module.app.config,
            {
                "TESTING": True,
                "SECRET_KEY": "dummy-secret-key-for-testing",
            },
        )
        self.config_patcher.start()
        self.addCleanup(self.config_patcher.stop)

        self.client = self.app_module.app.test_client()

        with self.client.session_transaction() as session:
            session["user_id"] = 1
            session["csrf_token"] = "dummy-csrf-token"

    def make_upload(self, content=b"Isi file dummy"):
        return {
            "csrf_token": "dummy-csrf-token",
            "category": "document",
            "file": (
                io.BytesIO(content),
                "dummy.txt",
                "text/plain",
            ),
        }

    def test_upload_saves_three_readable_envelopes(self):
        original_content = b"Isi file dummy"

        response = self.client.post(
            "/archives/upload",
            data=self.make_upload(original_content),
        )

        self.assertEqual(response.status_code, 201)

        records = self.db_module.get_medical_files_for_owner(1)
        self.assertEqual(len(records), 1)

        record = self.db_module.get_medical_file(records[0]["id"], 1)
        self.assertIsNotNone(record)

        context = {
            "owner_id": 1,
            "kind": "file",
            "item_id": record["id"],
        }

        for algorithm, column in (
            ("AES", "aes_storage_name"),
            ("DES", "des_storage_name"),
            ("RC4", "rc4_storage_name"),
        ):
            envelope = self.storage_module.read_envelope(record[column])

            payload = decrypt_blob(
                envelope,
                self.app_module.MASTER_KEY,
                algorithm,
                context,
            )

            metadata, file_bytes = unpack_file_payload(payload)

            self.assertEqual(metadata["filename"], "dummy.txt")
            self.assertEqual(metadata["mime"], "text/plain")
            self.assertEqual(file_bytes, original_content)

        self.assertEqual(len(list(self.storage_path.iterdir())), 3)

    def test_database_failure_cleans_up_envelopes(self):
        with patch.object(
            self.app_module,
            "create_medical_file",
            side_effect=sqlite3.OperationalError("simulated failure"),
        ):
            response = self.client.post(
                "/archives/upload",
                data=self.make_upload(),
            )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            self.db_module.get_medical_files_for_owner(1),
            [],
        )
        self.assertEqual(list(self.storage_path.iterdir()), [])

    def test_invalid_csrf_does_not_save_file(self):
        data = self.make_upload()
        data["csrf_token"] = "wrong-token"

        response = self.client.post("/archives/upload", data=data)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            self.db_module.get_medical_files_for_owner(1),
            [],
        )
        self.assertFalse(self.storage_path.exists())

    def test_invalid_category_does_not_save_file(self):
        data = self.make_upload()
        data["category"] = "invalid"

        response = self.client.post("/archives/upload", data=data)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            self.db_module.get_medical_files_for_owner(1),
            [],
        )
        self.assertFalse(self.storage_path.exists())

    def upload_dummy_archive(self):
        response = self.client.post(
            "/archives/upload",
            data=self.make_upload(b"Isi file dummy"),
        )
        self.assertEqual(response.status_code, 201)

        records = self.db_module.get_medical_files_for_owner(1)
        self.assertEqual(len(records), 1)

        return self.db_module.get_medical_file(records[0]["id"], 1)

    def test_download_with_each_algorithm(self):
        record = self.upload_dummy_archive()

        for algorithm in ("AES", "DES", "RC4"):
            with self.subTest(algorithm=algorithm):
                response = self.client.get(
                    f"/archives/{record['id']}/download",
                    query_string={"algorithm": algorithm},
                )

                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.data, b"Isi file dummy")
                self.assertIn(
                    "attachment",
                    response.headers.get("Content-Disposition", ""),
                )
                self.assertIn(
                    "no-store",
                    response.headers.get("Cache-Control", ""),
                )

        # Tanpa pilihan algoritma, route memakai AES.
        response = self.client.get(
            f"/archives/{record['id']}/download"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b"Isi file dummy")

    def test_other_user_cannot_download_archive(self):
        record = self.upload_dummy_archive()

        connection = self.db_module.get_connection()
        try:
            connection.execute(
                """
                INSERT INTO users (id, username, password_hash)
                VALUES (2, 'other_user', 'dummy_hash')
                """
            )
            connection.commit()
        finally:
            connection.close()

        with self.client.session_transaction() as session:
            session["user_id"] = 2

        response = self.client.get(
            f"/archives/{record['id']}/download"
        )

        self.assertEqual(response.status_code, 404)
        self.assertNotIn(b"Isi file dummy", response.data)

    def test_modified_envelope_is_rejected(self):
        record = self.upload_dummy_archive()
        storage_path = self.storage_module.get_storage_path(
            record["aes_storage_name"]
        )

        envelope = storage_path.read_bytes()
        damaged = envelope[:-1] + bytes([envelope[-1] ^ 1])
        storage_path.write_bytes(damaged)

        response = self.client.get(
            f"/archives/{record['id']}/download",
            query_string={"algorithm": "AES"},
        )

        self.assertEqual(response.status_code, 503)
        self.assertNotIn(b"Isi file dummy", response.data)

    def test_invalid_download_algorithm_is_rejected(self):
        record = self.upload_dummy_archive()

        response = self.client.get(
            f"/archives/{record['id']}/download",
            query_string={"algorithm": "INVALID"},
        )

        self.assertEqual(response.status_code, 400)
        self.assertNotIn(b"Isi file dummy", response.data)
    
if __name__ == "__main__":
    unittest.main()