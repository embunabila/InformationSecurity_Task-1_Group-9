import unittest

from crypto_core import (
    MAX_PAYLOAD_SIZE,
    InvalidEnvelopeError,
    decrypt_blob,
    encrypt_blob,
)


class CryptoIntegrationTests(unittest.TestCase):

    def setUp(self):
        self.master_key = b"K" * 32

        self.profile_context = {
            "owner_id": 7,
            "kind": "profile",
            "item_id": "profile",
        }

        self.file_context = {
            "owner_id": 7,
            "kind": "file",
            "item_id": "550e8400-e29b-41d4-a716-446655440000",
        }

    def test_three_algorithms_restore_the_same_dummy_data(self):
        data = b"Medimo dummy\x00\xff\x80" + bytes(range(256))

        envelopes = {}

        for algorithm in ("AES", "DES", "RC4"):
            with self.subTest(algorithm=algorithm):
                envelope = encrypt_blob(
                    data,
                    self.master_key,
                    algorithm,
                    self.profile_context,
                )

                restored = decrypt_blob(
                    envelope,
                    self.master_key,
                    algorithm,
                    self.profile_context,
                )

                self.assertEqual(restored, data)
                envelopes[algorithm] = envelope

        self.assertEqual(len(set(envelopes.values())), 3)

    def test_des_and_rc4_payload_size_boundary(self):
        data = b"A" * MAX_PAYLOAD_SIZE

        expected_ciphertext_lengths = {
            "DES": 8 * (MAX_PAYLOAD_SIZE // 8 + 1),

            "RC4": MAX_PAYLOAD_SIZE,
        }

        expected_header_lengths = {
            "DES": 34,  
            "RC4": 26,  
        }

        for algorithm in ("DES", "RC4"):
            with self.subTest(algorithm=algorithm):
                envelope = encrypt_blob(
                    data,
                    self.master_key,
                    algorithm,
                    self.profile_context,
                )

                declared_length = int.from_bytes(
                    envelope[22:26], "big"
                )

                self.assertEqual(
                    declared_length,
                    expected_ciphertext_lengths[algorithm],
                )

                self.assertEqual(
                    len(envelope),
                    expected_header_lengths[algorithm]
                    + expected_ciphertext_lengths[algorithm]
                    + 32,  
                )

                restored = decrypt_blob(
                    envelope,
                    self.master_key,
                    algorithm,
                    self.profile_context,
                )

                self.assertEqual(restored, data)

                with self.assertRaises(ValueError):
                    encrypt_blob(
                        data + b"A",
                        self.master_key,
                        algorithm,
                        self.profile_context,
                    )

    def test_file_envelope_rejects_other_owner_or_item(self):
        data = b"isi berkas dummy"

        other_owner = dict(self.file_context, owner_id=8)
        other_item = dict(
            self.file_context,
            item_id="550e8400-e29b-41d4-a716-446655440001",
        )

        for algorithm in ("AES", "DES", "RC4"):
            envelope = encrypt_blob(
                data,
                self.master_key,
                algorithm,
                self.file_context,
            )

            for wrong_context in (other_owner, other_item):
                with self.subTest(
                    algorithm=algorithm,
                    wrong_context=wrong_context,
                ):
                    with self.assertRaises(InvalidEnvelopeError):
                        decrypt_blob(
                            envelope,
                            self.master_key,
                            algorithm,
                            wrong_context,
                        )

    def test_des_rejects_invalid_declared_ciphertext_lengths(self):
        envelope = encrypt_blob(
            b"A" * 16,
            self.master_key,
            "DES",
            self.profile_context,
        )

        for invalid_length in (0, 1, 7, 9, 15):
            changed = (
                envelope[:22]
                + invalid_length.to_bytes(4, "big")
                + envelope[26:]
            )

            with self.subTest(length=invalid_length):
                with self.assertRaises(InvalidEnvelopeError):
                    decrypt_blob(
                        changed,
                        self.master_key,
                        "DES",
                        self.profile_context,
                    )


if __name__ == "__main__":
    unittest.main()