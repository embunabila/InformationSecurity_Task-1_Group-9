import hashlib
import hmac
import unittest
from unittest.mock import patch

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.Padding import pad

from crypto_core import (
    CryptoConfigError,
    InvalidEnvelopeError,
    decrypt_blob,
    encrypt_blob,
)


# Nilai berdasarkan kontrak Medimo
MAX_PAYLOAD = 25 * 1024 * 1024 + 16 * 1024 + 4
MAX_AES_CIPHERTEXT = 16 * (MAX_PAYLOAD // 16 + 1)
MAX_AES_ENVELOPE = 42 + MAX_AES_CIPHERTEXT + 32


class AESTests(unittest.TestCase):

    def setUp(self):
        self.master_key = b"K" * 32
        self.context = {
            "owner_id": 7,
            "kind": "profile",
            "item_id": "profile",
        }
        self.file_context = {
            "owner_id": 7,
            "kind": "file",
            "item_id": "550e8400-e29b-41d4-a716-446655440000",
        }

    def encrypt(self, data, context=None):
        if context is None:
            context = self.context

        return encrypt_blob(data, self.master_key, "AES", context)

    def decrypt(self, envelope, context=None):
        if context is None:
            context = self.context

        return decrypt_blob(
            envelope, self.master_key, "AES", context
        )

    def assert_exact_error(self, error_type, function, *args):
        with self.assertRaises(error_type) as caught:
            function(*args)

        # Custom error juga subclass ValueError.
        # Pemeriksaan ini memastikan jenis error benar-benar sesuai.
        self.assertIs(type(caught.exception), error_type)

    def reference_envelope(self, padded_data):
        """Paket pembanding untuk self.context, tanpa helper crypto_core."""
        salt = b"S" * 16
        iv = b"I" * 16

        encryption_key = HKDF(
            self.master_key,
            32,
            salt,
            SHA256,
            context=b"medimo:v1:aes:enc",
        )
        mac_key = HKDF(
            self.master_key,
            32,
            salt,
            SHA256,
            context=b"medimo:v1:aes:mac",
        )

        ciphertext = AES.new(
            encryption_key, AES.MODE_CBC, iv=iv
        ).encrypt(padded_data)

        header = (
            b"MDMO"
            + b"\x01\x01"
            + salt
            + len(ciphertext).to_bytes(4, "big")
            + iv
        )

        context_bytes = (
            b'{"item_id":"profile","kind":"profile","owner_id":7}'
        )
        authenticated_data = (
            header
            + len(context_bytes).to_bytes(4, "big")
            + context_bytes
            + ciphertext
        )

        # Gunakan HMAC standard library sebagai pembanding
        tag = hmac.new(
            mac_key, authenticated_data, hashlib.sha256
        ).digest()

        return header + ciphertext + tag

    def test_round_trip_for_empty_binary_and_block_boundaries(self):
        payloads = [
            b"",
            b"hasil lab",
            "catatan kesehatan: suhu 37°C".encode("utf-8"),
            bytes(range(256)),
        ]
        payloads.extend(
            b"A" * size
            for size in (1, 15, 16, 17, 31, 32, 33)
        )

        for context in (self.context, self.file_context):
            for data in payloads:
                with self.subTest(kind=context["kind"], size=len(data)):
                    envelope = self.encrypt(data, context)
                    plaintext = self.decrypt(envelope, context)

                    self.assertIsInstance(envelope, bytes)
                    self.assertIsInstance(plaintext, bytes)
                    self.assertEqual(plaintext, data)

    def test_envelope_layout_and_padding_lengths(self):
        for size in (0, 1, 15, 16, 17, 32):
            with self.subTest(size=size):
                envelope = self.encrypt(b"A" * size)
                expected_ciphertext_size = 16 * (size // 16 + 1)

                self.assertEqual(envelope[:4], b"MDMO")
                self.assertEqual(envelope[4], 1)
                self.assertEqual(envelope[5], 1)
                self.assertEqual(len(envelope[6:22]), 16)
                self.assertEqual(len(envelope[26:42]), 16)

                self.assertEqual(
                    int.from_bytes(envelope[22:26], "big"),
                    expected_ciphertext_size,
                )
                self.assertEqual(
                    len(envelope[42:-32]),
                    expected_ciphertext_size,
                )
                self.assertEqual(len(envelope[-32:]), 32)
                self.assertEqual(
                    len(envelope),
                    42 + expected_ciphertext_size + 32,
                )

    def test_matches_reference_aes_cbc_pkcs7_and_hmac(self):
        data = b"hasil lab medimo"
        expected = self.reference_envelope(
            pad(data, 16, style="pkcs7")
        )

        # Tetapkan randomness hanya selama tes pembanding ini
        with patch(
            "crypto_core.get_random_bytes",
            side_effect=[b"S" * 16, b"I" * 16],
        ):
            actual = self.encrypt(data)

        self.assertEqual(actual, expected)
        self.assertEqual(self.decrypt(expected), data)

    def test_repeated_encryption_uses_fresh_salt_and_iv(self):
        data = b"data yang sama"
        first = self.encrypt(data)
        second = self.encrypt(data)

        self.assertNotEqual(first, second)
        self.assertNotEqual(first[6:22], second[6:22])
        self.assertNotEqual(first[26:42], second[26:42])
        self.assertEqual(self.decrypt(first), data)
        self.assertEqual(self.decrypt(second), data)

    def test_reordered_context_can_decrypt(self):
        envelope = self.encrypt(b"hasil lab")
        reordered = {
            "item_id": "profile",
            "owner_id": 7,
            "kind": "profile",
        }

        self.assertEqual(
            self.decrypt(envelope, reordered),
            b"hasil lab",
        )

    def test_rejects_wrong_master_key(self):
        envelope = self.encrypt(b"hasil lab")

        self.assert_exact_error(
            InvalidEnvelopeError,
            decrypt_blob,
            envelope,
            b"X" * 32,
            "AES",
            self.context,
        )

    def test_rejects_different_valid_contexts(self):
        envelope = self.encrypt(b"berkas", self.file_context)

        other_owner = dict(self.file_context, owner_id=8)
        other_item = dict(
            self.file_context,
            item_id="550e8400-e29b-41d4-a716-446655440001",
        )

        # Ketiganya valid secara bentuk, tetapi tidak cocok dengan paket
        for context in (other_owner, other_item, self.context):
            with self.subTest(context=context):
                self.assert_exact_error(
                    InvalidEnvelopeError,
                    self.decrypt,
                    envelope,
                    context,
                )

    def test_rejects_wrong_expected_algorithm(self):
        envelope = self.encrypt(b"hasil lab")

        for algorithm in ("DES", "RC4"):
            with self.subTest(algorithm=algorithm):
                self.assert_exact_error(
                    InvalidEnvelopeError,
                    decrypt_blob,
                    envelope,
                    self.master_key,
                    algorithm,
                    self.context,
                )

    def test_rejects_modified_envelope_components(self):
        envelope = self.encrypt(b"A" * 32)
        positions = {
            "magic": 0,
            "version": 4,
            "algorithm_id": 5,
            "salt": 6,
            "iv": 26,
            "ciphertext": 42,
            "tag": len(envelope) - 1,
        }

        for component, position in positions.items():
            changed = bytearray(envelope)
            changed[position] ^= 0x01

            with self.subTest(component=component):
                self.assert_exact_error(
                    InvalidEnvelopeError,
                    self.decrypt,
                    bytes(changed),
                )

    def test_rejects_truncated_or_extra_bytes(self):
        envelope = self.encrypt(b"hasil lab")

        for cut in (0, 4, 5, 6, 22, 25, 26, 41, 42, len(envelope) - 1):
            with self.subTest(cut=cut):
                self.assert_exact_error(
                    InvalidEnvelopeError,
                    self.decrypt,
                    envelope[:cut],
                )

        self.assert_exact_error(
            InvalidEnvelopeError,
            self.decrypt,
            envelope + b"\x00",
        )

    def test_rejects_invalid_declared_ciphertext_lengths(self):
        envelope = self.encrypt(b"A" * 32)

        for length in (0, 1, 15, 17, 16, 64, 2**32 - 1):
            changed = (
                envelope[:22]
                + length.to_bytes(4, "big")
                + envelope[26:]
            )

            with self.subTest(length=length):
                self.assert_exact_error(
                    InvalidEnvelopeError,
                    self.decrypt,
                    changed,
                )

    def test_rejects_unsupported_algorithm_inputs(self):
        envelope = self.encrypt(b"hasil lab")

        for algorithm in ("UNKNOWN", "aes", "", None, 1, []):
            with self.subTest(algorithm=algorithm):
                self.assert_exact_error(
                    ValueError,
                    encrypt_blob,
                    b"data",
                    self.master_key,
                    algorithm,
                    self.context,
                )
                self.assert_exact_error(
                    ValueError,
                    decrypt_blob,
                    envelope,
                    self.master_key,
                    algorithm,
                    self.context,
                )

    def test_rejects_invalid_master_key_inputs(self):
        envelope = self.encrypt(b"hasil lab")
        invalid_keys = (
            None, "K" * 32, b"", b"K" * 31,
            b"K" * 33, bytearray(32),
        )

        for key in invalid_keys:
            with self.subTest(key_type=type(key).__name__, key=key):
                self.assert_exact_error(
                    CryptoConfigError,
                    encrypt_blob,
                    b"data",
                    key,
                    "AES",
                    self.context,
                )
                self.assert_exact_error(
                    CryptoConfigError,
                    decrypt_blob,
                    envelope,
                    key,
                    "AES",
                    self.context,
                )

    def test_rejects_non_bytes_data(self):
        for data in ("teks", None, bytearray(b"data"), 7, []):
            with self.subTest(data_type=type(data).__name__):
                self.assert_exact_error(
                    ValueError,
                    self.encrypt,
                    data,
                )

    def test_rejects_non_bytes_envelope(self):
        envelope = self.encrypt(b"hasil lab")

        for value in ("teks", None, bytearray(envelope), 7, []):
            with self.subTest(value_type=type(value).__name__):
                self.assert_exact_error(
                    ValueError,
                    self.decrypt,
                    value,
                )

    def test_rejects_invalid_context_inputs(self):
        envelope = self.encrypt(b"hasil lab")
        contexts = (
            None,
            {},
            dict(self.context, owner_id=True),
            dict(self.context, kind="unknown"),
            dict(self.context, item_id="wrong"),
            dict(self.context, extra="unexpected"),
        )

        for context in contexts:
            with self.subTest(context=context):
                # Panggil API langsung agar None tidak diganti helper tes
                self.assert_exact_error(
                    ValueError,
                    encrypt_blob,
                    b"data",
                    self.master_key,
                    "AES",
                    context,
                )
                self.assert_exact_error(
                    ValueError,
                    decrypt_blob,
                    envelope,
                    self.master_key,
                    "AES",
                    context,
                )

    def test_invalid_hmac_stops_before_decryption_and_unpadding(self):
        envelope = self.encrypt(b"hasil lab")
        damaged = envelope[:-1] + bytes([envelope[-1] ^ 0x01])

        with patch("crypto_core.AES.new") as aes_new:
            with patch("crypto_core.unpad") as unpad_mock:
                self.assert_exact_error(
                    InvalidEnvelopeError,
                    self.decrypt,
                    damaged,
                )

                aes_new.assert_not_called()
                unpad_mock.assert_not_called()

    def test_rejects_invalid_padding_even_with_valid_hmac(self):
        # Last byte 0 tidak valid sebagai padding PKCS7
        # Helper membuat ciphertext dan HMAC yang valid untuk blok ini
        envelope = self.reference_envelope(b"\x00" * 16)

        self.assert_exact_error(
            InvalidEnvelopeError,
            self.decrypt,
            envelope,
        )

    def test_payload_size_boundary(self):
        # Tes ini benar-benar memproses payload sekitar 25 MiB
        data = b"A" * MAX_PAYLOAD
        envelope = self.encrypt(data)

        self.assertEqual(len(envelope), MAX_AES_ENVELOPE)
        self.assertEqual(self.decrypt(envelope), data)

        self.assert_exact_error(
            ValueError,
            self.encrypt,
            data + b"A",
        )

    def test_rechecks_plaintext_size_after_decryption(self):
        envelope = self.encrypt(b"ABCD")

        # Simulasikan batas 3 byte untuk menguji pemeriksaan setelah unpad
        with patch("crypto_core.MAX_PAYLOAD_SIZE", 3):
            self.assert_exact_error(
                InvalidEnvelopeError,
                self.decrypt,
                envelope,
            )

    def test_rejects_envelope_above_maximum_size(self):
        oversized = b"\x00" * (MAX_AES_ENVELOPE + 1)

        self.assert_exact_error(
            InvalidEnvelopeError,
            self.decrypt,
            oversized,
        )

    def test_rejects_old_json_envelope(self):
        old_envelope = (
            b'{"algorithm":"AES","salt":"AAAA",'
            b'"iv":"AAAA","ciphertext":"AAAA","name":"lab.pdf"}'
        )

        self.assert_exact_error(
            InvalidEnvelopeError,
            self.decrypt,
            old_envelope,
        )


if __name__ == "__main__":
    unittest.main()