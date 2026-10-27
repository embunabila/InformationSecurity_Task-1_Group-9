import unittest
from unittest.mock import patch

import hashlib
import hmac

from Crypto.Cipher import DES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.Padding import pad

from crypto_core import (
    InvalidEnvelopeError,
    decrypt_blob,
    encrypt_blob,
)


class DESTests(unittest.TestCase):

    def setUp(self):
        self.master_key = b"K" * 32

        self.context = {
            "owner_id": 7,
            "kind": "profile",
            "item_id": "profile",
        }

    def encrypt(self, data):
        return encrypt_blob(
            data,
            self.master_key,
            "DES",
            self.context,
        )

    def decrypt(self, envelope):
        return decrypt_blob(
            envelope,
            self.master_key,
            "DES",
            self.context,
        )

    def test_round_trip_for_binary_data_and_block_boundaries(self):
        for size in (0, 1, 7, 8, 9, 15, 16, 17, 32):
            data = bytes(range(size))

            with self.subTest(size=size):
                envelope = self.encrypt(data)
                result = self.decrypt(envelope)

                self.assertEqual(result, data)

    def test_envelope_layout_and_padding_lengths(self):
        for size in (0, 1, 7, 8, 9, 16):
            with self.subTest(size=size):
                envelope = self.encrypt(b"A" * size)

                expected_ciphertext_size = 8 * (size // 8 + 1)

                self.assertEqual(envelope[:4], b"MDMO")
                self.assertEqual(envelope[4], 1)  # Versi
                self.assertEqual(envelope[5], 2)  # ID DES

                salt = envelope[6:22]
                ciphertext_length = int.from_bytes(
                    envelope[22:26], "big"
                )
                iv = envelope[26:34]
                ciphertext = envelope[34:-32]
                tag = envelope[-32:]

                self.assertEqual(len(salt), 16)
                self.assertEqual(len(iv), 8)
                self.assertEqual(
                    ciphertext_length,
                    expected_ciphertext_size,
                )
                self.assertEqual(
                    len(ciphertext),
                    expected_ciphertext_size,
                )
                self.assertEqual(len(tag), 32)
                self.assertEqual(
                    len(envelope),
                    34 + expected_ciphertext_size + 32,
                )

    def test_modified_ciphertext_is_rejected(self):
        envelope = self.encrypt(b"data uji DES")
        changed = bytearray(envelope)

        changed[34] ^= 0x01

        with self.assertRaises(InvalidEnvelopeError):
            self.decrypt(bytes(changed))

    def test_modified_hmac_is_rejected(self):
        envelope = self.encrypt(b"data uji DES")
        changed = bytearray(envelope)

        changed[-1] ^= 0x01

        with self.assertRaises(InvalidEnvelopeError):
            self.decrypt(bytes(changed))

    def test_invalid_hmac_stops_before_des_decryption(self):
        envelope = self.encrypt(b"data uji DES")
        changed = bytearray(envelope)
        changed[-1] ^= 0x01

        with patch("crypto_core.DES.new") as des_new:
            with patch("crypto_core.unpad") as unpad_mock:
                with self.assertRaises(InvalidEnvelopeError):
                    self.decrypt(bytes(changed))

                des_new.assert_not_called()
                unpad_mock.assert_not_called()

    def test_matches_reference_des_cbc_pkcs7_and_hmac(self):
        data = b"hasil lab medimo"
        salt = b"S" * 16
        iv = b"I" * 8

        # Bentuk kunci pembanding langsung dari HKDF.
        encryption_key = HKDF(
            self.master_key,
            8,
            salt,
            SHA256,
            context=b"medimo:v1:des:enc",
        )

        mac_key = HKDF(
            self.master_key,
            32,
            salt,
            SHA256,
            context=b"medimo:v1:des:mac",
        )

        ciphertext = DES.new(
            encryption_key,
            DES.MODE_CBC,
            iv=iv,
        ).encrypt(pad(data, 8, style="pkcs7"))

        header = (
            b"MDMO"
            + b"\x01\x02"
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

        tag = hmac.new(
            mac_key,
            authenticated_data,
            hashlib.sha256,
        ).digest()

        expected_envelope = header + ciphertext + tag

        # Hanya untuk tes ini: salt dan IV dibuat tetap
        # supaya hasilnya bisa dibandingkan byte demi byte.
        with patch(
            "crypto_core.get_random_bytes",
            side_effect=[salt, iv],
        ):
            actual_envelope = self.encrypt(data)

        self.assertEqual(actual_envelope, expected_envelope)
        self.assertEqual(self.decrypt(expected_envelope), data)

    def test_rejects_wrong_master_key(self):
        envelope = self.encrypt(b"hasil lab")

        with self.assertRaises(InvalidEnvelopeError):
            decrypt_blob(
                envelope,
                b"X" * 32,
                "DES",
                self.context,
            )

    def test_rejects_different_valid_contexts(self):
        envelope = self.encrypt(b"hasil lab")

        other_owner = {
            "owner_id": 8,
            "kind": "profile",
            "item_id": "profile",
        }

        other_item = {
            "owner_id": 7,
            "kind": "file",
            "item_id": "550e8400-e29b-41d4-a716-446655440000",
        }

        for context in (other_owner, other_item):
            with self.subTest(context=context):
                with self.assertRaises(InvalidEnvelopeError):
                    decrypt_blob(
                        envelope,
                        self.master_key,
                        "DES",
                        context,
                    )

    def test_rejects_modified_header(self):
        envelope = self.encrypt(b"hasil lab")

        positions = {
            "magic": 0,
            "version": 4,
            "algorithm_id": 5,
            "salt": 6,
            "ciphertext_length": 25,
            "iv": 26,
        }

        for component, position in positions.items():
            changed = bytearray(envelope)
            changed[position] ^= 0x01

            with self.subTest(component=component):
                with self.assertRaises(InvalidEnvelopeError):
                    self.decrypt(bytes(changed))

    def test_rejects_truncated_or_extra_bytes(self):
        envelope = self.encrypt(b"hasil lab")

        # Potong pada beberapa bagian envelope.
        for cut in (0, 4, 6, 22, 26, 33, 34, len(envelope) - 1):
            with self.subTest(cut=cut):
                with self.assertRaises(InvalidEnvelopeError):
                    self.decrypt(envelope[:cut])

        # Tambahan byte setelah tag juga harus ditolak.
        with self.assertRaises(InvalidEnvelopeError):
            self.decrypt(envelope + b"\x00")

    def test_rejects_wrong_expected_algorithm(self):
        envelope = self.encrypt(b"hasil lab")

        for algorithm in ("AES", "RC4"):
            with self.subTest(algorithm=algorithm):
                with self.assertRaises(InvalidEnvelopeError):
                    decrypt_blob(
                        envelope,
                        self.master_key,
                        algorithm,
                        self.context,
                    )

    def test_repeated_encryption_uses_fresh_salt_and_iv(self):
        data = b"data yang sama"

        first = self.encrypt(data)
        second = self.encrypt(data)

        self.assertNotEqual(first, second)
        self.assertNotEqual(first[6:22], second[6:22])
        self.assertNotEqual(first[26:34], second[26:34])
        self.assertEqual(self.decrypt(first), data)
        self.assertEqual(self.decrypt(second), data)

    def test_rejects_old_json_envelope(self):
        old_envelope = (
            b'{"algorithm":"DES","salt":"AAAA",'
            b'"iv":"AAAA","ciphertext":"AAAA","name":"lab.pdf"}'
        )

        with self.assertRaises(InvalidEnvelopeError):
            self.decrypt(old_envelope)

if __name__ == "__main__":
    unittest.main()