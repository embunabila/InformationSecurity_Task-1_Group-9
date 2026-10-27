import hashlib
import hmac
import unittest
from unittest.mock import patch

from Crypto.Cipher import ARC4
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

from crypto_core import (
    InvalidEnvelopeError,
    decrypt_blob,
    encrypt_blob,
)


class RC4Tests(unittest.TestCase):

    def setUp(self):
        # Hanya untuk tes.
        self.master_key = b"K" * 32
        self.context = {
            "owner_id": 7,
            "kind": "profile",
            "item_id": "profile",
        }

    def encrypt(self, data):
        return encrypt_blob(
            data, self.master_key, "RC4", self.context
        )

    def decrypt(self, envelope):
        return decrypt_blob(
            envelope, self.master_key, "RC4", self.context
        )

    def test_round_trip_binary_data(self):
        for size in (0, 1, 7, 8, 15, 16, 17, 32, 255):
            data = bytes(range(size))

            with self.subTest(size=size):
                self.assertEqual(self.decrypt(self.encrypt(data)), data)

    def test_envelope_layout_without_iv_or_padding(self):
        for size in (0, 1, 8, 16, 17):
            with self.subTest(size=size):
                envelope = self.encrypt(b"A" * size)

                self.assertEqual(envelope[:4], b"MDMO")
                self.assertEqual(envelope[4], 1)
                self.assertEqual(envelope[5], 3)
                self.assertEqual(len(envelope[6:22]), 16)
                self.assertEqual(
                    int.from_bytes(envelope[22:26], "big"),
                    size,
                )
                self.assertEqual(len(envelope[26:-32]), size)
                self.assertEqual(len(envelope[-32:]), 32)
                self.assertEqual(len(envelope), 26 + size + 32)

    def test_matches_reference_rc4_and_hmac(self):
        data = b"hasil lab medimo"
        salt = b"S" * 16

        encryption_key = HKDF(
            self.master_key,
            32,
            salt,
            SHA256,
            context=b"medimo:v1:rc4:enc",
        )
        mac_key = HKDF(
            self.master_key,
            32,
            salt,
            SHA256,
            context=b"medimo:v1:rc4:mac",
        )

        ciphertext = ARC4.new(encryption_key).encrypt(data)

        header = (
            b"MDMO"
            + b"\x01\x03"
            + salt
            + len(ciphertext).to_bytes(4, "big")
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

        expected = header + ciphertext + tag

        with patch(
            "crypto_core.get_random_bytes",
            return_value=salt,
        ):
            actual = self.encrypt(data)

        self.assertEqual(actual, expected)
        self.assertEqual(self.decrypt(expected), data)

    def test_rejects_modified_envelope(self):
        envelope = self.encrypt(b"data uji RC4")
        positions = {
            "magic": 0,
            "version": 4,
            "algorithm_id": 5,
            "salt": 6,
            "length": 25,
            "ciphertext": 26,
            "tag": len(envelope) - 1,
        }

        for component, position in positions.items():
            changed = bytearray(envelope)
            changed[position] ^= 0x01

            with self.subTest(component=component):
                with self.assertRaises(InvalidEnvelopeError):
                    self.decrypt(bytes(changed))

    def test_invalid_hmac_stops_before_rc4_decryption(self):
        envelope = self.encrypt(b"data uji RC4")
        changed = bytearray(envelope)
        changed[-1] ^= 0x01

        with patch("crypto_core.ARC4.new") as rc4_new:
            with self.assertRaises(InvalidEnvelopeError):
                self.decrypt(bytes(changed))

            rc4_new.assert_not_called()

    def test_rejects_wrong_key_context_and_algorithm(self):
        envelope = self.encrypt(b"data uji RC4")
        other_context = dict(self.context, owner_id=8)

        cases = (
            (b"X" * 32, "RC4", self.context),
            (self.master_key, "RC4", other_context),
            (self.master_key, "AES", self.context),
            (self.master_key, "DES", self.context),
        )

        for key, algorithm, context in cases:
            with self.subTest(algorithm=algorithm, context=context):
                with self.assertRaises(InvalidEnvelopeError):
                    decrypt_blob(envelope, key, algorithm, context)

    def test_rejects_truncated_or_extra_bytes(self):
        envelope = self.encrypt(b"data uji RC4")

        for cut in (0, 4, 6, 22, 26, len(envelope) - 1):
            with self.subTest(cut=cut):
                with self.assertRaises(InvalidEnvelopeError):
                    self.decrypt(envelope[:cut])

        with self.assertRaises(InvalidEnvelopeError):
            self.decrypt(envelope + b"\x00")

    def test_repeated_encryption_uses_fresh_salt(self):
        data = b"data yang sama"

        first = self.encrypt(data)
        second = self.encrypt(data)

        self.assertNotEqual(first[6:22], second[6:22])
        self.assertNotEqual(first, second)
        self.assertEqual(self.decrypt(first), data)
        self.assertEqual(self.decrypt(second), data)

    def test_rejects_old_json_envelope(self):
        old_envelope = (
            b'{"algorithm":"RC4","salt":"AAAA",'
            b'"ciphertext":"AAAA","name":"lab.pdf"}'
        )

        with self.assertRaises(InvalidEnvelopeError):
            self.decrypt(old_envelope)


if __name__ == "__main__":
    unittest.main()