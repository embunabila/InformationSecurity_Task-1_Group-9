import unittest

from crypto_core import (
    ALGORITHMS,
    CryptoConfigError,
    _validate_master_key,
    _derive_keys,
)


class MasterKeyTests(unittest.TestCase):

    def test_accepts_32_bytes(self):
        _validate_master_key(bytes(32))

    def test_rejects_text(self):
        with self.assertRaises(CryptoConfigError):
            _validate_master_key("a" * 32)

    def test_rejects_wrong_length(self):
        with self.assertRaises(CryptoConfigError):
            _validate_master_key(b"pendek")

    def test_rejects_missing_key(self):
        with self.assertRaises(CryptoConfigError):
            _validate_master_key(None)

    def test_rejects_empty_key(self):
        with self.assertRaises(CryptoConfigError):
            _validate_master_key(b"")

    def test_rejects_31_byte_key(self):
        with self.assertRaises(CryptoConfigError):
            _validate_master_key(b"A" * 31)

    def test_rejects_33_byte_key(self):
        with self.assertRaises(CryptoConfigError):
            _validate_master_key(b"A" * 33)

    def test_rejects_bytearray_key(self):
        with self.assertRaises(CryptoConfigError):
            _validate_master_key(bytearray(32))


class KeyDerivationTests(unittest.TestCase):

    def setUp(self):
        self.master_key = b"A" * 32
        self.salt = b"B" * 16

    def test_key_lengths(self):
        expected_lengths = {
            "AES": 32,
            "DES": 8,
            "RC4": 32,
        }

        for algorithm, expected_length in expected_lengths.items():
            encryption_key, mac_key = _derive_keys(
                self.master_key, self.salt, algorithm
            )

            self.assertEqual(len(encryption_key), expected_length)
            self.assertEqual(len(mac_key), 32)

    def test_encryption_and_mac_keys_are_different(self):
        for algorithm in ALGORITHMS:
            encryption_key, mac_key = _derive_keys(
                self.master_key, self.salt, algorithm
            )

            self.assertNotEqual(encryption_key, mac_key)

    def test_same_inputs_produce_same_keys(self):
        first = _derive_keys(self.master_key, self.salt, "AES")
        second = _derive_keys(self.master_key, self.salt, "AES")

        self.assertEqual(first, second)

    def test_different_salt_produces_different_keys(self):
        first = _derive_keys(self.master_key, self.salt, "AES")
        second = _derive_keys(self.master_key, b"C" * 16, "AES")

        self.assertNotEqual(first[0], second[0])
        self.assertNotEqual(first[1], second[1])

    def test_algorithm_labels_separate_keys(self):
        aes_keys = _derive_keys(self.master_key, self.salt, "AES")
        rc4_keys = _derive_keys(self.master_key, self.salt, "RC4")

        self.assertNotEqual(aes_keys[0], rc4_keys[0])
        self.assertNotEqual(aes_keys[1], rc4_keys[1])

    def test_rejects_wrong_salt_length(self):
        with self.assertRaises(ValueError):
            _derive_keys(self.master_key, b"pendek", "AES")

    def test_rejects_text_salt(self):
        with self.assertRaises(ValueError):
            _derive_keys(self.master_key, "B" * 16, "AES")

    def test_rejects_missing_salt(self):
        with self.assertRaises(ValueError):
            _derive_keys(self.master_key, None, "AES")

    def test_rejects_unknown_algorithm(self):
        with self.assertRaises(ValueError):
            _derive_keys(self.master_key, self.salt, "UNKNOWN")

    def test_different_master_key_produces_different_keys(self):
        for algorithm in ALGORITHMS:
            first = _derive_keys(
                self.master_key, self.salt, algorithm
            )

            second = _derive_keys(
                b"C" * 32, self.salt, algorithm
            )

            self.assertNotEqual(first[0], second[0])
            self.assertNotEqual(first[1], second[1])

    def test_derivation_rejects_invalid_master_key(self):
        for algorithm in ALGORITHMS:
            with self.assertRaises(CryptoConfigError):
                _derive_keys(
                    b"pendek", self.salt, algorithm
                )


if __name__ == "__main__":
    unittest.main()