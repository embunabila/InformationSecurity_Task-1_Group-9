import unittest

from crypto_core import CryptoConfigError, _validate_master_key


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


if __name__ == "__main__":
    unittest.main()