import unittest

from crypto_core import (
    ALGORITHMS,
    CryptoConfigError,
    _validate_master_key,
    _derive_keys,
    _encode_context,
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

class ContextTests(unittest.TestCase):

    def setUp(self):
        self.profile_context = {
            "owner_id": 7,
            "kind": "profile",
            "item_id": "profile",
        }
        self.file_id = "550e8400-e29b-41d4-a716-446655440000"
        self.file_context = {
            "owner_id": 7,
            "kind": "file",
            "item_id": self.file_id,
        }

    def assert_invalid_context(self, context):
        with self.assertRaises(ValueError) as caught:
            _encode_context(context)

        self.assertIs(type(caught.exception), ValueError)

    def test_profile_encoding_matches_expected_bytes(self):
        expected = (
            b'{"item_id":"profile","kind":"profile","owner_id":7}'
        )

        self.assertEqual(_encode_context(self.profile_context), expected)

    def test_file_encoding_matches_expected_bytes(self):
        expected = (
            b'{"item_id":"550e8400-e29b-41d4-a716-446655440000",'
            b'"kind":"file","owner_id":7}'
        )

        self.assertEqual(_encode_context(self.file_context), expected)

    def test_dictionary_order_does_not_change_encoding(self):
        reordered = {
            "item_id": "profile",
            "owner_id": 7,
            "kind": "profile",
        }

        self.assertEqual(
            _encode_context(self.profile_context),
            _encode_context(reordered),
        )

    def test_rejects_non_dictionary_context(self):
        for context in (None, "", b"", [], 7):
            with self.subTest(context=context):
                self.assert_invalid_context(context)

    def test_rejects_missing_or_extra_fields(self):
        for field in ("owner_id", "kind", "item_id"):
            context = self.profile_context.copy()
            del context[field]

            with self.subTest(missing_field=field):
                self.assert_invalid_context(context)

        context = self.profile_context.copy()
        context["extra"] = "unexpected"
        self.assert_invalid_context(context)

    def test_rejects_invalid_owner_id(self):
        for owner_id in (True, False, 0, -1, 7.0, "7", None, []):
            context = self.profile_context.copy()
            context["owner_id"] = owner_id

            with self.subTest(owner_id=owner_id):
                self.assert_invalid_context(context)

    def test_rejects_invalid_kind(self):
        for kind in ("PROFILE", "document", "", None, 7, []):
            context = self.profile_context.copy()
            context["kind"] = kind

            with self.subTest(kind=kind):
                self.assert_invalid_context(context)

    def test_rejects_invalid_profile_item_id(self):
        for item_id in ("PROFILE", "", self.file_id, None, 7, b"profile"):
            context = self.profile_context.copy()
            context["item_id"] = item_id

            with self.subTest(item_id=item_id):
                self.assert_invalid_context(context)

    def test_rejects_invalid_file_item_id(self):
        invalid_ids = (
            self.file_id.upper(),
            self.file_id.replace("-", ""),
            "{" + self.file_id + "}",
            "urn:uuid:" + self.file_id,
            " " + self.file_id,
            self.file_id + " ",
            self.file_id[:-1] + "g",
            "profile",
            "",
            None,
            7,
            self.file_id.encode("ascii"),
        )

        for item_id in invalid_ids:
            context = self.file_context.copy()
            context["item_id"] = item_id

            with self.subTest(item_id=item_id):
                self.assert_invalid_context(context)

    def test_different_valid_contexts_have_different_encodings(self):
        other_owner = self.file_context.copy()
        other_owner["owner_id"] = 8

        other_item = self.file_context.copy()
        other_item["item_id"] = "550e8400-e29b-41d4-a716-446655440001"

        original = _encode_context(self.file_context)

        for context in (other_owner, other_item, self.profile_context):
            with self.subTest(context=context):
                self.assertNotEqual(original, _encode_context(context))

if __name__ == "__main__":
    unittest.main()