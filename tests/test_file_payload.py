import unittest

from file_payload import MAX_METADATA_SIZE, pack_file_payload, unpack_file_payload


def raw_payload(metadata_bytes, data=b""):
    return len(metadata_bytes).to_bytes(4, "big") + metadata_bytes + data


class FilePayloadTests(unittest.TestCase):
    def test_unicode_metadata_and_binary_round_trip(self):
        metadata = {"filename": "hasil-é-🩺.pdf", "mime": "application/pdf", "extra": "uji"}
        data = bytes(range(256)) + b"\x00\xff"
        payload = pack_file_payload(metadata, data)
        metadata_length = int.from_bytes(payload[:4], "big")
        self.assertEqual(metadata_length, len(payload[4:4 + metadata_length]))
        self.assertIn("é".encode("utf-8"), payload[4:4 + metadata_length])
        self.assertEqual(unpack_file_payload(payload), (metadata, data))

    def test_accepts_empty_file(self):
        metadata = {"filename": "empty.txt", "mime": "text/plain"}
        self.assertEqual(unpack_file_payload(pack_file_payload(metadata, b"")), (metadata, b""))

    def test_metadata_byte_limit(self):
        metadata = {"filename": "a", "mime": "b", "extra": ""}
        base_size = len(pack_file_payload(metadata, b"")) - 4
        metadata["extra"] = "x" * (MAX_METADATA_SIZE - base_size)
        payload = pack_file_payload(metadata, b"")
        self.assertEqual(int.from_bytes(payload[:4], "big"), MAX_METADATA_SIZE)
        self.assertEqual(unpack_file_payload(payload)[0], metadata)
        metadata["extra"] += "x"
        with self.assertRaises(ValueError):
            pack_file_payload(metadata, b"")
        with self.assertRaises(ValueError):
            unpack_file_payload((MAX_METADATA_SIZE + 1).to_bytes(4, "big"))

    def test_invalid_inputs_and_required_fields(self):
        bad = [None, [], {}, {"filename": " ", "mime": "x"},
               {"filename": "a", "mime": None}, {"filename": "a", "mime": " "}]
        for metadata in bad:
            with self.subTest(metadata=metadata), self.assertRaises(ValueError):
                pack_file_payload(metadata, b"")
        with self.assertRaises(ValueError):
            pack_file_payload({"filename": "a", "mime": "b"}, "not bytes")
        with self.assertRaises(ValueError):
            unpack_file_payload("not bytes")
        with self.assertRaises(ValueError):
            pack_file_payload({"filename": "a", "mime": "b", "extra": float("nan")}, b"")

    def test_rejects_truncated_and_invalid_metadata(self):
        samples = [b"", b"\x00\x00\x00", (10).to_bytes(4, "big") + b"{}",
                   raw_payload(b"\xff"), raw_payload(b"{"), raw_payload(b"[]"),
                   raw_payload(b'{"filename":"a","filename":"b","mime":"x"}'),
                   raw_payload(b'{"filename":"a","mime":"b","extra":NaN}'),
                   raw_payload(b'{"filename":"a","mime":""}')]
        for payload in samples:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                unpack_file_payload(payload)


if __name__ == "__main__":
    unittest.main()
