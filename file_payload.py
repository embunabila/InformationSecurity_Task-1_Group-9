import json

MAX_METADATA_SIZE = 16 * 1024


def _validate_metadata(metadata):
    if not isinstance(metadata, dict):
        raise ValueError("Metadata harus berupa objek JSON.")
    for field in ("filename", "mime"):
        value = metadata.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} harus berupa string yang tidak kosong.")


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Metadata memiliki field duplikat.")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("Metadata mengandung nilai JSON tidak valid.")


def pack_file_payload(metadata, file_bytes):
    """Kemas metadata dan isi berkas sebagai payload bytes."""
    _validate_metadata(metadata)
    if not isinstance(file_bytes, bytes):
        raise ValueError("Isi berkas harus berupa bytes.")
    try:
        metadata_bytes = json.dumps(
            metadata, ensure_ascii=False, allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("Metadata tidak dapat dikodekan sebagai JSON UTF-8.") from exc
    if len(metadata_bytes) > MAX_METADATA_SIZE:
        raise ValueError("Metadata melebihi 16 KiB.")
    # Parse hasil serialisasi juga: kunci non-string bisa berubah menjadi
    # string dan bertabrakan, misalnya 1 dan "1".
    try:
        json.loads(metadata_bytes, object_pairs_hook=_unique_keys,
                   parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:
        raise ValueError("Metadata JSON tidak valid.") from exc
    return len(metadata_bytes).to_bytes(4, "big") + metadata_bytes + file_bytes


def unpack_file_payload(payload):
    """Kembalikan (metadata, isi berkas) dari payload bytes."""
    if not isinstance(payload, bytes):
        raise ValueError("Payload harus berupa bytes.")
    if len(payload) < 4:
        raise ValueError("Payload terpotong pada panjang metadata.")
    metadata_length = int.from_bytes(payload[:4], "big")
    if metadata_length > MAX_METADATA_SIZE:
        raise ValueError("Metadata melebihi 16 KiB.")
    end = 4 + metadata_length
    if len(payload) < end:
        raise ValueError("Payload terpotong pada metadata.")
    try:
        metadata_text = payload[4:end].decode("utf-8")
        metadata = json.loads(metadata_text, object_pairs_hook=_unique_keys,
                              parse_constant=_reject_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ValueError("Metadata JSON UTF-8 tidak valid.") from exc
    _validate_metadata(metadata)
    return metadata, payload[end:]
