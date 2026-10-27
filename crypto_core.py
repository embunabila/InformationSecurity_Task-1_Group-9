import json
from uuid import UUID

from Crypto.Cipher import AES, ARC4, DES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

ALGORITHMS = ("AES", "DES", "RC4")

MASTER_KEY_SIZE = 32
SALT_SIZE = 16

MAGIC = b"MDMO"
FORMAT_VERSION = 1
TAG_SIZE = 32
BASE_HEADER_SIZE = 26

MAX_PAYLOAD_SIZE = 25 * 1024 * 1024 + 16 * 1024 + 4

ALGORITHM_IDS = {"AES": 1, "DES": 2, "RC4": 3}
ALGORITHM_NAMES = {1: "AES", 2: "DES", 3: "RC4"}

IV_SIZES = {"AES": 16, "DES": 8, "RC4": 0}
BLOCK_SIZES = {"AES": 16, "DES": 8, "RC4": 0}

MAX_CIPHERTEXT_SIZES = {
    "AES": 16 * (MAX_PAYLOAD_SIZE // 16 + 1),
    "DES": 8 * (MAX_PAYLOAD_SIZE // 8 + 1),
    "RC4": MAX_PAYLOAD_SIZE,
}

MAX_ENVELOPE_SIZE = 42 + MAX_CIPHERTEXT_SIZES["AES"] + TAG_SIZE


class CryptoConfigError(ValueError):
    pass


class InvalidEnvelopeError(ValueError):
    pass


def _validate_master_key(master_key):
    if not isinstance(master_key, bytes):
        raise CryptoConfigError("master key dalam bentuk bytes")

    if len(master_key) != MASTER_KEY_SIZE:
        raise CryptoConfigError("master key sepanjang 32 byte")


def _derive_keys(master_key, salt, algorithm):
    _validate_master_key(master_key)

    if not isinstance(salt, bytes):
        raise ValueError("Salt harus berupa bytes.")

    if len(salt) != SALT_SIZE:
        raise ValueError("Salt harus sepanjang 16 byte.")

    if algorithm not in ALGORITHMS:
        raise ValueError("Algoritma harus AES, DES, atau RC4.")

    if algorithm == "DES":
        encryption_key_size = 8
    else:
        encryption_key_size = 32

    encryption_label = (
        "medimo:v1:" + algorithm.lower() + ":enc"
    ).encode("ascii")

    mac_label = (
        "medimo:v1:" + algorithm.lower() + ":mac"
    ).encode("ascii")

    encryption_key = HKDF(
        master=master_key,
        key_len=encryption_key_size,
        salt=salt,
        hashmod=SHA256,
        context=encryption_label,
    )

    mac_key = HKDF(
        master=master_key,
        key_len=32,
        salt=salt,
        hashmod=SHA256,
        context=mac_label,
    )

    return encryption_key, mac_key

def _encode_context(context):
    if not isinstance(context, dict):
        raise ValueError("Context harus berupa dictionary.")

    required_fields = {"owner_id", "kind", "item_id"}

    if set(context) != required_fields:
        raise ValueError(
            "Context harus berisi tepat owner_id, kind, dan item_id."
        )

    owner_id = context["owner_id"]
    kind = context["kind"]
    item_id = context["item_id"]

    if (
        isinstance(owner_id, bool)
        or not isinstance(owner_id, int)
        or owner_id <= 0
    ):
        raise ValueError("owner_id harus integer positif, bukan boolean.")

    if not isinstance(kind, str) or kind not in ("profile", "file"):
        raise ValueError("kind harus profile atau file.")

    if not isinstance(item_id, str):
        raise ValueError("item_id harus berupa string.")

    if kind == "profile":
        if item_id != "profile":
            raise ValueError(
                "item_id untuk profil harus berupa string profile."
            )
    else:
        if len(item_id) != 36:
            raise ValueError(
                "item_id berkas harus UUID huruf kecil dengan tanda hubung."
            )

        try:
            parsed_uuid = UUID(item_id)
        except ValueError:
            raise ValueError("item_id berkas bukan UUID yang valid.") from None

        if str(parsed_uuid) != item_id:
            raise ValueError(
                "item_id berkas harus UUID huruf kecil dengan tanda hubung."
            )
            
    return json.dumps(
        context,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")

def _validate_algorithm(algorithm):
    if not isinstance(algorithm, str) or algorithm not in ALGORITHMS:
        raise ValueError("The algorithm has to be AES, DES, or RC4")


def _parse_envelope(envelope):
    if not isinstance(envelope, bytes):
        raise ValueError("Envelope harus berupa bytes")

    if not BASE_HEADER_SIZE + TAG_SIZE <= len(envelope) <= MAX_ENVELOPE_SIZE:
        raise InvalidEnvelopeError("Ukuran envelope tidak valid")

    if envelope[:4] != MAGIC or envelope[4] != FORMAT_VERSION:
        raise InvalidEnvelopeError("Format atau versi tidak dikenal")

    algorithm = ALGORITHM_NAMES.get(envelope[5])
    if algorithm is None:
        raise InvalidEnvelopeError("ID algoritma tidak dikenal")

    ciphertext_length = int.from_bytes(envelope[22:26], "big")
    if ciphertext_length > MAX_CIPHERTEXT_SIZES[algorithm]:
        raise InvalidEnvelopeError("Ciphertext terlalu besar")

    block_size = BLOCK_SIZES[algorithm]
    if block_size != 0:
        if ciphertext_length < block_size or ciphertext_length % block_size != 0:
            raise InvalidEnvelopeError("Panjang ciphertext tidak valid")

    header_size = BASE_HEADER_SIZE + IV_SIZES[algorithm]
    expected_size = header_size + ciphertext_length + TAG_SIZE

    if len(envelope) != expected_size:
        raise InvalidEnvelopeError("Panjang envelope tidak cocok")

    return {
        "algorithm": algorithm,
        "salt": envelope[6:22],
        "iv": envelope[26:header_size],
        "header": envelope[:header_size],
        "ciphertext": envelope[header_size:-TAG_SIZE],
        "tag": envelope[-TAG_SIZE:],
    }


def _make_mac(mac_key, header, context_bytes, ciphertext):
    if len(context_bytes) > 2**32 - 1:
        raise ValueError("Context terlalu besar.")

    mac = HMAC.new(mac_key, digestmod=SHA256)
    mac.update(header)
    mac.update(len(context_bytes).to_bytes(4, "big"))
    mac.update(context_bytes)
    mac.update(ciphertext)

    return mac

def encrypt_blob(data, master_key, algorithm, context):
    _validate_master_key(master_key)
    _validate_algorithm(algorithm)

    if not isinstance(data, bytes):
        raise ValueError("Data harus berupa bytes.")

    if len(data) > MAX_PAYLOAD_SIZE:
        raise ValueError("Data melebihi batas ukuran.")

    context_bytes = _encode_context(context)

    salt = get_random_bytes(SALT_SIZE)

    encryption_key, mac_key = _derive_keys(
        master_key, salt, algorithm
    )

    if algorithm == "RC4":
        iv = b""
        encryptor = ARC4.new(encryption_key)
        ciphertext = encryptor.encrypt(data)
    else:
        cipher_module = AES if algorithm == "AES" else DES
        iv = get_random_bytes(cipher_module.block_size)

        padded_data = pad(
            data,
            cipher_module.block_size,
            style="pkcs7",
        )

        encryptor = cipher_module.new(
            encryption_key,
            cipher_module.MODE_CBC,
            iv=iv,
        )
        ciphertext = encryptor.encrypt(padded_data)

    header = (
        MAGIC
        + bytes([FORMAT_VERSION, ALGORITHM_IDS[algorithm]])
        + salt
        + len(ciphertext).to_bytes(4, "big")
        + iv
    )

    tag = _make_mac(
        mac_key, header, context_bytes, ciphertext
    ).digest()

    return header + ciphertext + tag

def decrypt_blob(envelope, master_key, expected_algorithm, context):
    _validate_master_key(master_key)
    _validate_algorithm(expected_algorithm)

    context_bytes = _encode_context(context)
    parts = _parse_envelope(envelope)

    if parts["algorithm"] != expected_algorithm:
        raise InvalidEnvelopeError("Algoritma paket tidak cocok.")

    encryption_key, mac_key = _derive_keys(
        master_key,
        parts["salt"],
        parts["algorithm"],
    )

    verifier = _make_mac(
        mac_key,
        parts["header"],
        context_bytes,
        parts["ciphertext"],
    )

    try:
        verifier.verify(parts["tag"])
    except ValueError:
        raise InvalidEnvelopeError(
            "Data tidak dapat diverifikasi."
        ) from None

    try:
        if parts["algorithm"] == "RC4":
            decryptor = ARC4.new(encryption_key)
            plaintext = decryptor.decrypt(parts["ciphertext"])
        else:
            cipher_module = (
                AES if parts["algorithm"] == "AES" else DES
            )

            decryptor = cipher_module.new(
                encryption_key,
                cipher_module.MODE_CBC,
                iv=parts["iv"],
            )

            padded_plaintext = decryptor.decrypt(
                parts["ciphertext"]
            )

            plaintext = unpad(
                padded_plaintext,
                cipher_module.block_size,
                style="pkcs7",
            )
    except ValueError:
        raise InvalidEnvelopeError(
            "Data tidak dapat dibuka."
        ) from None

    if len(plaintext) > MAX_PAYLOAD_SIZE:
        raise InvalidEnvelopeError("Data melebihi batas ukuran.")

    return plaintext




