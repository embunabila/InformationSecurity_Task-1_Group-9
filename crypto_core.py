import json
from uuid import UUID

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

ALGORITHMS = ("AES", "DES", "RC4")

MASTER_KEY_SIZE = 32
SALT_SIZE = 16


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
