
import os


MASTER_KEY_SIZE = 32


def load_master_key():
    key_hex = os.environ.get("MASTER_KEY")

    if not key_hex:
        raise RuntimeError(
            "MASTER_KEY is not configured in the environment."
        )

    if len(key_hex) != MASTER_KEY_SIZE * 2:
        raise RuntimeError(
            "MASTER_KEY must be a 64-character hexadecimal string."
        )

    try:
        master_key = bytes.fromhex(key_hex)
    except ValueError as exc:
        raise RuntimeError(
            "MASTER_KEY must contain valid hexadecimal characters."
        ) from exc

    if len(master_key) != MASTER_KEY_SIZE:
        raise RuntimeError(
            "MASTER_KEY must decode to exactly 32 bytes."
        )

    return master_key
