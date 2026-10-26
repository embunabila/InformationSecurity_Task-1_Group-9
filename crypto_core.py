ALGORITHMS = ("AES", "DES", "RC4")

MASTER_KEY_SIZE = 32
SALT_SIZE = 16


class CryptoConfigError(ValueError):
    pass


class InvalidEnvelopeError(ValueError):
    pass


def _validate_master_key(master_key):
    if not isinstance(master_key, bytes):
        raise CryptoConfigError("Master key harus berupa bytes.")

    if len(master_key) != MASTER_KEY_SIZE:
        raise CryptoConfigError("Master key harus sepanjang 32 byte.")