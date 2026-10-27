import uuid
import re
from pathlib import Path

STORAGE_DIR = Path(__file__).resolve().parent / "storage"

_STORAGE_NAME_PATTERN = re.compile(r"[0-9a-f]{32}\.bin\Z")


def ensure_storage_dir():
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)


def get_storage_path(storage_name):
    if not isinstance(storage_name, str):
        raise ValueError("Nama file storage tidak valid.")

    if not _STORAGE_NAME_PATTERN.fullmatch(storage_name):
        raise ValueError("Nama file storage tidak valid.")

    return STORAGE_DIR / storage_name


def write_envelope(storage_name, envelope):
    if not isinstance(envelope, bytes):
        raise TypeError("Envelope harus berupa bytes.")

    path = get_storage_path(storage_name)
    ensure_storage_dir()
    created = False

    try:
        with path.open("xb") as file:
            created = True
            file.write(envelope)
    except Exception:
        if created:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        raise


def read_envelope(storage_name):
    path = get_storage_path(storage_name)
    return path.read_bytes()


def delete_envelope(storage_name):
    path = get_storage_path(storage_name)
    path.unlink(missing_ok=True)

def write_envelope_set(envelopes):
    expected_algorithms = {"AES", "DES", "RC4"}

    if not isinstance(envelopes, dict):
        raise TypeError("Envelopes harus berupa dictionary.")

    if set(envelopes) != expected_algorithms:
        raise ValueError("Harus tersedia envelope AES, DES, dan RC4.")

    storage_names = {
        algorithm: uuid.uuid4().hex + ".bin"
        for algorithm in expected_algorithms
    }

    written_names = []

    try:
        for algorithm in ("AES", "DES", "RC4"):
            storage_name = storage_names[algorithm]
            write_envelope(storage_name, envelopes[algorithm])
            written_names.append(storage_name)

        return storage_names

    except Exception:
        for storage_name in written_names:
            try:
                delete_envelope(storage_name)
            except OSError:
                pass
        raise


def delete_envelope_set(storage_names):
    expected_algorithms = {"AES", "DES", "RC4"}

    if not isinstance(storage_names, dict):
        raise TypeError("Storage names harus berupa dictionary.")

    if set(storage_names) != expected_algorithms:
        raise ValueError("Harus tersedia nama file AES, DES, dan RC4.")

    for algorithm in ("AES", "DES", "RC4"):
        delete_envelope(storage_names[algorithm])