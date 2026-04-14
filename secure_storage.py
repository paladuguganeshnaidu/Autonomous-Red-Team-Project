import os

from cryptography.fernet import Fernet

import config


def _get_master_key():
    key = os.environ.get(config.MASTER_KEY_ENV, "").strip()
    if not key:
        raise RuntimeError(f"Missing master key. Set {config.MASTER_KEY_ENV}.")
    return key.encode("utf-8")


def encrypt_file(path, delete_original=False):
    if not os.path.exists(path):
        return ""
    key = _get_master_key()
    fernet = Fernet(key)
    with open(path, "rb") as fh:
        data = fh.read()
    encrypted = fernet.encrypt(data)
    out_path = f"{path}.enc"
    with open(out_path, "wb") as fh:
        fh.write(encrypted)
    if delete_original:
        os.remove(path)
    return out_path
