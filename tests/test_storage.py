from safe_assertions import require

import os
from pathlib import Path
import secrets
import stat

import pytest

from eapolkit.storage import Store


def test_private_storage_and_key_recovery_invariant(tmp_path):
    os.chmod(tmp_path, 0o700)
    directory = tmp_path / "data"
    store = Store(directory)
    secret = secrets.token_urlsafe(32)
    token = store.encrypt(secret)
    store.put("target", {"id": "test", "_secret": token})
    matched = store.decrypt(token).decode() == secret
    require(matched)
    database = directory / "eapolkit.sqlite3"
    absent = secret.encode() not in database.read_bytes()
    require(absent, "A reusable secret reached plaintext storage")
    for path in (directory, directory / "secrets"):
        require(stat.S_IMODE(path.stat().st_mode) == 0o700)
    for path in (database, directory / "secrets/master.key"):
        require(stat.S_IMODE(path.stat().st_mode) == 0o600)
    store.close()
    key = directory / "secrets/master.key"
    original = key.read_bytes()
    key.unlink()
    with pytest.raises(RuntimeError, match="missing"):
        Store(directory)
    require(not key.exists())
    fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(original)
    recovered = Store(directory)
    valid = recovered.decrypt(recovered.get("target", "test")["_secret"]).decode() == secret
    require(valid)
    recovered.close()


def test_wrong_master_key_fails_without_replacement(tmp_path):
    from cryptography.fernet import Fernet
    os.chmod(tmp_path, 0o700)
    directory = tmp_path / "data"
    Store(directory).close()
    key = directory / "secrets/master.key"
    replacement = Fernet.generate_key()
    key.write_bytes(replacement)
    with pytest.raises(RuntimeError, match="does not match"):
        Store(directory)
    unchanged = key.read_bytes() == replacement
    require(unchanged)
