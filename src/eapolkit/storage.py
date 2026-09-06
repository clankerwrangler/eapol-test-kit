"""Private SQLite object storage and installation-key encryption."""
from __future__ import annotations

import json
from contextlib import contextmanager
import os
import sqlite3
import stat
import threading
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


class Store:
    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.directory.is_symlink():
            raise RuntimeError("Data directory must not be a symlink")
        os.chmod(self.directory, 0o700)
        database = self.directory / "eapolkit.sqlite3"
        existed = database.exists()
        if database.is_symlink():
            raise RuntimeError("Database must not be a symlink")
        secrets = self.directory / "secrets"
        secrets.mkdir(mode=0o700, exist_ok=True)
        if secrets.is_symlink():
            raise RuntimeError("Secrets directory must not be a symlink")
        os.chmod(secrets, 0o700)
        key_path = secrets / "master.key"
        if key_path.is_symlink():
            raise RuntimeError("Master key must not be a symlink")
        if not key_path.exists():
            if existed:
                raise RuntimeError("Master key is missing for an existing database; restore the original key")
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(Fernet.generate_key())
                output.flush()
                os.fsync(output.fileno())
        if not stat.S_ISREG(key_path.stat().st_mode):
            raise RuntimeError("Master key must be a regular file")
        os.chmod(key_path, 0o600)
        try:
            self._cipher = Fernet(key_path.read_bytes())
        except (ValueError, TypeError):
            raise RuntimeError("Invalid installation master key") from None
        self._lock = threading.RLock()
        # Create the database privately before SQLite can create it with a broader mode.
        fd = os.open(database, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        os.chmod(database, 0o600)
        self._db = sqlite3.connect(database, check_same_thread=False)
        with self._db:
            self._db.execute("PRAGMA journal_mode=DELETE")
            self._db.execute("PRAGMA secure_delete=ON")
            self._db.execute("CREATE TABLE IF NOT EXISTS objects (kind TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (kind,id))")
            self._db.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        verifier = self.setting("key_verifier")
        if verifier is not None:
            try:
                if self.decrypt(verifier) != b"eapolkit-key-verifier-v1":
                    raise ValueError
            except (ValueError, InvalidToken):
                self._db.close()
                raise RuntimeError("Installation master key does not match this database") from None
        else:
            self.set_setting("key_verifier", self.encrypt(b"eapolkit-key-verifier-v1"))

    @contextmanager
    def transaction(self):
        """Serialize a compound object update with other store operations."""
        with self._lock, self._db:
            yield self

    def encrypt(self, value: bytes | str) -> str:
        if isinstance(value, str):
            value = value.encode("utf-8")
        return self._cipher.encrypt(value).decode("ascii")

    def decrypt(self, value: str) -> bytes:
        return self._cipher.decrypt(value.encode("ascii"))

    def get(self, kind: str, object_id: str) -> dict:
        with self._lock:
            row = self._db.execute("SELECT data FROM objects WHERE kind=? AND id=?", (kind, object_id)).fetchone()
        if row is None:
            raise KeyError(object_id)
        return json.loads(row[0])

    def list(self, kind: str) -> list[dict]:
        with self._lock:
            rows = self._db.execute("SELECT data FROM objects WHERE kind=? ORDER BY rowid DESC", (kind,)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def put(self, kind: str, record: dict) -> dict:
        with self._lock, self._db:
            self._db.execute("INSERT INTO objects(kind,id,data) VALUES (?,?,?) ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data", (kind, record["id"], json.dumps(record, ensure_ascii=True)))
        return record

    def delete(self, kind: str, object_id: str) -> None:
        with self._lock, self._db:
            changed = self._db.execute("DELETE FROM objects WHERE kind=? AND id=?", (kind, object_id)).rowcount
        if not changed:
            raise KeyError(object_id)

    def setting(self, key: str) -> str | None:
        with self._lock:
            row = self._db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def set_setting(self, key: str, value: str) -> None:
        with self._lock, self._db:
            self._db.execute("INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def set_setting_if_missing(self, key: str, value: str) -> bool:
        with self._lock, self._db:
            changed = self._db.execute("INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT(key) DO NOTHING", (key, value)).rowcount
        return changed == 1

    def close(self) -> None:
        with self._lock:
            self._db.close()


def public(record: dict) -> dict:
    return {key: value for key, value in record.items() if not key.startswith("_")}
