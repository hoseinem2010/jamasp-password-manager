
import os
import json
import sqlite3
import secrets

from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
import base64


class Vault:
    """Encrypted local password database."""

    def __init__(self, connection, key):
        self.connection = connection
        self.cipher = Fernet(key)

    @staticmethod
    def _derive_key(master_password, salt):
        # Derive an encryption key with Argon2id
        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=3,
            lanes=4,
            memory_cost=65536
        )

        raw_key = kdf.derive(master_password.encode("utf-8"))
        return base64.urlsafe_b64encode(raw_key)

    @staticmethod
    def _connect(db_path):
        path = Path(db_path).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)

        # Restrict the data directory on Unix-like systems
        if os.name == "posix":
            os.chmod(path.parent, 0o700)

        connection = sqlite3.connect(path)
        connection.execute("PRAGMA secure_delete = ON")
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA temp_store = MEMORY")
        connection.execute("PRAGMA foreign_keys = ON")

        return connection, path

    @classmethod
    def create(cls, db_path, master_password):
        # Validate the master password
        if not isinstance(master_password, str) or len(master_password) < 12:
            raise ValueError("Master password must be at least 12 characters")

        path = Path(db_path).expanduser().resolve()

        if path.exists():
            raise FileExistsError("Vault already exists")

        connection, path = cls._connect(path)

        try:
            salt = secrets.token_bytes(16)
            key = cls._derive_key(master_password, salt)
            cipher = Fernet(key)

            connection.execute("""
                CREATE TABLE metadata (
                    name TEXT PRIMARY KEY,
                    value BLOB NOT NULL
                )
            """)

            connection.execute("""
                CREATE TABLE entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    encrypted_data BLOB NOT NULL
                )
            """)

            check_token = cipher.encrypt(b"jamasp-vault-check-v1")

            connection.executemany(
                "INSERT INTO metadata (name, value) VALUES (?, ?)",
                [
                    ("salt", salt),
                    ("check_token", check_token),
                    ("version", b"1")
                ]
            )

            connection.commit()

            # Restrict database file permissions
            if os.name == "posix":
                os.chmod(path, 0o600)

            return cls(connection, key)

        except Exception:
            connection.close()

            if path.exists():
                path.unlink()

            raise

    @classmethod
    def unlock(cls, db_path, master_password):
        connection, path = cls._connect(db_path)

        try:
            rows = dict(connection.execute(
                "SELECT name, value FROM metadata"
            ).fetchall())

            salt = rows["salt"]
            check_token = rows["check_token"]

            key = cls._derive_key(master_password, salt)
            cipher = Fernet(key)

            # Check the master password
            check_value = cipher.decrypt(check_token)

            if check_value != b"jamasp-vault-check-v1":
                raise ValueError("Invalid master password")

            return cls(connection, key)

        except (InvalidToken, KeyError, sqlite3.Error, ValueError) as error:
            connection.close()
            raise ValueError("Cannot unlock vault") from error

    def add_entry(self, service, username, password, notes=""):
        # Prepare the record
        record = {
            "service": service,
            "username": username,
            "password": password,
            "notes": notes
        }

        plain_data = json.dumps(
            record,
            ensure_ascii=False
        ).encode("utf-8")

        # Encrypt the complete record
        encrypted_data = self.cipher.encrypt(plain_data)

        self.connection.execute(
            "INSERT INTO entries (encrypted_data) VALUES (?)",
            (encrypted_data,)
        )

        self.connection.commit()

    def get_entries(self):
        rows = self.connection.execute(
            "SELECT id, encrypted_data FROM entries"
        ).fetchall()

        records = []

        for entry_id, encrypted_data in rows:
            plain_data = self.cipher.decrypt(encrypted_data)
            record = json.loads(plain_data.decode("utf-8"))

            records.append({
                "id": entry_id,
                **record
            })

        return records

    def delete_entry(self, entry_id):
        self.connection.execute(
            "DELETE FROM entries WHERE id = ?",
            (entry_id,)
        )
        self.connection.commit()

    def close(self):
        self.connection.close()
