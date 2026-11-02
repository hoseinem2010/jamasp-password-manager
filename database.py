
import sqlite3
import json
from pathlib import Path

import utils


class Vault:
    """Manages the local SQLite password database."""

    CHECK_VALUE = "jamasp-vault-check-v1"

    def __init__(self, connection, key):
        self.connection = connection
        self.key = key

    @staticmethod
    def _connect(db_path):
        path = Path(db_path).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)

        connection = sqlite3.connect(path)

        connection.execute("PRAGMA secure_delete = ON")
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA temp_store = MEMORY")
        connection.execute("PRAGMA foreign_keys = ON")

        return connection, path

    @classmethod
    def create(cls, db_path, master_password):
        if not isinstance(master_password, str) or len(master_password) < 12:
            raise ValueError("Master password must be at least 12 characters")

        path = Path(db_path).expanduser().resolve()

        if path.exists():
            raise FileExistsError("Vault already exists")

        connection, path = cls._connect(path)

        try:
            # Use the existing functions from utils.py
            salt = utils.salt()
            key = utils.encryption_key(master_password, salt)

            # Create database tables
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

            # Encrypt a verification value
            check_token = utils.password_encryption(
                key,
                cls.CHECK_VALUE
            )

            # Save database metadata
            connection.executemany(
                "INSERT INTO metadata (name, value) VALUES (?, ?)",
                [
                    ("salt", salt),
                    ("check_token", check_token),
                    ("version", b"1")
                ]
            )

            connection.commit()

            return cls(connection, key)

        except Exception:
            connection.close()

            if path.exists():
                path.unlink()

            raise

    @classmethod
    def unlock(cls, db_path, master_password):
        path = Path(db_path).expanduser().resolve()

        if not path.is_file():
            raise FileNotFoundError("Vault database not found")

        connection, path = cls._connect(path)

        try:
            rows = dict(
                connection.execute(
                    "SELECT name, value FROM metadata"
                ).fetchall()
            )

            salt = rows["salt"]
            check_token = rows["check_token"]

            # Recreate the same encryption key
            key = utils.encryption_key(master_password, salt)

            # Verify the master password
            check_value = utils.Decoding(key, check_token)

            if check_value != cls.CHECK_VALUE:
                raise ValueError("Invalid master password")

            return cls(connection, key)

        except Exception as error:
            connection.close()
            raise ValueError("Cannot unlock vault") from error

    def add_entry(self, service, username, password, notes=""):
        record = {
            "service": service,
            "username": username,
            "password": password,
            "notes": notes
        }

        # Convert the record to JSON
        plain_data = json.dumps(
            record,
            ensure_ascii=False
        )

        # Use the existing encryption function
        encrypted_data = utils.password_encryption(
            self.key,
            plain_data
        )

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
            # Use the existing decryption function
            plain_data = utils.Decoding(
                self.key,
                encrypted_data
            )

            record = json.loads(plain_data)

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
