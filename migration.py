import sqlite3
from pathlib import Path

from database import Vault


def migrate_user(
    db_path,
    master_password,
    transfer_and_verify,
    confirmation
):
    """
    Transfers vault data to another destination.
    The local database is deleted only after successful verification.
    """

    # Make sure the user has confirmed the migration.
    if confirmation != "DELETE MY LOCAL VAULT":
        raise ValueError("Migration was not confirmed")

    # Check that the transfer function is valid.
    if not callable(transfer_and_verify):
        raise TypeError("A valid transfer function is required")

    # Get the absolute path of the database.
    db_path = Path(db_path).expanduser().resolve()

    # Check whether the database file exists.
    if not db_path.is_file():
        raise FileNotFoundError("Vault database not found")

    # Unlock the local vault using the master password.
    vault = Vault.unlock(db_path, master_password)

    try:
        # Read and decrypt all saved entries.
        records = vault.get_entries()

        # Transfer the records and verify the destination.
        result = transfer_and_verify(records)

        # Continue only if verification returns True.
        if result is not True:
            raise RuntimeError("Destination verification failed")

    finally:
        # Close the database connection.
        vault.close()

    # Delete the local database and its possible temporary files.
    related_files = [
        db_path,
        Path(str(db_path) + "-journal"),
        Path(str(db_path) + "-wal"),
        Path(str(db_path) + "-shm")
    ]

    for file_path in related_files:
        if file_path.exists():
            file_path.unlink()

    return True
