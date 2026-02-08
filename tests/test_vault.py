import os
import tempfile
import pytest

from vault_class import Vault

MASTER = "correct horse battery staple"
NEW_MASTER = "even better master password"


def make_vault():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    return Vault(db_name=path)


def test_create_and_unlock_vault():
    vault = make_vault()
    vault.unlock_or_create(MASTER)
    assert vault.key is not None
    vault.lock()


def test_wrong_master_password_fails():
    vault = make_vault()
    vault.unlock_or_create(MASTER)
    vault.lock()

    with pytest.raises(ValueError):
        vault.unlock_or_create("wrong password")


def test_add_and_get_entry():
    vault = make_vault()
    vault.unlock_or_create(MASTER)

    vault.add_entry("gmail.com", "alice", "secret123")
    entries = vault.get_entries_by_site("gmail.com")

    assert entries[0][1] == "alice"
    assert entries[0][2] == "secret123"


def test_password_not_stored_in_plaintext():
    vault = make_vault()
    vault.unlock_or_create(MASTER)

    vault.add_entry("site", "user", "plaintext")

    with open(vault.db_name, "rb") as f:
        raw = f.read()

    assert b"plaintext" not in raw


def test_delete_entry():
    vault = make_vault()
    vault.unlock_or_create(MASTER)

    vault.add_entry("site", "user", "pass")
    entry_id = vault.get_entries_by_site("site")[0][0]
    vault.delete_entry(entry_id)

    assert vault.get_entries_by_site("site") == []


def test_change_master_password_preserves_data():
    vault = make_vault()
    vault.unlock_or_create(MASTER)

    vault.add_entry("site", "user", "pass")
    vault.change_master_password(NEW_MASTER)

    vault.lock()
    vault.unlock_or_create(NEW_MASTER)

    assert vault.get_entries_by_site("site")[0][2] == "pass"


def test_export_import_roundtrip():
    vault = make_vault()
    vault.unlock_or_create(MASTER)

    vault.add_entry("github.com", "bob", "token123")

    fd, export_file = tempfile.mkstemp()
    os.close(fd)

    vault.export(export_file)

    vault.lock()
    vault.unlock_or_create(MASTER)

    entries = vault.get_entries_by_site("github.com")
    assert entries[0][2] == "token123"
