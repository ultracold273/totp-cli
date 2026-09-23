import json
import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from conftest import SECRET, URI

from totp_cli.errors import AppError
from totp_cli.store import Store, validate_alias
from totp_cli.totp import parse_enrollment


def test_accounts_roundtrip_and_metadata_never_contains_secret(store, backend):
    enrollment = parse_enrollment(URI)
    store.add("work", enrollment)
    store.add("personal", enrollment)
    reads = backend.reads
    assert [item["alias"] for item in store.list()] == ["personal", "work"]
    assert backend.reads == reads
    assert SECRET not in store.index.read_text()
    assert "otpauth" not in store.index.read_text()
    assert len({service for service, user in backend.values}) == 2
    assert Store(store.directory, store.vault).get("WORK").secret == SECRET
    store.remove("work")
    assert [item["alias"] for item in store.list()] == ["personal"]
    assert len(backend.values) == 1
    if os.name != "nt":
        assert store.index.stat().st_mode & 0o777 == 0o600


def test_fresh_list_has_no_files_or_credential_store_access(store, backend):
    assert store.list() == []
    assert not store.directory.exists()
    assert backend.reads == 0


def test_duplicate_alias_never_overwrites(store, backend):
    store.add("Work", parse_enrollment(URI))
    original = store.index.read_bytes()
    with pytest.raises(AppError, match="already exists"):
        store.add("work", parse_enrollment(URI.replace(SECRET, "MY")))
    assert store.index.read_bytes() == original
    assert list(backend.values.values()) == [SECRET]


@pytest.mark.parametrize("alias", ["../work", "-work", "a/b", "a\\b", "work account", "", "a" * 65])
def test_invalid_alias_is_rejected(alias):
    with pytest.raises(AppError):
        validate_alias(alias)


def test_unicode_and_windows_reserved_name_are_not_used_as_filenames(store):
    store.add("CON", parse_enrollment(URI))
    store.add("工作", parse_enrollment(URI))
    assert store.get("con").secret == SECRET
    assert store.get("工作").secret == SECRET


def test_failed_index_commit_rolls_back_only_new_credential(store, backend, monkeypatch):
    store.add("existing", parse_enrollment(URI))
    original = store.index.read_bytes()

    def fail_replace(*args):
        raise PermissionError

    monkeypatch.setattr("totp_cli.store.os.replace", fail_replace)
    with pytest.raises(AppError, match="Could not save the account index"):
        store.add("new", parse_enrollment(URI))
    assert store.index.read_bytes() == original
    assert len(backend.values) == 1
    assert list(store.directory.glob(".accounts-*")) == []


def test_failed_vault_write_does_not_create_index(store, backend, monkeypatch):
    def partial_write(service, username, value):
        backend.values[service, username] = value
        raise RuntimeError(SECRET)

    monkeypatch.setattr(backend, "set_password", partial_write)
    with pytest.raises(AppError, match="Could not save the credential") as result:
        store.add("work", parse_enrollment(URI))
    assert SECRET not in str(result.value)
    assert not store.index.exists()
    assert backend.values == {}


def test_missing_credential_can_be_removed(store, backend):
    store.add("work", parse_enrollment(URI))
    backend.values.clear()
    with pytest.raises(AppError, match="credential is missing"):
        store.get("work")
    store.remove("work")
    assert store.list() == []


def test_remove_can_recover_after_index_write_failure(store, backend, monkeypatch):
    store.add("work", parse_enrollment(URI))

    def fail_write(records):
        raise AppError("simulated disk failure")

    with monkeypatch.context() as patch:
        patch.setattr(store, "_write", fail_write)
        with pytest.raises(AppError, match="Retry the remove command"):
            store.remove("work")
    assert not backend.values
    store.remove("work")
    assert store.list() == []


@pytest.mark.parametrize(
    "corruption", ["broken-json", "version", "extra-secret", "control-character"]
)
def test_corrupt_index_is_never_overwritten_or_echoed(store, corruption):
    store.add("work", parse_enrollment(URI))
    data = json.loads(store.index.read_text())
    if corruption == "version":
        data["version"] = 100
    elif corruption == "extra-secret":
        data["accounts"][0]["secret"] = SECRET
    elif corruption == "control-character":
        data["accounts"][0]["account"] = "\x1b[31m"
    store.index.write_text(SECRET if corruption == "broken-json" else json.dumps(data))
    original = store.index.read_bytes()
    with pytest.raises(AppError, match="account index is invalid") as result:
        store.add("new", parse_enrollment(URI))
    assert SECRET not in str(result.value)
    assert store.index.read_bytes() == original


def test_concurrent_imports_do_not_lose_accounts(store):
    def add(alias):
        Store(store.directory, store.vault).add(alias, parse_enrollment(URI))

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(add, ["one", "two", "three", "four"]))
    assert len(store.list()) == 4
