"""An atomic, locked index of accounts; secrets live only in the OS vault."""

from __future__ import annotations

import json
import os
import re
import tempfile
import unicodedata
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from filelock import FileLock, Timeout
from platformdirs import user_data_path

from totp_cli.errors import AppError
from totp_cli.totp import DIGESTS, Enrollment, visible_text
from totp_cli.vault import Vault

MAX_INDEX_BYTES = 1024 * 1024
FIELDS = {"id", "alias", "account", "issuer", "algorithm", "digits", "period"}


def validate_alias(alias: str) -> str:
    if not isinstance(alias, str):
        raise AppError("An account alias must be text.")
    alias = unicodedata.normalize("NFC", alias)
    if (
        not 1 <= len(alias) <= 64
        or not alias[0].isalnum()
        or not all(c.isalnum() or c in "._-" for c in alias)
    ):
        raise AppError(
            "Use an alias of 1-64 letters, numbers, dots, underscores or hyphens; "
            "start with a letter or number."
        )
    return alias


class Store:
    def __init__(self, directory: Path | None = None, vault: Vault | None = None):
        self.directory = (
            directory
            if directory is not None
            else user_data_path("local-totp-cli", appauthor=False, roaming=False)
        )
        self.index = self.directory / "accounts.json"
        self._vault = vault

    @property
    def vault(self) -> Vault:
        if self._vault is None:
            self._vault = Vault.native()
        return self._vault

    @contextmanager
    def _locked(self) -> Iterator[None]:
        try:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            with FileLock(self.directory / "accounts.lock", timeout=5, mode=0o600):
                yield
        except Timeout:
            raise AppError(
                "Another TOTP process is updating the account index. Try again."
            ) from None
        except OSError:
            raise AppError(
                "Could not access the account index directory. Check its permissions."
            ) from None

    def _read(self) -> list[dict]:
        try:
            with self.index.open("rb") as stream:
                content = stream.read(MAX_INDEX_BYTES + 1)
        except FileNotFoundError:
            return []
        except OSError:
            raise AppError("Could not read the account index. Check its permissions.") from None
        try:
            if len(content) > MAX_INDEX_BYTES:
                raise ValueError
            document = json.loads(content)
            if (
                not isinstance(document, dict)
                or set(document) != {"version", "accounts"}
                or type(document["version"]) is not int
                or document["version"] != 1
                or not isinstance(document["accounts"], list)
            ):
                raise ValueError
            aliases: set[str] = set()
            identifiers: set[str] = set()
            for record in document["accounts"]:
                if not isinstance(record, dict) or set(record) != FIELDS:
                    raise ValueError
                if not isinstance(record["id"], str) or not re.fullmatch(
                    r"[a-f0-9]{32}", record["id"]
                ):
                    raise ValueError
                alias = validate_alias(record["alias"])
                if alias != record["alias"] or alias.casefold() in aliases:
                    raise ValueError
                if record["id"] in identifiers:
                    raise ValueError
                aliases.add(alias.casefold())
                identifiers.add(record["id"])
                visible_text(record["account"])
                visible_text(record["issuer"], allow_empty=True)
                if record["algorithm"] not in DIGESTS:
                    raise ValueError
                if type(record["digits"]) is not int or record["digits"] not in (6, 8):
                    raise ValueError
                if type(record["period"]) is not int or not 1 <= record["period"] <= 86400:
                    raise ValueError
            return document["accounts"]
        except (ValueError, TypeError, KeyError, UnicodeError, AppError):
            raise AppError(
                "The account index is invalid or from an unsupported version. "
                "It has not been overwritten."
            ) from None

    def _write(self, records: list[dict]) -> None:
        temporary: Path | None = None
        try:
            content = (
                json.dumps({"version": 1, "accounts": records}, ensure_ascii=True, indent=2).encode(
                    "utf-8"
                )
                + b"\n"
            )
            if len(content) > MAX_INDEX_BYTES:
                raise AppError("The account index has reached its size limit.")
            descriptor, name = tempfile.mkstemp(prefix=".accounts-", dir=self.directory)
            temporary = Path(name)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            # The temporary file is closed first, which is required by Windows.
            os.replace(temporary, self.index)
        except OSError:
            raise AppError(
                "Could not save the account index. Check free space and permissions."
            ) from None
        finally:
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass

    @staticmethod
    def _find(records: list[dict], alias: str) -> dict:
        folded = validate_alias(alias).casefold()
        for record in records:
            if record["alias"].casefold() == folded:
                return record
        raise AppError("Account not found. Use 'totp list' to see saved aliases.")

    def list(self) -> list[dict]:
        # A fresh installation can list accounts without creating files or opening a vault.
        if not self.directory.exists():
            return []
        with self._locked():
            return sorted(self._read(), key=lambda record: record["alias"].casefold())

    def add(self, alias: str, enrollment: Enrollment) -> None:
        alias = validate_alias(alias)
        with self._locked():
            records = self._read()
            if any(record["alias"].casefold() == alias.casefold() for record in records):
                raise AppError(
                    "That alias already exists. Choose another alias; nothing was replaced."
                )
            identifier = uuid4().hex
            record = {
                "id": identifier,
                "alias": alias,
                "account": enrollment.account,
                "issuer": enrollment.issuer,
                "algorithm": enrollment.algorithm,
                "digits": enrollment.digits,
                "period": enrollment.period,
            }
            vault = self.vault
            try:
                vault.put(identifier, enrollment.secret)
                self._write([*records, record])
            except BaseException:
                # Roll back the new, uniquely named entry if the index cannot be committed.
                try:
                    vault.delete(identifier)
                except AppError:
                    raise AppError(
                        "Import failed and credential cleanup also failed. Remove the OS "
                        f"credential entry '{vault.service(identifier)}' before retrying."
                    ) from None
                raise

    def get(self, alias: str) -> Enrollment:
        validate_alias(alias)
        if not self.directory.exists():
            raise AppError("Account not found. Import it with 'totp add NAME --qr PATH'.")
        with self._locked():
            record = self._find(self._read(), alias)
            secret = self.vault.get(record["id"])
            if secret is None:
                raise AppError(
                    "This account's credential is missing from the OS store. "
                    "Remove its local index entry and import the enrollment again."
                )
            return Enrollment(
                secret=secret,
                account=record["account"],
                issuer=record["issuer"],
                algorithm=record["algorithm"],
                digits=record["digits"],
                period=record["period"],
            )

    def remove(self, alias: str) -> None:
        validate_alias(alias)
        if not self.directory.exists():
            raise AppError("Account not found. Use 'totp list' to see saved aliases.")
        with self._locked():
            records = self._read()
            record = self._find(records, alias)
            self.vault.delete(record["id"])
            try:
                self._write([item for item in records if item["id"] != record["id"]])
            except AppError:
                raise AppError(
                    "The credential was removed, but its index could not be updated. "
                    "Retry the remove command to finish cleanup."
                ) from None
