"""Explicit OS credential-store backends, with no plaintext fallback."""

from __future__ import annotations

import sys
from typing import Any

from totp_cli.errors import AppError

SERVICE_PREFIX = "local-totp-cli"
USERNAME = "totp-secret"


def native_backend() -> tuple[Any, str]:
    try:
        if sys.platform == "win32":
            from keyring.backends.Windows import WinVaultKeyring

            backend = WinVaultKeyring()
            # Keep the credential on this machine, rather than enabling profile roaming.
            backend.persist = "local machine"
            label = "Windows Credential Manager"
        elif sys.platform == "darwin":
            from keyring.backends.macOS import Keyring

            backend = Keyring()
            label = "macOS Keychain"
        elif sys.platform.startswith("linux"):
            from keyring.backends.SecretService import Keyring

            backend = Keyring()
            label = "Linux Secret Service"
        else:
            raise AppError("Supported platforms are Windows, macOS and Linux.")
        if backend.priority <= 0:
            raise RuntimeError
    except AppError:
        raise
    except Exception:
        raise AppError(
            "The OS credential store is unavailable. Windows needs Credential Manager; "
            "macOS needs Keychain; Linux needs a running, unlocked Secret Service. "
            "No plaintext fallback is used."
        ) from None
    return backend, label


class Vault:
    def __init__(self, backend: Any, label: str):
        self.backend = backend
        self.label = label

    @classmethod
    def native(cls) -> Vault:
        return cls(*native_backend())

    @staticmethod
    def service(credential_id: str) -> str:
        # Each account has its own service name, avoiding WinVault's multi-user fallback.
        return f"{SERVICE_PREFIX}/{credential_id}"

    def get(self, credential_id: str) -> str | None:
        try:
            return self.backend.get_password(self.service(credential_id), USERNAME)
        except Exception:
            raise AppError(
                "Could not read the credential. Unlock the OS credential store."
            ) from None

    def put(self, credential_id: str, secret: str) -> None:
        try:
            self.backend.set_password(self.service(credential_id), USERNAME, secret)
        except Exception:
            raise AppError("Could not save the credential to the OS credential store.") from None

    def delete(self, credential_id: str) -> None:
        # Missing secrets are allowed so an interrupted removal can be retried.
        if self.get(credential_id) is None:
            return
        try:
            self.backend.delete_password(self.service(credential_id), USERNAME)
        except Exception:
            raise AppError(
                "Could not remove the credential from the OS credential store."
            ) from None
