import sys
from types import SimpleNamespace

import pytest
from conftest import SECRET

from totp_cli import vault
from totp_cli.errors import AppError


@pytest.mark.parametrize(
    "platform,module,classname,label",
    [
        ("win32", "Windows", "WinVaultKeyring", "Windows Credential Manager"),
        ("darwin", "macOS", "Keyring", "macOS Keychain"),
        ("linux", "SecretService", "Keyring", "Linux Secret Service"),
    ],
)
def test_explicit_platform_backend_ignores_plaintext_override(
    monkeypatch, platform, module, classname, label
):
    class NativeBackend:
        priority = 5

    monkeypatch.setattr(vault, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setitem(
        sys.modules, f"keyring.backends.{module}", SimpleNamespace(**{classname: NativeBackend})
    )
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyrings.alt.file.PlaintextKeyring")
    backend, result = vault.native_backend()
    assert isinstance(backend, NativeBackend)
    assert result == label
    if platform == "win32":
        assert backend.persist == "local machine"


def test_unavailable_vault_fails_without_fallback(monkeypatch):
    class BrokenBackend:
        @property
        def priority(self):
            raise RuntimeError(SECRET)

    monkeypatch.setattr(vault, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setitem(
        sys.modules, "keyring.backends.SecretService", SimpleNamespace(Keyring=BrokenBackend)
    )
    with pytest.raises(AppError, match="No plaintext fallback") as result:
        vault.native_backend()
    assert SECRET not in str(result.value)


def test_backend_read_errors_are_sanitized():
    class BrokenBackend:
        def get_password(self, service, username):
            raise RuntimeError(SECRET)

    with pytest.raises(AppError) as result:
        vault.Vault(BrokenBackend(), "test").get("id")
    assert SECRET not in str(result.value)
