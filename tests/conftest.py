from pathlib import Path

import pytest
import qrcode

from totp_cli.store import Store
from totp_cli.vault import Vault

# Public RFC 6238 test material, never a real account's enrollment.
SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
URI = f"otpauth://totp/Example:alice@example.com?secret={SECRET}&issuer=Example"


class MemoryBackend:
    def __init__(self):
        self.values = {}
        self.reads = 0

    def get_password(self, service, username):
        self.reads += 1
        return self.values.get((service, username))

    def set_password(self, service, username, secret):
        self.values[service, username] = secret

    def delete_password(self, service, username):
        del self.values[service, username]


@pytest.fixture
def backend():
    return MemoryBackend()


@pytest.fixture
def store(tmp_path, backend):
    return Store(tmp_path / "state", Vault(backend, "In-memory test backend"))


@pytest.fixture
def qr_path(tmp_path: Path):
    path = tmp_path / "截图 with spaces.png"
    qrcode.make(URI).save(path)
    return path
