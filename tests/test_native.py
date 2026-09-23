import os
from uuid import uuid4

import pytest
from conftest import SECRET

from totp_cli.vault import Vault


@pytest.mark.native
@pytest.mark.skipif(os.environ.get("TOTP_TEST_NATIVE") != "1", reason="OS vault test is opt-in")
def test_disposable_native_credential_roundtrip():
    backend = Vault.native()
    identifier = uuid4().hex
    try:
        backend.put(identifier, SECRET)
        assert backend.get(identifier) == SECRET
    finally:
        backend.delete(identifier)
    assert backend.get(identifier) is None
