"""Exercise the installed CLI or binary with a disposable public test credential."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pyotp
import qrcode

PUBLIC_TEST_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, help="test a frozen executable instead of Python")
    parser.add_argument("--work-dir", type=Path, default=Path(".build"))
    options = parser.parse_args()
    options.work_dir.mkdir(parents=True, exist_ok=True)
    command = (
        [str(options.binary.resolve())] if options.binary else [sys.executable, "-m", "totp_cli"]
    )
    environment = dict(os.environ, PYTHONIOENCODING="utf-8")
    with tempfile.TemporaryDirectory(prefix="totp-smoke-", dir=options.work_dir) as temporary:
        directory = Path(temporary).resolve()
        image = directory / "测试 QR image.png"
        qrcode.make("otpauth://totp/Test:alice?secret=" + PUBLIC_TEST_SECRET + "&issuer=Test").save(
            image
        )
        prefix = [*command, "--data-dir", str(directory / "state")]

        def run(*args: str) -> str:
            result = subprocess.run(
                [*prefix, *args],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                env=environment,
            )
            if result.returncode:
                raise RuntimeError(f"CLI smoke step '{args[0]}' failed: {result.stderr}")
            return result.stdout

        imported = False
        try:
            run("add", "smoke-test", "--qr", str(image))
            imported = True
            start = int(time.time())
            code = run("code", "smoke-test").strip()
            finish = int(time.time())
            valid = {pyotp.TOTP(PUBLIC_TEST_SECRET).at(t) for t in range(start, finish + 1)}
            if code not in valid:
                raise RuntimeError("The CLI generated an unexpected test code.")
            accounts = json.loads(run("list", "--json"))
            if [record["alias"] for record in accounts] != ["smoke-test"]:
                raise RuntimeError("Account listing failed.")
            metadata = (directory / "state" / "accounts.json").read_text()
            if PUBLIC_TEST_SECRET in metadata:
                raise RuntimeError("Secret material was written to the account index.")
        finally:
            if imported:
                run("remove", "smoke-test")
        if json.loads(run("list", "--json")):
            raise RuntimeError("The disposable account was not removed.")
    print("Native CLI smoke passed: QR import, OS vault, code, listing and removal.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
