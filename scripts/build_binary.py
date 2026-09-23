"""Build on the target OS: Windows -> totp.exe, macOS/Linux -> totp."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", type=Path, default=ROOT / "dist")
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build")
    options = parser.parse_args()
    build = options.work_dir.resolve()
    build.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--console",
        "--name",
        "totp",
        "--noupx",
        "--paths",
        str(ROOT / "src"),
        "--distpath",
        str(options.dist_dir.resolve()),
        "--workpath",
        str(build / "objects"),
        "--specpath",
        str(build),
        "--copy-metadata",
        "keyring",
        "--collect-all",
        "zxingcpp",
    ]
    # Explicit imports are needed because OS credential backends use lazy native imports.
    if sys.platform == "win32":
        command += [
            "--hidden-import",
            "keyring.backends.Windows",
            "--collect-submodules",
            "win32ctypes",
        ]
    elif sys.platform == "darwin":
        command += [
            "--hidden-import",
            "keyring.backends.macOS",
            "--hidden-import",
            "keyring.backends.macOS.api",
        ]
    elif sys.platform.startswith("linux"):
        command += [
            "--hidden-import",
            "keyring.backends.SecretService",
            "--collect-submodules",
            "secretstorage",
            "--collect-submodules",
            "jeepney",
        ]
    else:
        parser.error("Build on Windows, macOS or Linux.")
    command.append(str(ROOT / "scripts" / "entrypoint.py"))
    environment = dict(os.environ)
    environment["PYINSTALLER_CONFIG_DIR"] = str(build / "cache")
    subprocess.run(command, check=True, cwd=ROOT, env=environment)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
