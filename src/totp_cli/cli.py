"""The same CLI entry point is used on Windows, macOS and Linux."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from totp_cli import __version__
from totp_cli.errors import AppError
from totp_cli.qr import read_enrollment
from totp_cli.store import Store, validate_alias
from totp_cli.totp import Enrollment


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse normally echoes invalid values. A pasted secret must not be echoed.
        self.print_usage(sys.stderr)
        self.exit(2, "totp: invalid arguments. Use --help for command syntax.\n")


def parser() -> Parser:
    result = Parser(
        prog="totp", description="Offline TOTP from QR screenshots, using the OS vault."
    )
    result.add_argument("--version", action="version", version=f"totp {__version__}")
    result.add_argument(
        "--data-dir",
        type=Path,
        help="account index directory (secrets always stay in the OS credential store)",
    )
    commands = result.add_subparsers(dest="command", required=True)
    add = commands.add_parser("add", help="import one TOTP enrollment from a local image")
    add.add_argument("name", help="account alias, for example work")
    add.add_argument(
        "--qr", required=True, type=Path, metavar="PATH", help="local PNG or JPEG path"
    )
    listing = commands.add_parser("list", help="list accounts without reading their secrets")
    listing.add_argument("--json", action="store_true", help="output account metadata as JSON")
    code = commands.add_parser("code", help="print the current code")
    code.add_argument("name", help="saved account alias")
    code.add_argument(
        "--watch", action="store_true", help="refresh code and countdown until Ctrl+C"
    )
    remove = commands.add_parser("remove", help="remove this local credential and its index entry")
    remove.add_argument("name", help="saved account alias")
    commands.add_parser("doctor", help="show platform, credential backend and index location")
    return result


def watch(enrollment: Enrollment) -> None:
    if not sys.stdout.isatty():
        raise AppError("--watch needs an interactive terminal. Use 'totp code NAME' in scripts.")
    previous = ""
    try:
        while True:
            code, remaining = enrollment.code_at(time.time())
            line = f"{code}  expires in {remaining:5d}s  (Ctrl+C to exit)"
            if line != previous:
                sys.stdout.write("\r" + line.ljust(len(previous)))
                sys.stdout.flush()
                previous = line
            time.sleep(0.2)
    finally:
        if previous:
            sys.stdout.write("\r" + " " * len(previous) + "\r")
            sys.stdout.flush()


def run(arguments: argparse.Namespace, store: Store) -> None:
    if arguments.command == "add":
        alias = validate_alias(arguments.name)
        store.add(alias, read_enrollment(arguments.qr))
        print(f"Added '{alias}'.", flush=True)
    elif arguments.command == "list":
        records = [{k: v for k, v in row.items() if k != "id"} for row in store.list()]
        if arguments.json:
            print(json.dumps(records, ensure_ascii=True, indent=2), flush=True)
        elif not records:
            print("No accounts. Import one with 'totp add NAME --qr PATH'.", flush=True)
        else:
            print("ALIAS\tISSUER\tACCOUNT\tALGORITHM\tDIGITS\tPERIOD")
            for record in records:
                print(
                    "\t".join(
                        str(record[key])
                        for key in ("alias", "issuer", "account", "algorithm", "digits", "period")
                    ),
                    flush=True,
                )
    elif arguments.command == "code":
        if arguments.watch and not sys.stdout.isatty():
            raise AppError(
                "--watch needs an interactive terminal. Use 'totp code NAME' in scripts."
            )
        enrollment = store.get(arguments.name)
        if arguments.watch:
            watch(enrollment)
        else:
            print(enrollment.code_at(time.time())[0], flush=True)
    elif arguments.command == "remove":
        store.remove(arguments.name)
        print("Removed the local credential. The website's 2FA setting is unchanged.", flush=True)
    elif arguments.command == "doctor":
        print(f"Platform: {sys.platform}")
        print(f"Credential backend: {store.vault.label}")
        print(f"Account index: {store.index}")
        print(f"Accounts: {len(store.list())}")
        print("Store access is checked when importing or reading a credential.", flush=True)


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")
    arguments = parser().parse_args(argv)
    try:
        run(arguments, Store(arguments.data_dir))
    except AppError as error:
        print(f"Error: {error}", file=sys.stderr, flush=True)
        return 1
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return 0
    except Exception:
        # Native image/vault libraries can put input data in exception messages.
        print("Error: The operation failed; no credential details were printed.", file=sys.stderr)
        return 1
    return 0
