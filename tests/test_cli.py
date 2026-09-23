import io
import json

import pytest
from conftest import SECRET, URI

from totp_cli import cli
from totp_cli.totp import parse_enrollment


def test_cli_import_list_code_remove(store, qr_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "Store", lambda directory: store)
    monkeypatch.setattr(cli.time, "time", lambda: 59)
    assert cli.main(["add", "work", "--qr", str(qr_path)]) == 0
    assert SECRET not in capsys.readouterr().out
    assert cli.main(["list", "--json"]) == 0
    records = json.loads(capsys.readouterr().out)
    assert records[0]["alias"] == "work"
    assert set(records[0]) == {"alias", "issuer", "account", "digits", "period", "algorithm"}
    assert cli.main(["code", "WORK"]) == 0
    assert capsys.readouterr().out == "287082\n"
    assert cli.main(["remove", "work"]) == 0
    capsys.readouterr()
    assert cli.main(["code", "work"]) == 1
    assert "Account not found" in capsys.readouterr().err


def test_cli_watch_rejects_redirect_before_reading_secret(store, monkeypatch, capsys):
    monkeypatch.setattr(cli, "Store", lambda directory: store)
    assert cli.main(["code", "work", "--watch"]) == 1
    assert "interactive terminal" in capsys.readouterr().err


def test_watch_refreshes_and_clears_line_on_interrupt(store, monkeypatch):
    class Terminal(io.StringIO):
        def isatty(self):
            return True

    terminal = Terminal()
    moments = iter([59.5, 60])
    sleeps = []

    def sleep(duration):
        sleeps.append(duration)
        if len(sleeps) == 2:
            raise KeyboardInterrupt

    store.add("work", parse_enrollment(URI))
    monkeypatch.setattr(cli, "Store", lambda directory: store)
    monkeypatch.setattr(cli.sys, "stdout", terminal)
    monkeypatch.setattr(cli.time, "time", lambda: next(moments))
    monkeypatch.setattr(cli.time, "sleep", sleep)
    assert cli.main(["code", "work", "--watch"]) == 130
    content = terminal.getvalue()
    assert "287082" in content and "359152" in content
    assert content.endswith(" \r")
    assert SECRET not in content


def test_parser_does_not_echo_accidentally_pasted_secret(capsys):
    with pytest.raises(SystemExit) as result:
        cli.main(["code", "work", "--secret", SECRET])
    assert result.value.code == 2
    output = capsys.readouterr()
    assert SECRET not in output.err + output.out


def test_decoder_exception_is_sanitized(monkeypatch, capsys):
    def fail(path):
        raise RuntimeError(URI)

    monkeypatch.setattr(cli, "read_enrollment", fail)
    assert cli.main(["add", "work", "--qr", "fake.png"]) == 1
    output = capsys.readouterr()
    assert "operation failed" in output.err
    assert URI not in output.err and SECRET not in output.err
