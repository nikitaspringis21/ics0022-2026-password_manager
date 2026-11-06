"""End-to-end CLI tests. The central property checked here is the
Checkpoint 2 requirement that the interface never prints a stored
password in cleartext -- on any command, success or failure path."""
import sys
import types

import pytest

from pwmanager import cli
from tests.conftest import MASTER

ENTRY_PW = "Entry-Pa55word-zq81"


@pytest.fixture
def clipboard(monkeypatch):
    board = {"value": ""}
    fake = types.SimpleNamespace(copy=lambda s: board.__setitem__("value", s),
                                 paste=lambda: board["value"])
    monkeypatch.setitem(sys.modules, "pyperclip", fake)
    monkeypatch.setattr(cli.time, "sleep", lambda s: board.__setitem__("seen", board["value"]))
    return board


@pytest.fixture
def populated(new_vault, prompts):
    prompts.extend([MASTER, ENTRY_PW, ENTRY_PW])
    assert cli.main(["--vault", new_vault, "add", "GitHub", "--username", "alice"]) == 0
    return new_vault


def _run(vault, prompts, *argv, master=MASTER):
    prompts.append(master)
    return cli.main(["--vault", vault, *argv])


def test_no_command_prints_the_password(populated, prompts, clipboard, capsys):
    for argv in (["list"], ["show", "GitHub"], ["get", "GitHub"]):
        assert _run(populated, prompts, *argv) == 0
    out = capsys.readouterr()
    assert ENTRY_PW not in out.out and ENTRY_PW not in out.err
    assert MASTER not in out.out and MASTER not in out.err
    assert "GitHub" in out.out and cli.MASK in out.out


def test_get_copies_then_clears_clipboard(populated, prompts, clipboard):
    assert _run(populated, prompts, "get", "GitHub") == 0
    assert clipboard["seen"] == ENTRY_PW   # was on the clipboard during the wait
    assert clipboard["value"] == ""        # and cleared afterwards


def test_get_without_clipboard_fails_without_printing(populated, prompts, monkeypatch, capsys):
    broken = types.SimpleNamespace(copy=lambda s: (_ for _ in ()).throw(RuntimeError("no backend")))
    monkeypatch.setitem(sys.modules, "pyperclip", broken)
    assert _run(populated, prompts, "get", "GitHub") == 1
    out = capsys.readouterr()
    assert ENTRY_PW not in out.out + out.err
    assert "No clipboard available" in out.err


def test_show_flag_removed(populated):
    with pytest.raises(SystemExit):
        cli.main(["--vault", populated, "get", "GitHub", "--show"])


def test_wrong_master_password_exit_code(populated, prompts, capsys):
    prompts.extend(["bad", "bad", "bad"])
    assert cli.main(["--vault", populated, "list"]) == 1
    assert "GitHub" not in capsys.readouterr().out


def test_generate(new_vault, prompts, clipboard, capsys):
    assert _run(new_vault, prompts, "add", "Mail", "--generate", "--length", "24") == 0
    assert _run(new_vault, prompts, "get", "Mail") == 0
    generated = clipboard["seen"]
    assert len(generated) == 24
    assert generated not in capsys.readouterr().out


def test_delete_needs_confirmation(populated, prompts, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda p: "n")
    assert _run(populated, prompts, "delete", "GitHub") == 1
    monkeypatch.setattr("builtins.input", lambda p: "y")
    assert _run(populated, prompts, "delete", "GitHub") == 0
    assert _run(populated, prompts, "show", "GitHub") == 1


def test_missing_vault_is_clean_error(tmp_path, capsys):
    assert cli.main(["--vault", str(tmp_path / "x.json"), "list"]) == 1
    assert "pwmanager init" in capsys.readouterr().err


def test_safe_strips_terminal_escapes():
    assert cli.safe("a\x1b[2Jb\n") == "a?[2Jb?"


def test_generated_passwords_are_strong_and_unique():
    pws = {cli.generate_password() for _ in range(50)}
    assert len(pws) == 50
    with pytest.raises(Exception):
        cli.generate_password(4)