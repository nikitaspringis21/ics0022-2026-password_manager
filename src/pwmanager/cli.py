"""Interface layer: argparse-based CLI.

Design rules (threat-model.md, M3/M4/I1-I4):
- No command accepts a secret as a CLI argument; secrets are only ever
  entered through the non-echoing prompt in vault.session.
- No command ever prints a stored password in cleartext. `get` copies
  it to the clipboard and clears the clipboard after a timeout; `show`
  prints entry metadata with the password masked.
- Text that came out of the vault (titles, usernames, notes) is
  sanitised before printing so it cannot inject terminal escape codes.
"""
from __future__ import annotations

import argparse
import secrets
import string
import sys
import time

from pwmanager import __version__
from pwmanager.crypto.cipher import DecryptionError
from pwmanager.models import Entry
from pwmanager.storage.file_storage import StorageError, permissions_too_open
from pwmanager.vault import session as sessionmod
from pwmanager.vault.vault import VaultError

DEFAULT_VAULT_PATH = "vault.json"
DEFAULT_CLIPBOARD_SECONDS = 20
MASK = "********"

GEN_ALPHABET = string.ascii_letters + string.digits + "!#$%&()*+,-./:;<=>?@[]^_{|}~"
GEN_MIN_LEN, GEN_DEFAULT_LEN, GEN_MAX_LEN = 12, 20, 128


class ClipboardError(Exception):
    pass


# -- helpers -------------------------------------------------------------

def safe(text: str) -> str:
    """Replace control / non-printable characters (e.g. ANSI escape
    sequences stored in a title or note) so vault content can't
    manipulate the terminal when displayed."""
    return "".join(ch if ch.isprintable() else "?" for ch in text)


def generate_password(length: int = GEN_DEFAULT_LEN) -> str:
    """CSPRNG password (`secrets`, never `random`) that contains at least
    one lowercase, uppercase, digit and symbol."""
    if not GEN_MIN_LEN <= length <= GEN_MAX_LEN:
        raise VaultError(f"Generated password length must be {GEN_MIN_LEN}-{GEN_MAX_LEN}.")
    while True:
        pw = "".join(secrets.choice(GEN_ALPHABET) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw) and any(not c.isalnum() for c in pw)):
            return pw


def _unlock(path: str) -> sessionmod.Session:
    if permissions_too_open(path):
        print(f"Warning: {path!r} is readable by other users; run `chmod 600 {path}`.",
              file=sys.stderr)
    return sessionmod.unlock(path)


def _copy_with_autoclear(secret: str, seconds: int) -> None:
    """Copy `secret` to the clipboard, wait, then clear it (I2). The
    clipboard is only cleared if it still holds our secret, so we don't
    wipe something the user copied in the meantime. Ctrl+C clears now."""
    try:
        import pyperclip

        pyperclip.copy(secret)
    except Exception as exc:  # pyperclip raises various errors without a backend
        raise ClipboardError(
            "No clipboard available. On Linux install xclip, xsel or "
            "wl-clipboard; on a headless machine `get` cannot be used. "
            "(Passwords are never printed to the terminal.)"
        ) from exc

    if seconds <= 0:
        print("Password copied to the clipboard (auto-clear disabled).")
        return
    print(f"Password copied to the clipboard. It will be cleared in {seconds}s "
          "(press Ctrl+C to clear now).")
    try:
        time.sleep(seconds)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            if pyperclip.paste() == secret:
                pyperclip.copy("")
                print("Clipboard cleared.")
        except Exception:
            print("Warning: could not clear the clipboard.", file=sys.stderr)


# -- commands ------------------------------------------------------------

def _cmd_init(args: argparse.Namespace) -> int:
    print(f"Creating a new vault at {args.vault!r}.")
    print(f"Choose a master password of at least {sessionmod.MIN_MASTER_PASSWORD_LEN} "
          "characters. It cannot be recovered if lost.")
    sessionmod.create_vault(args.vault)
    print(f"Initialised a new vault at {args.vault!r}.")
    return 0


def _cmd_add(args: argparse.Namespace) -> int:
    sess = _unlock(args.vault)
    try:
        if sess.vault.get_entry(args.title) is not None:
            raise VaultError(f"An entry titled {safe(args.title)!r} already exists.")
        if args.generate:
            entry_password = generate_password(args.length)
        else:
            entry_password = sessionmod.prompt_secret(f"Password for {safe(args.title)!r}: ")
            if not entry_password:
                raise VaultError("Entry password must not be empty.")
            if sessionmod.prompt_secret("Confirm password: ") != entry_password:
                raise VaultError("Passwords did not match.")
        entry = Entry(title=args.title, username=args.username, password=entry_password,
                      url=args.url, notes=args.notes)
        sess.vault.add_entry(entry)
        sess.save(args.vault)
        suffix = " with a generated password (use `get` to copy it)" if args.generate else ""
        print(f"Added {safe(args.title)!r}{suffix}.")
        return 0
    finally:
        sess.lock()


def _cmd_get(args: argparse.Namespace) -> int:
    sess = _unlock(args.vault)
    try:
        entry = sess.vault.get_entry(args.title)
        if entry is None:
            print(f"No entry titled {safe(args.title)!r}.", file=sys.stderr)
            return 1
        secret = entry.password
    finally:
        sess.lock()  # drop the key before we sit waiting on the clipboard timer
    _copy_with_autoclear(secret, args.clear_after)
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    sess = _unlock(args.vault)
    try:
        entry = sess.vault.get_entry(args.title)
        if entry is None:
            print(f"No entry titled {safe(args.title)!r}.", file=sys.stderr)
            return 1
        rows = [("Title", entry.title), ("Username", entry.username),
                ("Password", MASK), ("URL", entry.url), ("Notes", entry.notes),
                ("Created", entry.created_at), ("Updated", entry.updated_at)]
        for label, value in rows:
            print(f"{label + ':':<10} {value if value is MASK else safe(value)}")
        return 0
    finally:
        sess.lock()


def _cmd_list(args: argparse.Namespace) -> int:
    sess = _unlock(args.vault)
    try:
        titles = sess.vault.list_titles()
        if not titles:
            print("(vault is empty)")
        for title in sorted(titles, key=str.casefold):
            print(safe(title))
        return 0
    finally:
        sess.lock()


def _cmd_delete(args: argparse.Namespace) -> int:
    sess = _unlock(args.vault)
    try:
        if sess.vault.get_entry(args.title) is None:
            print(f"No entry titled {safe(args.title)!r}.", file=sys.stderr)
            return 1
        if not args.yes:
            answer = input(f"Delete {safe(args.title)!r}? This cannot be undone [y/N]: ")
            if answer.strip().lower() not in ("y", "yes"):
                print("Cancelled.")
                return 1
        sess.vault.delete_entry(args.title)
        sess.save(args.vault)
        print(f"Deleted {safe(args.title)!r}.")
        return 0
    finally:
        sess.lock()


# -- parser / entry point ------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pwmanager", description="Secure local password manager")
    parser.add_argument("--vault", default=DEFAULT_VAULT_PATH,
                        help=f"Path to the vault file (default: {DEFAULT_VAULT_PATH})")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Create a new, empty vault").set_defaults(func=_cmd_init)

    p_add = sub.add_parser("add", help="Add a new entry (password is prompted, never an argument)")
    p_add.add_argument("title")
    p_add.add_argument("--username", default="")
    p_add.add_argument("--url", default="")
    p_add.add_argument("--notes", default="",
                       help="Non-secret notes (visible in shell history; don't put secrets here)")
    p_add.add_argument("--generate", action="store_true",
                       help="Generate a random password instead of prompting for one")
    p_add.add_argument("--length", type=int, default=GEN_DEFAULT_LEN,
                       help=f"Length for --generate (default {GEN_DEFAULT_LEN})")
    p_add.set_defaults(func=_cmd_add)

    p_get = sub.add_parser("get", help="Copy an entry's password to the clipboard")
    p_get.add_argument("title")
    p_get.add_argument("--clear-after", type=int, default=DEFAULT_CLIPBOARD_SECONDS, metavar="SECONDS",
                       help=f"Clear the clipboard after this many seconds (default "
                            f"{DEFAULT_CLIPBOARD_SECONDS}; 0 disables)")
    p_get.set_defaults(func=_cmd_get)

    p_show = sub.add_parser("show", help="Show an entry's details (password masked)")
    p_show.add_argument("title")
    p_show.set_defaults(func=_cmd_show)

    sub.add_parser("list", help="List entry titles").set_defaults(func=_cmd_list)

    p_del = sub.add_parser("delete", help="Delete an entry")
    p_del.add_argument("title")
    p_del.add_argument("-y", "--yes", action="store_true", help="Don't ask for confirmation")
    p_del.set_defaults(func=_cmd_delete)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (VaultError, DecryptionError, StorageError, ClipboardError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nAborted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())