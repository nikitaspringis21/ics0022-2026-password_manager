"""Interface layer: argparse-based CLI.

Design rule (threat-model.md, I1/I4): no command ever accepts a secret
as a CLI argument. Secrets are only ever entered interactively.
"""
from __future__ import annotations

import argparse
import sys

from pwmanager.crypto.cipher import DecryptionError
from pwmanager.models import Entry
from pwmanager.storage.file_storage import vault_exists
from pwmanager.vault import session as sessionmod
from pwmanager.vault.vault import VaultError

DEFAULT_VAULT_PATH = "vault.json"


def _cmd_init(args: argparse.Namespace) -> int:
    if vault_exists(args.vault):
        print(f"A vault already exists at {args.vault!r}.", file=sys.stderr)
        return 1
    sessionmod.create_vault(args.vault)
    print(f"Initialised a new vault at {args.vault!r}.")
    return 0


def _cmd_add(args: argparse.Namespace) -> int:
    sess = sessionmod.unlock(args.vault)
    try:
        import getpass

        entry_password = getpass.getpass(f"Password for {args.title!r}: ")
        entry = Entry(title=args.title, username=args.username, password=entry_password,
                      url=args.url or "", notes=args.notes or "")
        sess.vault.add_entry(entry)
        sess.save(args.vault)
        print(f"Added {args.title!r}.")
        return 0
    finally:
        sess.lock()


def _cmd_get(args: argparse.Namespace) -> int:
    sess = sessionmod.unlock(args.vault)
    try:
        entry = sess.vault.get_entry(args.title)
        if entry is None:
            print(f"No entry titled {args.title!r}.", file=sys.stderr)
            return 1
        if args.show:
            print(entry.password)
        else:
            _copy_to_clipboard(entry.password)
            print(f"Copied password for {args.title!r} to the clipboard.")
        return 0
    finally:
        sess.lock()


def _cmd_list(args: argparse.Namespace) -> int:
    sess = sessionmod.unlock(args.vault)
    try:
        for title in sess.vault.list_titles():
            print(title)
        return 0
    finally:
        sess.lock()


def _cmd_delete(args: argparse.Namespace) -> int:
    sess = sessionmod.unlock(args.vault)
    try:
        if sess.vault.delete_entry(args.title):
            sess.save(args.vault)
            print(f"Deleted {args.title!r}.")
            return 0
        print(f"No entry titled {args.title!r}.", file=sys.stderr)
        return 1
    finally:
        sess.lock()


def _copy_to_clipboard(text: str) -> None:
    """Best-effort clipboard copy; degrades gracefully if pyperclip
    isn't installed rather than crashing (still an early-stage skeleton
    -- see README's Planned commands / TODO)."""
    try:
        import pyperclip

        pyperclip.copy(text)
    except Exception:
        print("(clipboard copy unavailable in this environment)", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pwmanager", description="Secure local password manager")
    parser.add_argument("--vault", default=DEFAULT_VAULT_PATH, help="Path to the vault file")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Create a new, empty vault").set_defaults(func=_cmd_init)

    p_add = sub.add_parser("add", help="Add a new entry")
    p_add.add_argument("title")
    p_add.add_argument("--username", default="")
    p_add.add_argument("--url", default="")
    p_add.add_argument("--notes", default="")
    p_add.set_defaults(func=_cmd_add)

    p_get = sub.add_parser("get", help="Retrieve an entry's password")
    p_get.add_argument("title")
    p_get.add_argument("--show", action="store_true", help="Print instead of copying to clipboard")
    p_get.set_defaults(func=_cmd_get)

    sub.add_parser("list", help="List entry titles").set_defaults(func=_cmd_list)

    p_del = sub.add_parser("delete", help="Delete an entry")
    p_del.add_argument("title")
    p_del.set_defaults(func=_cmd_delete)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (VaultError, DecryptionError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
