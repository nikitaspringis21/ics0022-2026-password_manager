"""Storage layer: durable, safe persistence of the opaque envelope.

This module knows nothing about encryption or passwords — it only reads
and writes a JSON dict (the envelope produced by Vault.seal /
consumed by Vault.unseal) to disk, safely.
"""
from __future__ import annotations

import json
import os
import stat
import tempfile


class StorageError(Exception):
    """The vault file could not be read or written. Generic messages only."""


def save_envelope(path: str, envelope: dict) -> None:
    """Atomically write `envelope` to `path` with owner-only permissions.

    Writes to a temp file in the same directory, fsyncs it, then renames
    it over the target — so a crash mid-write can never leave a
    truncated or half-written vault file (threat-model.md, S5).
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".vault-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(envelope, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600, owner rw only
        os.replace(tmp_path, path)  # atomic on POSIX and Windows
    except BaseException:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def load_envelope(path: str) -> dict:
    """Read the envelope JSON. Raises StorageError (never a raw traceback)
    if the file is missing, unreadable, or not JSON."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError as exc:
        raise StorageError(
            f"No vault found at {path!r}. Run `pwmanager init` first, "
            "or pass --vault PATH."
        ) from exc
    except OSError as exc:
        raise StorageError(f"Could not read vault file {path!r}: {exc.strerror}.") from exc
    except (ValueError, UnicodeDecodeError) as exc:
        raise StorageError(f"Vault file {path!r} is corrupted (not valid JSON).") from exc


def permissions_too_open(path: str) -> bool:
    """True if group/other can access the vault file (POSIX only). The
    file is still encrypted, but 0600 is part of our defence in depth
    (threat-model.md, S4), so the CLI warns about it."""
    if os.name != "posix":
        return False
    try:
        return bool(os.stat(path).st_mode & (stat.S_IRWXG | stat.S_IRWXO))
    except OSError:
        return False


def vault_exists(path: str) -> bool:
    return os.path.isfile(path)