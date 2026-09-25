"""User-management module: master password handling and session state.

This is the layer the CLI talks to instead of touching crypto/storage
directly. Checkpoint 1 ships the essential shape of it; command-specific
polish (auto-lock timers, retry limits) is planned follow-up work
tracked in docs/design-decisions.md.
"""
from __future__ import annotations

import getpass
from dataclasses import dataclass

from pwmanager.crypto import kdf
from pwmanager.crypto.memutil import zero
from pwmanager.storage.file_storage import load_envelope, save_envelope
from pwmanager.vault.vault import Vault, VaultError


@dataclass
class Session:
    """An unlocked session: holds the derived key and the decrypted
    Vault for the lifetime of one CLI invocation, then is discarded."""

    vault: Vault
    _key: bytearray
    _kdf_params: kdf.KdfParams

    def save(self, path: str) -> None:
        envelope = self.vault.seal(bytes(self._key), self._kdf_params)
        save_envelope(path, envelope)

    def lock(self) -> None:
        """Explicitly drop the key material. Call this in a `finally`
        block so it runs even if a command raises."""
        zero(self._key)


def prompt_master_password(confirm: bool = False) -> bytes:
    """Interactive, non-echoing password prompt. Never accepts the
    password as a CLI argument (see threat-model.md, M4)."""
    pw = getpass.getpass("Master password: ")
    if confirm:
        pw2 = getpass.getpass("Confirm master password: ")
        if pw != pw2:
            raise VaultError("Passwords did not match.")
    return pw.encode("utf-8")


def create_vault(path: str) -> None:
    """`pwmanager init` — create a brand-new, empty vault."""
    password = prompt_master_password(confirm=True)
    try:
        params = kdf.KdfParams.generate()
        key = bytearray(kdf.derive_key(password, params))
        vault = Vault()
        envelope = vault.seal(bytes(key), params)
        save_envelope(path, envelope)
    finally:
        zero(bytearray(password))


def unlock(path: str) -> Session:
    """`pwmanager <command>` — prompt for the master password and
    decrypt the vault into a live Session."""
    password = prompt_master_password(confirm=False)
    try:
        envelope = load_envelope(path)
        params = kdf.KdfParams.from_dict(envelope["kdf"])
        key = bytearray(kdf.derive_key(password, params))
        vault = Vault.unseal(bytes(key), envelope)  # raises DecryptionError on wrong password
        return Session(vault=vault, _key=key, _kdf_params=params)
    finally:
        zero(bytearray(password))
