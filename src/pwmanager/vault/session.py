"""User-management module: master password handling and session state.

This is the layer the CLI talks to instead of touching crypto/storage
directly. Authentication works by *trial decryption*: the master
password is run through Argon2id and the resulting key is used to open
the vault. AES-GCM's authentication tag only verifies with the correct
key, so the vault unlocks if and only if the password is correct. No
password hash is stored anywhere (design-decisions.md, section 1).
"""
from __future__ import annotations

import getpass
import sys
from dataclasses import dataclass

from pwmanager.crypto import kdf
from pwmanager.crypto.cipher import DecryptionError
from pwmanager.crypto.memutil import zero
from pwmanager.storage.file_storage import load_envelope, save_envelope, vault_exists
from pwmanager.vault.vault import Vault, VaultError

MIN_MASTER_PASSWORD_LEN = 12
MAX_UNLOCK_ATTEMPTS = 3


class AuthenticationError(VaultError):
    """Raised when the master password could not be verified."""


@dataclass
class Session:
    """An unlocked session: holds the derived key and the decrypted
    Vault for the lifetime of one CLI invocation, then is discarded."""

    vault: Vault
    _key: bytearray
    _kdf_params: kdf.KdfParams
    _locked: bool = False

    def save(self, path: str) -> None:
        if self._locked:
            raise VaultError("Session is locked.")
        envelope = self.vault.seal(bytes(self._key), self._kdf_params)
        save_envelope(path, envelope)

    def lock(self) -> None:
        """Drop the key material and the decrypted entries. Call this in
        a `finally` block so it runs even if a command raises."""
        zero(self._key)
        self.vault.entries.clear()
        self._locked = True

    @property
    def locked(self) -> bool:
        return self._locked


def prompt_secret(prompt: str) -> str:
    """Single choke point for all secret input: non-echoing, interactive
    only. Never accept secrets via argv/env (threat-model.md, M3/M4/I4)."""
    return getpass.getpass(prompt)


def check_master_password_strength(pw: str) -> None:
    """Minimal policy for M2. Rejects short or single-character-class
    passwords; a full entropy estimator (zxcvbn) is planned."""
    if len(pw) < MIN_MASTER_PASSWORD_LEN:
        raise VaultError(
            f"Master password must be at least {MIN_MASTER_PASSWORD_LEN} characters "
            "(a passphrase of several random words works well)."
        )
    if len(set(pw)) < 4:
        raise VaultError("Master password is too repetitive.")


def prompt_master_password(confirm: bool = False) -> bytearray:
    """Interactive, non-echoing password prompt. Returns a bytearray so
    the caller can zero it after use. (The `str` returned by getpass is
    immutable and cannot be wiped -- see threat-model.md, V1.)"""
    pw = prompt_secret("Master password: ")
    if confirm:
        check_master_password_strength(pw)
        if prompt_secret("Confirm master password: ") != pw:
            raise VaultError("Passwords did not match.")
    return bytearray(pw.encode("utf-8"))


def create_vault(path: str) -> None:
    """`pwmanager init` -- create a brand-new, empty vault."""
    if vault_exists(path):
        raise VaultError(f"A vault already exists at {path!r}; refusing to overwrite it.")
    password = prompt_master_password(confirm=True)
    key = bytearray()
    try:
        params = kdf.KdfParams.generate()
        key = bytearray(kdf.derive_key(bytes(password), params))
        save_envelope(path, Vault().seal(bytes(key), params))
    finally:
        zero(password)
        zero(key)


def unlock(path: str, attempts: int = MAX_UNLOCK_ATTEMPTS) -> Session:
    """Prompt for the master password and decrypt the vault into a live
    Session. The vault is only returned after the GCM tag verifies; on
    failure the user may retry up to `attempts` times (each try costs a
    full Argon2id derivation, which is the real brute-force throttle)."""
    envelope = load_envelope(path)  # StorageError if missing / not JSON
    try:
        params = kdf.KdfParams.from_dict(envelope.get("kdf") if isinstance(envelope, dict) else None)
    except kdf.KdfParamsError as exc:
        raise VaultError(f"Vault file is corrupted or unsupported: {exc}") from exc

    for attempt in range(1, attempts + 1):
        password = prompt_master_password(confirm=False)
        key = bytearray()
        try:
            key = bytearray(kdf.derive_key(bytes(password), params))
            vault = Vault.unseal(bytes(key), envelope)
        except DecryptionError:
            zero(key)
            if attempt < attempts:
                print("Wrong master password, try again.", file=sys.stderr)
                continue
            raise AuthenticationError(
                "Could not unlock vault: wrong master password, or the vault "
                "file is corrupted/tampered with."
            ) from None
        except BaseException:
            zero(key)
            raise
        finally:
            zero(password)
        return Session(vault=vault, _key=key, _kdf_params=params)
    raise AuthenticationError("Could not unlock vault.")  # attempts == 0