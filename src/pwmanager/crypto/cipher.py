"""Authenticated encryption: AES-256-GCM seal / unseal.

Pure bytes-in, bytes-out. No file I/O, no knowledge of "entries".
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12  # 96 bits, the standard/recommended size for GCM


class DecryptionError(Exception):
    """Raised when ciphertext fails authentication (wrong password,
    corrupted file, or tampering). Deliberately generic — never reveals
    *why* decryption failed."""


@dataclass(frozen=True)
class SealedBlob:
    nonce: bytes
    ciphertext: bytes  # GCM tag is appended by AESGCM automatically


def seal(key: bytes, plaintext: bytes, associated_data: bytes) -> SealedBlob:
    """Encrypt+authenticate `plaintext`. `associated_data` (e.g. the
    serialized KDF header) is authenticated but not encrypted, so
    tampering with it is also detected on unseal."""
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return SealedBlob(nonce=nonce, ciphertext=ciphertext)


def unseal(key: bytes, blob: SealedBlob, associated_data: bytes) -> bytes:
    """Decrypt+verify. Raises DecryptionError on any failure — wrong
    key, corrupted ciphertext, or mismatched associated_data."""
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(blob.nonce, blob.ciphertext, associated_data)
    except InvalidTag as exc:
        raise DecryptionError(
            "Could not decrypt vault: wrong master password, or the "
            "vault file is corrupted/tampered with."
        ) from exc
