"""Vault: the domain/business-logic layer.

Holds the decrypted list of Entry objects for an unlocked session and
knows how to seal itself into an on-disk envelope (via the crypto
module) and unseal an envelope back into entries. It never touches the
filesystem directly — that's the Storage layer's job.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from pwmanager.crypto import cipher, kdf
from pwmanager.models import Entry

VAULT_FORMAT_VERSION = 1


class VaultError(Exception):
    """User-facing vault error. Messages must never contain secrets."""


@dataclass
class Vault:
    entries: list[Entry] = field(default_factory=list)

    # -- entry operations -------------------------------------------------

    def add_entry(self, entry: Entry) -> None:
        if not entry.title.strip():
            raise VaultError("Entry title must not be empty.")
        if not entry.password:
            raise VaultError("Entry password must not be empty.")
        if any(e.title == entry.title for e in self.entries):
            raise VaultError(f"An entry titled {entry.title!r} already exists.")
        self.entries.append(entry)

    def get_entry(self, title: str) -> Optional[Entry]:
        return next((e for e in self.entries if e.title == title), None)

    def delete_entry(self, title: str) -> bool:
        before = len(self.entries)
        self.entries = [e for e in self.entries if e.title != title]
        return len(self.entries) != before

    def list_titles(self) -> list[str]:
        return [e.title for e in self.entries]

    # -- (de)serialisation to the plaintext-JSON layer ---------------------

    def to_bytes(self) -> bytes:
        payload = {"entries": [e.to_dict() for e in self.entries]}
        return json.dumps(payload).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "Vault":
        try:
            payload = json.loads(data.decode("utf-8"))
            return cls(entries=[Entry.from_dict(d) for d in payload["entries"]])
        except (ValueError, KeyError, TypeError) as exc:
            # Only reachable if the plaintext authenticated but has an
            # unexpected shape (e.g. written by an incompatible version).
            raise VaultError("Vault contents are not in the expected format.") from exc

    # -- seal / unseal (crypto boundary) -----------------------------------

    def seal(self, key: bytes, kdf_params: kdf.KdfParams) -> dict:
        """Encrypt this vault into the on-disk envelope format."""
        header = {
            "version": VAULT_FORMAT_VERSION,
            "kdf": kdf_params.to_dict(),
        }
        aad = json.dumps(header, sort_keys=True).encode("utf-8")
        blob = cipher.seal(key, self.to_bytes(), aad)
        return {
            **header,
            "cipher": {
                "algorithm": "AES-256-GCM",
                "nonce": _b64(blob.nonce),
            },
            "ciphertext": _b64(blob.ciphertext),
        }

    @classmethod
    def unseal(cls, key: bytes, envelope: dict) -> "Vault":
        """Decrypt an on-disk envelope back into a Vault."""
        header, blob = parse_envelope(envelope)
        aad = json.dumps(header, sort_keys=True).encode("utf-8")
        plaintext = cipher.unseal(key, blob, aad)  # DecryptionError on wrong key / tampering
        return cls.from_bytes(plaintext)


def parse_envelope(envelope: dict) -> tuple[dict, cipher.SealedBlob]:
    """Structurally validate an on-disk envelope *before* any crypto runs.

    Returns the header (used as AAD) and the sealed blob. Raises
    VaultError with a generic message on any malformed input, so a
    corrupted or hand-edited file never produces a raw traceback.
    """
    if not isinstance(envelope, dict):
        raise VaultError("Vault file is not a valid vault (unexpected structure).")
    if envelope.get("version") != VAULT_FORMAT_VERSION:
        raise VaultError("Unsupported or missing vault format version.")
    try:
        header = {"version": envelope["version"], "kdf": envelope["kdf"]}
        if envelope["cipher"]["algorithm"] != "AES-256-GCM":
            raise VaultError("Unsupported cipher in vault file.")
        nonce = _b64d(envelope["cipher"]["nonce"])
        ciphertext = _b64d(envelope["ciphertext"])
    except (KeyError, TypeError, ValueError) as exc:
        raise VaultError("Vault file is corrupted (missing or malformed fields).") from exc
    if len(nonce) != cipher.NONCE_LEN or len(ciphertext) < 16:  # 16 = GCM tag
        raise VaultError("Vault file is corrupted (bad nonce or ciphertext length).")
    return header, cipher.SealedBlob(nonce=nonce, ciphertext=ciphertext)


def _b64(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    import base64

    return base64.b64decode(data, validate=True)