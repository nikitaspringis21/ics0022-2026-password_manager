"""Key derivation: master password -> 256-bit key, via Argon2id.

This module never sees a vault, a file, or plaintext entries. It only
turns (password, salt, params) into raw key bytes. Keep it that way so
it stays trivially unit-testable.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw

KEY_LEN = 32  # 256-bit key for AES-256
SALT_LEN = 16  # 128-bit salt

# OWASP baseline starting point; retune after benchmarking (see
# docs/design-decisions.md, section 3).
DEFAULT_TIME_COST = 3
DEFAULT_MEMORY_COST_KIB = 65536  # 64 MB
DEFAULT_PARALLELISM = 4


@dataclass(frozen=True)
class KdfParams:
    salt: bytes
    time_cost: int = DEFAULT_TIME_COST
    memory_cost: int = DEFAULT_MEMORY_COST_KIB
    parallelism: int = DEFAULT_PARALLELISM

    def to_dict(self) -> dict:
        import base64

        return {
            "algorithm": "argon2id",
            "salt": base64.b64encode(self.salt).decode("ascii"),
            "time_cost": self.time_cost,
            "memory_cost": self.memory_cost,
            "parallelism": self.parallelism,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "KdfParams":
        import base64

        if data.get("algorithm") != "argon2id":
            raise ValueError(f"Unsupported KDF algorithm: {data.get('algorithm')!r}")
        return cls(
            salt=base64.b64decode(data["salt"]),
            time_cost=data["time_cost"],
            memory_cost=data["memory_cost"],
            parallelism=data["parallelism"],
        )

    @classmethod
    def generate(cls) -> "KdfParams":
        return cls(salt=os.urandom(SALT_LEN))


def derive_key(password: bytes, params: KdfParams) -> bytes:
    """Derive a 256-bit key from the master password.

    `password` should be bytes (encode as UTF-8 at the call site) so the
    caller controls the buffer's lifetime and can zero it afterwards.
    """
    return hash_secret_raw(
        secret=password,
        salt=params.salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=KEY_LEN,
        type=Type.ID,  # Argon2id
    )
