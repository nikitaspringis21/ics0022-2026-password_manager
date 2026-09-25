"""Domain model for a single vault entry.

This module has no crypto and no file I/O in it on purpose — it is just
the shape of the data that the Vault module encrypts as a whole.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Entry:
    """A single credential stored in the vault."""

    title: str
    username: str
    password: str
    url: str = ""
    notes: str = ""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Entry":
        return cls(**data)
