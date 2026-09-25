"""Small helpers for reducing the time secrets spend in memory.

Honest caveat (see docs/threat-model.md, V1): Python strings are
immutable and the interpreter/GC can leave copies around that this
module cannot reach. Use `bytearray` for anything sensitive so it is at
least possible to overwrite it in place; avoid `str` for secrets
wherever practical.
"""
from __future__ import annotations


def zero(buf: bytearray) -> None:
    """Overwrite a bytearray in place with zeros."""
    for i in range(len(buf)):
        buf[i] = 0
