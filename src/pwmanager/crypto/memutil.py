"""Small helpers for reducing the time secrets spend in memory.

Honest caveat (see docs/threat-model.md, V1): Python strings are
immutable and the interpreter/GC can leave copies around that this
module cannot reach. Use `bytearray` for anything sensitive so it is at
least possible to overwrite it in place; avoid `str` for secrets
wherever practical.
"""
from __future__ import annotations


def zero(buf: bytearray) -> None:
    """Overwrite a bytearray in place with zeros.

    Only meaningful on the *original* buffer: `zero(bytearray(x))` wipes
    a fresh copy and leaves `x` untouched, so callers must keep secrets
    in a bytearray from the start and pass that same object here.
    """
    buf[:] = bytes(len(buf))