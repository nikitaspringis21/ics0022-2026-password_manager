"""Shared fixtures.

Argon2id with production parameters takes ~0.5s per derivation, so
tests use the *minimum* parameters the vault loader accepts. The code
paths are identical; only the cost differs.
"""
from __future__ import annotations

import os

import pytest

from pwmanager.crypto import kdf
from pwmanager.vault import session as sessionmod

MASTER = "correct horse battery staple"


def fast_params() -> kdf.KdfParams:
    return kdf.KdfParams(salt=os.urandom(kdf.SALT_LEN), time_cost=kdf.MIN_TIME_COST,
                         memory_cost=kdf.MIN_MEMORY_COST_KIB, parallelism=1)


@pytest.fixture(autouse=True)
def _fast_kdf(monkeypatch):
    monkeypatch.setattr(kdf.KdfParams, "generate", classmethod(lambda cls: fast_params()))


@pytest.fixture
def prompts(monkeypatch):
    """Script the answers to secret prompts: `prompts.extend([...])`."""
    answers: list[str] = []

    def fake(prompt: str) -> str:
        if not answers:
            raise AssertionError(f"unexpected prompt: {prompt!r}")
        return answers.pop(0)

    monkeypatch.setattr(sessionmod, "prompt_secret", fake)
    return answers


@pytest.fixture
def vault_path(tmp_path):
    return str(tmp_path / "vault.json")


@pytest.fixture
def new_vault(vault_path, prompts):
    prompts.extend([MASTER, MASTER])
    sessionmod.create_vault(vault_path)
    return vault_path