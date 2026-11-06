import os

import pytest

from pwmanager.crypto import cipher

KEY = os.urandom(32)


def test_roundtrip():
    blob = cipher.seal(KEY, b"secret", b"aad")
    assert cipher.unseal(KEY, blob, b"aad") == b"secret"
    assert b"secret" not in blob.ciphertext


def test_wrong_key_fails():
    blob = cipher.seal(KEY, b"secret", b"aad")
    with pytest.raises(cipher.DecryptionError):
        cipher.unseal(os.urandom(32), blob, b"aad")


def test_tampered_ciphertext_fails():
    blob = cipher.seal(KEY, b"secret", b"aad")
    flipped = bytes([blob.ciphertext[0] ^ 1]) + blob.ciphertext[1:]
    with pytest.raises(cipher.DecryptionError):
        cipher.unseal(KEY, cipher.SealedBlob(blob.nonce, flipped), b"aad")


def test_tampered_aad_fails():
    blob = cipher.seal(KEY, b"secret", b"aad")
    with pytest.raises(cipher.DecryptionError):
        cipher.unseal(KEY, blob, b"AAD")


def test_fresh_nonce_every_seal():
    nonces = {cipher.seal(KEY, b"x", b"").nonce for _ in range(200)}
    assert len(nonces) == 200