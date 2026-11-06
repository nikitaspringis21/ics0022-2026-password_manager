import copy
import json
import os

import pytest

from pwmanager.crypto.cipher import DecryptionError
from pwmanager.models import Entry
from pwmanager.vault.vault import Vault, VaultError
from tests.conftest import fast_params

KEY = os.urandom(32)


def _vault():
    v = Vault()
    v.add_entry(Entry(title="GitHub", username="alice", password="hunter2-plaintext"))
    return v


def test_seal_unseal_roundtrip():
    params = fast_params()
    env = _vault().seal(KEY, params)
    v = Vault.unseal(KEY, env)
    assert v.get_entry("GitHub").password == "hunter2-plaintext"


def test_envelope_contains_no_plaintext():
    text = json.dumps(_vault().seal(KEY, fast_params()))
    for s in ("hunter2", "GitHub", "alice"):
        assert s not in text


def test_header_tampering_detected():
    env = _vault().seal(KEY, fast_params())
    bad = copy.deepcopy(env)
    bad["kdf"]["time_cost"] += 1  # still within bounds, but bound as AAD
    with pytest.raises(DecryptionError):
        Vault.unseal(KEY, bad)


@pytest.mark.parametrize("mutate", [
    lambda e: e.pop("ciphertext"),
    lambda e: e.__setitem__("version", 99),
    lambda e: e["cipher"].__setitem__("nonce", "AAAA"),
    lambda e: e["cipher"].__setitem__("algorithm", "AES-128-ECB"),
    lambda e: e.__setitem__("ciphertext", "%%%"),
])
def test_malformed_envelope_gives_vault_error(mutate):
    env = _vault().seal(KEY, fast_params())
    mutate(env)
    with pytest.raises(VaultError):
        Vault.unseal(KEY, env)


def test_duplicate_and_empty_rejected():
    v = _vault()
    with pytest.raises(VaultError):
        v.add_entry(Entry(title="GitHub", username="", password="x"))
    with pytest.raises(VaultError):
        v.add_entry(Entry(title="Other", username="", password=""))
    with pytest.raises(VaultError):
        v.add_entry(Entry(title="  ", username="", password="x"))


def test_delete_and_list():
    v = _vault()
    assert v.list_titles() == ["GitHub"]
    assert v.delete_entry("GitHub") is True
    assert v.delete_entry("GitHub") is False