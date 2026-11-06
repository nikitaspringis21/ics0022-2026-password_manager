import pytest

from pwmanager.vault import session as sessionmod
from pwmanager.vault.vault import VaultError
from tests.conftest import MASTER


def test_unlock_with_correct_password(new_vault, prompts):
    prompts.append(MASTER)
    sess = sessionmod.unlock(new_vault)
    assert sess.vault.entries == []
    sess.lock()


def test_wrong_password_never_unlocks(new_vault, prompts):
    prompts.extend(["wrong-1", "wrong-2", "wrong-3"])
    with pytest.raises(sessionmod.AuthenticationError):
        sessionmod.unlock(new_vault)
    assert prompts == []  # exactly 3 attempts used


def test_retry_then_success(new_vault, prompts):
    prompts.extend(["typo", MASTER])
    sessionmod.unlock(new_vault).lock()


def test_lock_wipes_key_and_entries(new_vault, prompts):
    prompts.append(MASTER)
    sess = sessionmod.unlock(new_vault)
    key = sess._key
    sess.lock()
    assert key == bytearray(len(key)) and sess.locked
    with pytest.raises(VaultError):
        sess.save(new_vault)


@pytest.mark.parametrize("weak", ["short", "aaaaaaaaaaaaaaaa"])
def test_weak_master_password_rejected(vault_path, prompts, weak):
    prompts.extend([weak, weak])
    with pytest.raises(VaultError):
        sessionmod.create_vault(vault_path)


def test_mismatched_confirmation_rejected(vault_path, prompts):
    prompts.extend([MASTER, MASTER + "x"])
    with pytest.raises(VaultError):
        sessionmod.create_vault(vault_path)


def test_init_refuses_to_overwrite(new_vault, prompts):
    with pytest.raises(VaultError):
        sessionmod.create_vault(new_vault)


def test_zero_wipes_original_buffer():
    from pwmanager.crypto.memutil import zero
    buf = bytearray(b"secret")
    zero(buf)
    assert buf == bytearray(6)