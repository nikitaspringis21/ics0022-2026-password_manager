import os

import pytest

from pwmanager.crypto import kdf
from tests.conftest import fast_params


def test_derive_is_deterministic_and_256_bit():
    p = fast_params()
    k1 = kdf.derive_key(b"pw", p)
    assert k1 == kdf.derive_key(b"pw", p)
    assert len(k1) == 32


def test_different_salt_or_password_gives_different_key():
    p1, p2 = fast_params(), fast_params()
    assert kdf.derive_key(b"pw", p1) != kdf.derive_key(b"pw", p2)
    assert kdf.derive_key(b"pw", p1) != kdf.derive_key(b"pw2", p1)


def test_production_defaults_meet_owasp_baseline():
    p = kdf.KdfParams(salt=os.urandom(16))
    assert p.memory_cost >= 19456 and p.time_cost >= 2


def test_params_roundtrip():
    p = fast_params()
    assert kdf.KdfParams.from_dict(p.to_dict()) == p


@pytest.mark.parametrize("field,value", [
    ("memory_cost", 10 ** 9),   # DoS attempt
    ("memory_cost", 8),         # downgrade
    ("time_cost", 0),
    ("parallelism", 1000),
    ("time_cost", "3"),
    ("algorithm", "pbkdf2"),
    ("salt", "not base64!!"),
])
def test_out_of_range_or_malformed_params_rejected(field, value):
    d = fast_params().to_dict()
    d[field] = value
    with pytest.raises(kdf.KdfParamsError):
        kdf.KdfParams.from_dict(d)