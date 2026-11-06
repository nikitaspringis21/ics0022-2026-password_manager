import os
import stat

import pytest

from pwmanager.storage.file_storage import (StorageError, load_envelope,
                                            permissions_too_open, save_envelope)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_saved_file_is_owner_only(tmp_path):
    p = tmp_path / "v.json"
    save_envelope(str(p), {"a": 1})
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert not permissions_too_open(str(p))
    os.chmod(p, 0o644)
    assert permissions_too_open(str(p))


def test_atomic_write_leaves_no_temp_files(tmp_path):
    p = tmp_path / "v.json"
    save_envelope(str(p), {"a": 1})
    save_envelope(str(p), {"a": 2})
    assert load_envelope(str(p)) == {"a": 2}
    assert [f.name for f in tmp_path.iterdir()] == ["v.json"]


def test_missing_file(tmp_path):
    with pytest.raises(StorageError, match="No vault found"):
        load_envelope(str(tmp_path / "nope.json"))


def test_not_json(tmp_path):
    p = tmp_path / "v.json"
    p.write_text("garbage")
    with pytest.raises(StorageError, match="corrupted"):
        load_envelope(str(p))