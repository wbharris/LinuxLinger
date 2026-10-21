import os

import pytest

from linux_linger.util import data_dir, ensure_private_dir, write_private_file


def test_data_dir_is_owner_only(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    path = data_dir()
    assert path == tmp_path / "linux-linger"
    assert path.is_dir()
    assert not path.is_symlink()
    assert path.stat().st_mode & 0o777 == 0o700
    assert path.stat().st_uid == os.geteuid()


def test_data_dir_tightens_existing_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    linger = tmp_path / "linux-linger"
    linger.mkdir()
    linger.chmod(0o755)
    data_dir()
    assert linger.stat().st_mode & 0o777 == 0o700


def test_data_dir_rejects_symlink(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "linux-linger").symlink_to(real)
    with pytest.raises(PermissionError, match="symlink"):
        data_dir()


def test_write_private_file_mode_and_replaces_symlink(tmp_path):
    decoy = tmp_path / "decoy"
    decoy.write_text("secret", encoding="utf-8")
    dest = tmp_path / "report.html"
    dest.symlink_to(decoy)
    write_private_file(dest, "<html>ok</html>\n", mode=0o600)
    assert dest.is_file()
    assert not dest.is_symlink()
    assert dest.read_text(encoding="utf-8") == "<html>ok</html>\n"
    assert dest.stat().st_mode & 0o777 == 0o600
    assert decoy.read_text(encoding="utf-8") == "secret"


def test_ensure_private_dir_rejects_file(tmp_path):
    path = tmp_path / "notdir"
    path.write_text("x", encoding="utf-8")
    with pytest.raises(PermissionError, match="not a directory"):
        ensure_private_dir(path)
