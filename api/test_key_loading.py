"""
Tests for api/server.py load_okey() permission gate. Mirrors the C
daemon's virp_key_load_file hardening so the API server and the
daemon either both accept a key file or both reject it — never a
split where one trusts it and the other doesn't.

Run with:  pytest api/test_key_loading.py -v
"""

import importlib
import os
import sys
from pathlib import Path

import pytest


VIRP_KEY_SIZE = 32
GOOD_KEY = b"\xAB" * VIRP_KEY_SIZE


def _fresh_server(tmp_path, monkeypatch, key_path=None):
    monkeypatch.setenv("VIRP_API_TOKEN", "test")
    monkeypatch.setenv("VIRP_DEVICES", str(tmp_path / "devices.json"))
    monkeypatch.setenv("VIRP_SOCKET", str(tmp_path / "no.sock"))
    if key_path is not None:
        monkeypatch.setenv("VIRP_KEY_PATH", str(key_path))
    monkeypatch.setenv("VIRP_WEB_DIR", str(tmp_path / "no-web"))
    monkeypatch.delenv("VIRP_ALLOWED_ORIGINS", raising=False)

    api_dir = Path(__file__).parent
    if str(api_dir) not in sys.path:
        sys.path.insert(0, str(api_dir))
    if "server" in sys.modules:
        del sys.modules["server"]
    return importlib.import_module("server")


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o666, 0o777, 0o755])
def test_load_okey_rejects_insecure_mode(tmp_path, monkeypatch, mode, capsys):
    """A key file with any group/other bit set must be refused —
    mirror of the C gate. The C daemon's `chmod 0600` hint is
    reproduced in the Python message."""
    key_path = tmp_path / "okey.bin"
    key_path.write_bytes(GOOD_KEY)
    os.chmod(key_path, mode)

    server = _fresh_server(tmp_path, monkeypatch, key_path=key_path)
    ok = server.load_okey()

    assert ok is False, f"load_okey should refuse mode 0o{mode:o}"
    assert server.key_material is None
    err = capsys.readouterr().out
    assert f"0o{mode:o}" in err or f"insecure mode" in err
    assert "chmod 0600" in err


@pytest.mark.parametrize("mode", [0o400, 0o600])
def test_load_okey_accepts_safe_mode(tmp_path, monkeypatch, mode):
    key_path = tmp_path / "okey.bin"
    key_path.write_bytes(GOOD_KEY)
    os.chmod(key_path, mode)

    server = _fresh_server(tmp_path, monkeypatch, key_path=key_path)
    ok = server.load_okey()
    assert ok is True, f"load_okey should accept mode 0o{mode:o}"
    assert server.key_material == GOOD_KEY
    # Fingerprint is sha256[:16] of the key material
    import hashlib
    assert server.key_fingerprint == hashlib.sha256(GOOD_KEY).hexdigest()[:16]


def test_load_okey_rejects_symlink(tmp_path, monkeypatch, capsys):
    target = tmp_path / "okey-target.bin"
    target.write_bytes(GOOD_KEY)
    os.chmod(target, 0o600)

    link = tmp_path / "okey.bin"
    os.symlink(target, link)

    server = _fresh_server(tmp_path, monkeypatch, key_path=link)
    ok = server.load_okey()
    assert ok is False
    err = capsys.readouterr().out
    assert "symlink" in err


def test_load_okey_warns_no_file(tmp_path, monkeypatch, capsys):
    """Absent key file → demo mode (returns False, no crash)."""
    key_path = tmp_path / "missing.bin"
    server = _fresh_server(tmp_path, monkeypatch, key_path=key_path)
    ok = server.load_okey()
    assert ok is False
    err = capsys.readouterr().out
    assert "not found" in err


def test_load_okey_rejects_wrong_size(tmp_path, monkeypatch, capsys):
    key_path = tmp_path / "okey.bin"
    key_path.write_bytes(b"X" * (VIRP_KEY_SIZE - 4))  # truncated
    os.chmod(key_path, 0o600)

    server = _fresh_server(tmp_path, monkeypatch, key_path=key_path)
    ok = server.load_okey()
    assert ok is False
    err = capsys.readouterr().out
    assert "Expected 32-byte key" in err or "byte key" in err


def test_coredump_filter_probe_runs(capsys):
    """Just exercise the probe — on CI it may not warn, but must not raise."""
    api_dir = Path(__file__).parent
    if str(api_dir) not in sys.path:
        sys.path.insert(0, str(api_dir))
    if "server" in sys.modules:
        del sys.modules["server"]
    server = importlib.import_module("server")
    server._probe_coredump_filter()  # must not raise
