"""
Tests for /api/devices/add + /api/devices/{name} DELETE hardening:

  - asyncio lock + atomic write (no torn writes, no races)
  - host validation (IP, hostname, junk rejected)
  - driver allow-list
  - credential fields refused (extra='forbid')
  - audit log line on every mutation
  - default DEVICES_PATH moved to /var/lib/virp/devices.json

Run with:  pytest api/test_devices.py -v
"""

import asyncio
import importlib
import json
import os
import sys
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


TEST_TOKEN = "test-token"


@pytest.fixture
def server(tmp_path, monkeypatch):
    devices_path = tmp_path / "devices.json"
    devices_path.write_text(json.dumps({"R1": {"host": "10.0.0.50", "driver": "cisco"}}))

    monkeypatch.setenv("VIRP_API_TOKEN", TEST_TOKEN)
    monkeypatch.setenv("VIRP_DEVICES", str(devices_path))
    monkeypatch.setenv("VIRP_SOCKET", str(tmp_path / "no.sock"))
    monkeypatch.setenv("VIRP_KEY_PATH", str(tmp_path / "no.key"))
    monkeypatch.setenv("VIRP_WEB_DIR", str(tmp_path / "no-web"))
    monkeypatch.delenv("VIRP_ALLOWED_ORIGINS", raising=False)

    api_dir = Path(__file__).parent
    if str(api_dir) not in sys.path:
        sys.path.insert(0, str(api_dir))
    if "server" in sys.modules:
        del sys.modules["server"]
    server = importlib.import_module("server")
    monkeypatch.setattr(server, "_HAVE_REGISTRY", False)
    return server


@pytest.fixture
def client(server):
    return TestClient(server.app)


def _auth():
    return {"Authorization": f"Bearer {TEST_TOKEN}"}


# ---- default path moved ------------------------------------------------------

def test_default_devices_path_is_var_lib(monkeypatch):
    monkeypatch.delenv("VIRP_DEVICES", raising=False)
    api_dir = Path(__file__).parent
    if str(api_dir) not in sys.path:
        sys.path.insert(0, str(api_dir))
    if "server" in sys.modules:
        del sys.modules["server"]
    server = importlib.import_module("server")
    assert server.DEVICES_PATH == "/var/lib/virp/devices.json"


# ---- host validation ---------------------------------------------------------

@pytest.mark.parametrize("host", [
    "10.0.0.1", "192.168.1.100", "::1", "2001:db8::1",
    "r1.lab.internal", "router-9", "host123",
])
def test_add_accepts_valid_host(client, host):
    r = client.post("/api/devices/add", headers=_auth(), json={
        "name": "Rtest", "host": host, "driver": "cisco",
    })
    assert r.status_code == 200, r.text


@pytest.mark.parametrize("host", [
    "10.0.0.1; rm -rf /",
    "'; DROP TABLE devices--",
    "host with spaces",
    "not_a_host!",
    "-leading-hyphen",
    "trailing-hyphen-",
    "",
    "a" * 300,
    "../../../etc/passwd",
    "host\nname",
])
def test_add_rejects_bad_host(client, host):
    r = client.post("/api/devices/add", headers=_auth(), json={
        "name": "Rbad", "host": host, "driver": "cisco",
    })
    assert r.status_code == 422, f"{host!r} should have been rejected: {r.text}"


# ---- driver allow-list -------------------------------------------------------

@pytest.mark.parametrize("driver", [
    "cisco", "cisco_asa", "fortigate", "panos", "linux",
    "juniper", "windows", "proxmox", "wazuh",
])
def test_add_accepts_allowlisted_drivers(client, driver):
    r = client.post("/api/devices/add", headers=_auth(), json={
        "name": "Rtest", "host": "10.0.0.1", "driver": driver,
    })
    assert r.status_code == 200, r.text


@pytest.mark.parametrize("driver", [
    "ssh-brute",         # not in allowlist
    "",
    "CISCO",             # case-sensitive allowlist
    "cisco; evil",
    "generic",
])
def test_add_rejects_bad_driver(client, driver):
    r = client.post("/api/devices/add", headers=_auth(), json={
        "name": "Rbad", "host": "10.0.0.1", "driver": driver,
    })
    assert r.status_code == 422


# ---- credential fields forbidden --------------------------------------------

@pytest.mark.parametrize("bad_field", ["password", "enable", "username", "secret"])
def test_add_rejects_credential_fields(client, bad_field):
    r = client.post("/api/devices/add", headers=_auth(), json={
        "name": "Rtest", "host": "10.0.0.1", "driver": "cisco",
        bad_field: "hunter2",
    })
    assert r.status_code == 422, (
        f"Expected credential field {bad_field!r} to be rejected"
    )


# ---- atomic write ------------------------------------------------------------

def test_atomic_write_leaves_no_tmp(client, server):
    r = client.post("/api/devices/add", headers=_auth(), json={
        "name": "Ratomic", "host": "10.0.0.99", "driver": "cisco",
    })
    assert r.status_code == 200
    parent = Path(os.environ["VIRP_DEVICES"]).parent
    stray = [p.name for p in parent.iterdir() if p.name.startswith(".devices-")]
    assert not stray, f"temp file(s) left behind: {stray}"


def test_atomic_write_preserves_on_concurrent_read(client, server, tmp_path):
    """
    While one thread is adding, another reading the file directly must
    always see EITHER the pre-write state OR the post-write state —
    never a truncated mid-write file. os.replace provides this.
    """
    path = Path(os.environ["VIRP_DEVICES"])
    stop = threading.Event()
    reader_errors = []

    def reader():
        while not stop.is_set():
            try:
                raw = path.read_text()
                if raw:
                    json.loads(raw)   # must always parse as valid JSON
            except Exception as e:
                reader_errors.append(e)

    t = threading.Thread(target=reader)
    t.start()
    try:
        for i in range(30):
            r = client.post("/api/devices/add", headers=_auth(), json={
                "name": f"Rconc{i}", "host": "10.0.0.1", "driver": "cisco",
            })
            assert r.status_code == 200
    finally:
        stop.set()
        t.join(timeout=2)

    assert not reader_errors, f"concurrent reader saw torn file: {reader_errors}"


# ---- asyncio lock actually serializes writes --------------------------------

def test_parallel_adds_do_not_lose_entries(client, server):
    """
    Fire 20 concurrent add requests (different device names). With the
    unlocked old code, concurrent read-modify-writes lost entries
    because they each read the same `raw` dict and the later write
    clobbered the earlier. The async lock means every add must land.
    """
    import concurrent.futures as cf
    with cf.ThreadPoolExecutor(max_workers=20) as ex:
        futs = [ex.submit(
            client.post, "/api/devices/add",
            headers=_auth(),
            json={"name": f"Rpar{i}", "host": "10.0.0.1", "driver": "cisco"},
        ) for i in range(20)]
        for f in futs:
            assert f.result().status_code == 200

    raw = json.loads(Path(os.environ["VIRP_DEVICES"]).read_text())
    for i in range(20):
        assert f"Rpar{i}" in raw, f"lost entry Rpar{i} under concurrent adds"


# ---- audit logging -----------------------------------------------------------

def test_add_emits_audit_log(client, server, caplog):
    caplog.set_level("INFO", logger="virp.audit")
    r = client.post("/api/devices/add", headers=_auth(), json={
        "name": "Raudit", "host": "10.0.0.42", "driver": "cisco",
    })
    assert r.status_code == 200
    messages = [rec.getMessage() for rec in caplog.records
                if rec.name == "virp.audit"]
    assert any("device.add" in m and "Raudit" in m and "token:" in m
               for m in messages), messages


def test_delete_emits_audit_log(client, server, caplog):
    caplog.set_level("INFO", logger="virp.audit")
    r = client.delete("/api/devices/R1", headers=_auth())
    assert r.status_code == 200
    messages = [rec.getMessage() for rec in caplog.records
                if rec.name == "virp.audit"]
    assert any("device.remove" in m and "R1" in m and "token:" in m
               for m in messages), messages


# ---- DELETE ----------------------------------------------------------------

def test_delete_missing_returns_404(client, server):
    r = client.delete("/api/devices/does-not-exist", headers=_auth())
    assert r.status_code == 404


def test_delete_actually_removes(client, server):
    r = client.delete("/api/devices/R1", headers=_auth())
    assert r.status_code == 200
    raw = json.loads(Path(os.environ["VIRP_DEVICES"]).read_text())
    assert "R1" not in raw
