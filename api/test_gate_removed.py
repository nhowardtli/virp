"""
Test for V42 remediation — the /api/gate endpoint has been removed.

History: /api/gate was an HTTP Observation Gate on the appliance API that
trusted a client-supplied `verified: true` field without re-checking HMAC
(audit finding V42, April 2026). The endpoint was architecturally
redundant with the chain-backed verification service on virp-bridge.py
(port 9998) and had zero callers in the tree. The fix was to remove the
endpoint entirely rather than re-verify.

This test guards against accidental reintroduction.

Run with:  pytest api/test_gate_removed.py -v
"""
import importlib
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

TEST_TOKEN = "s3cret-test-token"


@pytest.fixture
def server(tmp_path, monkeypatch):
    """Import api/server.py fresh with a known token and a writable devices file.

    Mirrors the fixture in test_auth.py. Duplicated deliberately — there is
    no conftest.py in this tree; consolidation is out of scope for V42.
    """
    devices_path = tmp_path / "devices.json"
    devices_path.write_text(json.dumps({
        "R1": {"host": "10.0.0.50", "driver": "cisco"},
    }))

    monkeypatch.setenv("VIRP_API_TOKEN", TEST_TOKEN)
    monkeypatch.setenv("VIRP_DEVICES", str(devices_path))
    monkeypatch.setenv("VIRP_SOCKET", str(tmp_path / "nonexistent.sock"))
    monkeypatch.setenv("VIRP_KEY_PATH", str(tmp_path / "nonexistent.key"))
    monkeypatch.setenv("VIRP_WEB_DIR", str(tmp_path / "no-web"))
    monkeypatch.delenv("VIRP_ALLOWED_ORIGINS", raising=False)
    monkeypatch.delenv("VIRP_BIND_HOST", raising=False)

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


def test_gate_endpoint_returns_404(client):
    """POST /api/gate must not exist on the appliance API."""
    r = client.post(
        "/api/gate",
        json={"response": "R1 is up", "observations": []},
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
    )
    assert r.status_code == 404, (
        f"/api/gate returned {r.status_code}; expected 404. "
        "The gate endpoint was removed in V42 remediation and must not be "
        "reintroduced on the appliance API. Chain-backed verification lives "
        "on virp-bridge.py:9998."
    )


def test_gaterequest_model_removed(server):
    """The GateRequest pydantic model was gate-exclusive and should be gone."""
    assert not hasattr(server, "GateRequest"), (
        "server.GateRequest still exists; V42 removal was incomplete."
    )


def test_check_content_fidelity_removed(server):
    """check_content_fidelity was gate-exclusive and should be gone."""
    assert not hasattr(server, "check_content_fidelity"), (
        "server.check_content_fidelity still exists; V42 removal was incomplete."
    )
