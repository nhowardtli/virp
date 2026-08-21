"""
Auth + CORS + bind-host tests for api/server.py.

Every mutating route is exercised with three auth states:
  - no token
  - wrong token
  - correct token

The onode socket client and the legacy devices.json writer are stubbed
so the tests don't need a running daemon or /etc/virp write access.

Run with:  pytest api/test_auth.py -v
"""

import importlib
import json
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


TEST_TOKEN = "s3cret-test-token"
WRONG_TOKEN = "wrong-token-same-shape"


@pytest.fixture
def server(tmp_path, monkeypatch):
    """Import api/server.py fresh with a known token and a writable devices file."""
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

    # Stub the onode client so tests don't need a live daemon.
    def fake_execute(device, command, timeout=30.0):
        return {
            "verified": True,
            "trust_tier": "GREEN",
            "timestamp_iso": "2026-04-17T00:00:00+00:00",
            "timestamp": 0.0,
            "payload_length": 4,
            "sequence": 1,
            "payload": "OK\n",
            "type": "OBSERVATION",
            "channel": "OBSERVATION",
            "node_id": 0,
        }

    def fake_batch(cmds, timeout=30.0):
        out = []
        for i, c in enumerate(cmds):
            obs = fake_execute(c["device"], c["command"], timeout)
            obs["device"] = c["device"]
            obs["command"] = c["command"]
            obs["sequence"] = i + 1
            out.append(obs)
        return out

    monkeypatch.setattr(server, "onode_execute", fake_execute)
    monkeypatch.setattr(server, "onode_batch_execute", fake_batch)

    # Force the legacy devices.json path so tests don't conflict with the
    # real devices.yaml registry that ships alongside the source tree.
    monkeypatch.setattr(server, "_USE_REGISTRY", False)

    return server


@pytest.fixture
def client(server):
    return TestClient(server.app)


# Each entry: (method, path, json_body_factory_or_None).
# body factories are callables so mutating tests get a fresh body per call.
MUTATING_ROUTES = [
    ("POST", "/api/observe", lambda: {"device": "R1", "command": "show ver"}),
    ("POST", "/api/sweep",   lambda: {"devices": ["R1"], "commands": ["show ver"]}),
    ("POST", "/api/devices/add",
        lambda: {"name": "R99", "host": "10.0.0.99", "driver": "cisco"}),
    ("DELETE", "/api/devices/R1", lambda: None),
]


def _call(client, method, path, body, token=None):
    headers = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    kwargs = {"headers": headers}
    if body is not None:
        kwargs["json"] = body
    return client.request(method, path, **kwargs)


@pytest.mark.parametrize("method,path,body_factory", MUTATING_ROUTES)
def test_no_token_rejected(client, method, path, body_factory):
    r = _call(client, method, path, body_factory())
    assert r.status_code == 401, (
        f"{method} {path} returned {r.status_code} without a token; expected 401"
    )


@pytest.mark.parametrize("method,path,body_factory", MUTATING_ROUTES)
def test_wrong_token_rejected(client, method, path, body_factory):
    r = _call(client, method, path, body_factory(), token=WRONG_TOKEN)
    assert r.status_code == 401, (
        f"{method} {path} returned {r.status_code} with a wrong token; expected 401"
    )


@pytest.mark.parametrize("method,path,body_factory", MUTATING_ROUTES)
def test_correct_token_accepted(client, server, tmp_path, monkeypatch,
                                method, path, body_factory):
    # Each add/delete test needs a fresh devices.json because the previous
    # call may have mutated it. Reset before every request.
    devices_path = Path(os.environ["VIRP_DEVICES"])
    devices_path.write_text(json.dumps({
        "R1": {"host": "10.0.0.50", "driver": "cisco"},
    }))

    r = _call(client, method, path, body_factory(), token=TEST_TOKEN)
    assert r.status_code != 401, (
        f"{method} {path} rejected the correct token: {r.status_code} {r.text}"
    )
    # Each route should produce a 2xx on the happy path with stubs in place.
    assert 200 <= r.status_code < 300, (
        f"{method} {path} unexpected status {r.status_code}: {r.text}"
    )


def test_health_is_public(client):
    r = client.get("/api/health")
    assert r.status_code == 200


def test_key_is_public(client):
    r = client.get("/api/key")
    assert r.status_code == 200


def test_cors_not_added_when_origins_unset(server):
    # With VIRP_ALLOWED_ORIGINS unset (see fixture), CORSMiddleware must
    # not be installed. Inspect the middleware stack for its presence.
    from fastapi.middleware.cors import CORSMiddleware
    installed = [m.cls for m in server.app.user_middleware]
    assert CORSMiddleware not in installed


def test_cors_added_when_origins_set(tmp_path, monkeypatch):
    monkeypatch.setenv("VIRP_API_TOKEN", TEST_TOKEN)
    monkeypatch.setenv("VIRP_DEVICES", str(tmp_path / "d.json"))
    monkeypatch.setenv("VIRP_ALLOWED_ORIGINS", "http://example.test")
    monkeypatch.setenv("VIRP_WEB_DIR", str(tmp_path / "no-web"))

    api_dir = Path(__file__).parent
    if str(api_dir) not in sys.path:
        sys.path.insert(0, str(api_dir))
    if "server" in sys.modules:
        del sys.modules["server"]
    server = importlib.import_module("server")

    from fastapi.middleware.cors import CORSMiddleware
    installed = [m.cls for m in server.app.user_middleware]
    assert CORSMiddleware in installed
    assert server.VIRP_ALLOWED_ORIGINS == ["http://example.test"]


def test_auth_noop_when_token_unset(tmp_path, monkeypatch):
    """When VIRP_API_TOKEN is empty, mutating routes are open (POC mode)."""
    monkeypatch.delenv("VIRP_API_TOKEN", raising=False)
    devices_path = tmp_path / "devices.json"
    devices_path.write_text(json.dumps({
        "R1": {"host": "10.0.0.50", "driver": "cisco"},
    }))
    monkeypatch.setenv("VIRP_DEVICES", str(devices_path))
    monkeypatch.setenv("VIRP_SOCKET", str(tmp_path / "no.sock"))
    monkeypatch.setenv("VIRP_KEY_PATH", str(tmp_path / "no.key"))
    monkeypatch.setenv("VIRP_WEB_DIR", str(tmp_path / "no-web"))

    api_dir = Path(__file__).parent
    if str(api_dir) not in sys.path:
        sys.path.insert(0, str(api_dir))
    if "server" in sys.modules:
        del sys.modules["server"]
    server = importlib.import_module("server")

    monkeypatch.setattr(server, "onode_execute",
                        lambda d, c, timeout=30.0: {
                            "verified": True, "trust_tier": "GREEN",
                            "timestamp_iso": "t", "timestamp": 0.0,
                            "payload_length": 0, "sequence": 1,
                            "payload": "", "type": "OBSERVATION",
                            "channel": "OBSERVATION", "node_id": 0,
                        })

    c = TestClient(server.app)
    r = c.post("/api/observe", json={"device": "R1", "command": "show ver"})
    assert r.status_code == 200


def test_openapi_declares_bearer_scheme(client):
    """The OpenAPI doc must advertise the bearer scheme so Swagger /docs
    renders an Authorize button (issue #8). Protected operations must
    carry the security requirement; public ones must not."""
    spec = client.get("/openapi.json").json()

    schemes = spec.get("components", {}).get("securitySchemes", {})
    assert "HTTPBearer" in schemes
    assert schemes["HTTPBearer"] == {"type": "http", "scheme": "bearer"}

    observe = spec["paths"]["/api/observe"]["post"]
    assert {"HTTPBearer": []} in observe.get("security", []), (
        "protected operation missing the HTTPBearer security requirement"
    )

    health = spec["paths"]["/api/health"]["get"]
    assert not health.get("security"), "public route must not require auth"
