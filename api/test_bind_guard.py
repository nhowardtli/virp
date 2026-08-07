"""
Startup bind-safety guard tests for api/server.py.

The guard refuses to start when a non-loopback bind is combined with no
VIRP_API_TOKEN — that configuration would serve every mutating route
unauthenticated to the network. These tests pin the three-way matrix and
the uvicorn `--host` bypass path, at IMPORT time (the real exposure is
`uvicorn server:app --host 0.0.0.0`, which never runs __main__).

Run with:  pytest api/test_bind_guard.py -v
"""

import importlib
import sys
from pathlib import Path

import pytest


API_DIR = Path(__file__).parent


def _fresh_import(monkeypatch, *, token=None, bind_host=None, argv=None):
    """Import api/server.py fresh under a specific bind/token config.
    Returns the module, or raises whatever import raised."""
    if str(API_DIR) not in sys.path:
        sys.path.insert(0, str(API_DIR))

    monkeypatch.delenv("VIRP_API_TOKEN", raising=False)
    monkeypatch.delenv("VIRP_BIND_HOST", raising=False)
    if token is not None:
        monkeypatch.setenv("VIRP_API_TOKEN", token)
    if bind_host is not None:
        monkeypatch.setenv("VIRP_BIND_HOST", bind_host)
    # Keep the module off the filesystem web-mount path and away from a
    # real daemon socket/key.
    monkeypatch.setenv("VIRP_WEB_DIR", str(API_DIR / "no-web"))
    monkeypatch.setattr(sys, "argv", argv if argv is not None else ["pytest"])

    sys.modules.pop("server", None)
    return importlib.import_module("server")


# --- The three-way matrix --------------------------------------------------

def test_loopback_no_token_starts(monkeypatch):
    """127.0.0.1 + no token: allowed (dev mode)."""
    s = _fresh_import(monkeypatch, bind_host="127.0.0.1")
    assert s.app is not None


def test_ipv6_loopback_no_token_starts(monkeypatch):
    """::1 + no token: allowed (dev mode)."""
    s = _fresh_import(monkeypatch, bind_host="::1")
    assert s.app is not None


def test_nonloopback_no_token_refuses(monkeypatch):
    """0.0.0.0 + no token: REFUSE at import (raise, not a running app)."""
    with pytest.raises(Exception) as ei:
        _fresh_import(monkeypatch, bind_host="0.0.0.0")
    assert ei.type.__name__ == "UnsafeBindError"
    # server must not have been left importable/serving
    assert "server" not in sys.modules


def test_token_plus_nonloopback_starts(monkeypatch):
    """Token set + 0.0.0.0: allowed (operator opted into auth)."""
    s = _fresh_import(monkeypatch, token="s3cret", bind_host="0.0.0.0")
    assert s.app is not None


# --- Fail-closed / bypass coverage -----------------------------------------

def test_uvicorn_host_flag_bypass_is_caught(monkeypatch):
    """`uvicorn server:app --host 0.0.0.0` never sets VIRP_BIND_HOST — the
    guard must still refuse via argv detection."""
    with pytest.raises(Exception) as ei:
        _fresh_import(monkeypatch,
                      argv=["uvicorn", "server:app", "--host", "0.0.0.0"])
    assert ei.type.__name__ == "UnsafeBindError"


def test_gunicorn_bind_flag_bypass_is_caught(monkeypatch):
    """gunicorn `-b 0.0.0.0:8470` is caught the same way."""
    with pytest.raises(Exception) as ei:
        _fresh_import(monkeypatch,
                      argv=["gunicorn", "-b", "0.0.0.0:8470", "server:app"])
    assert ei.type.__name__ == "UnsafeBindError"


def test_hostname_is_fail_closed(monkeypatch):
    """'localhost' is a hostname, not a proven loopback IP — fail closed."""
    with pytest.raises(Exception) as ei:
        _fresh_import(monkeypatch, bind_host="localhost")
    assert ei.type.__name__ == "UnsafeBindError"


def test_routable_address_no_token_refuses(monkeypatch):
    """A concrete routable address with no token is refused."""
    with pytest.raises(Exception) as ei:
        _fresh_import(monkeypatch, bind_host="10.0.20.5")
    assert ei.type.__name__ == "UnsafeBindError"


# --- The guard's own classification (unit-level) ---------------------------

def test_loopback_classifier(monkeypatch):
    s = _fresh_import(monkeypatch, token="x")   # import safely first
    assert s._is_genuine_loopback("127.0.0.1")
    assert s._is_genuine_loopback("127.5.5.5")   # 127/8 is all loopback
    assert s._is_genuine_loopback("::1")
    assert not s._is_genuine_loopback("0.0.0.0")
    assert not s._is_genuine_loopback("::")
    assert not s._is_genuine_loopback("10.0.0.1")
    assert not s._is_genuine_loopback("localhost")
    assert not s._is_genuine_loopback("")


def test_enforce_is_the_guard_not_a_noop(monkeypatch):
    """If the guard body were removed/neutered, this direct call would not
    raise — proving the test binds to real behavior."""
    s = _fresh_import(monkeypatch, token="x")
    monkeypatch.setattr(s, "API_TOKEN", "")      # simulate no token
    with pytest.raises(s.UnsafeBindError):
        s.enforce_safe_bind(["0.0.0.0"])
    # and the safe cases do not raise
    s.enforce_safe_bind(["127.0.0.1"])
    monkeypatch.setattr(s, "API_TOKEN", "tok")
    s.enforce_safe_bind(["0.0.0.0"])
