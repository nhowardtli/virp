"""Duplicate device identity rejection in the Python registry.

Counterpart of the C-side onode_add_device()/load_devices() duplicate
checks: devices.yaml keyed by hostname silently collapsed duplicate
hostname keys (YAML last-wins), and duplicate node_ids silently
overwrote each other in node_id_to_hostname()'s int map — both are
identity collisions that must fail closed at load.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import device_registry as dr


def _load(tmp_path, monkeypatch, text):
    p = tmp_path / "devices.yaml"
    p.write_text(text)
    monkeypatch.setattr(dr, "DEVICES_YAML", p)
    monkeypatch.setattr(dr, "_cache", None)
    monkeypatch.setattr(dr, "_cache_mtime", 0.0)
    return dr.load_devices(force_reload=True)


def test_duplicate_hostname_key_rejected(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="duplicate key 'r1'"):
        _load(tmp_path, monkeypatch,
              "r1:\n  host: 10.0.0.1\n  node_id: '01010101'\n"
              "r1:\n  host: 10.0.0.2\n  node_id: '02020202'\n")


def test_duplicate_node_id_rejected(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="duplicate node_id"):
        _load(tmp_path, monkeypatch,
              "r1:\n  host: 10.0.0.1\n  node_id: '01010101'\n"
              "r2:\n  host: 10.0.0.2\n  node_id: '01010101'\n")


def test_duplicate_node_id_differing_spelling_rejected(tmp_path, monkeypatch):
    # Same integer id in different hex spellings must still collide.
    with pytest.raises(ValueError, match="duplicate node_id"):
        _load(tmp_path, monkeypatch,
              "r1:\n  host: 10.0.0.1\n  node_id: '01010101'\n"
              "r2:\n  host: 10.0.0.2\n  node_id: '1010101'\n")


def test_unique_config_loads(tmp_path, monkeypatch):
    devices = _load(tmp_path, monkeypatch,
                    "r1:\n  host: 10.0.0.1\n  node_id: '01010101'\n"
                    "r2:\n  host: 10.0.0.2\n  node_id: '02020202'\n")
    assert set(devices) == {"r1", "r2"}


def test_absent_node_ids_do_not_collide(tmp_path, monkeypatch):
    # No node_id = never routed by id; hostname (unique by the strict
    # loader) remains the lookup key. Two such devices are legal.
    devices = _load(tmp_path, monkeypatch,
                    "r1:\n  host: 10.0.0.1\n"
                    "r2:\n  host: 10.0.0.2\n")
    assert set(devices) == {"r1", "r2"}
