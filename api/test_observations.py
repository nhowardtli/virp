"""
Concurrency tests for the in-memory observation log + LRU payload cache.

Covers:
  - observation_log is a bounded deque: never grows past MAX_LOG_SIZE.
  - list(observation_log) snapshot in /api/observations survives
    concurrent appends without RuntimeError("deque mutated during
    iteration").
  - _obs_payload_cache stays at or below _OBS_CACHE_MAX entries under
    concurrent /api/observe load, with no exceptions raised.

Run with:  pytest api/test_observations.py -v
"""

import concurrent.futures as cf
import importlib
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


TOKEN = "stress-token"


@pytest.fixture
def server(tmp_path, monkeypatch):
    devices_path = tmp_path / "devices.json"
    # Enough distinct devices that the cache has to evict before we're done.
    registry = {f"R{i}": {"host": "10.0.0.1", "driver": "cisco"}
                for i in range(200)}
    devices_path.write_text(json.dumps(registry))

    monkeypatch.setenv("VIRP_API_TOKEN", TOKEN)
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

    seq_counter = {"n": 0}
    def fake_execute(device, command, timeout=30.0):
        seq_counter["n"] += 1
        return {
            "verified": True,
            "trust_tier": "GREEN",
            "timestamp_iso": "2026-04-17T00:00:00+00:00",
            "timestamp": 0.0,
            "payload_length": 4,
            "sequence": seq_counter["n"],
            "payload": f"OK {seq_counter['n']}\n",
            "type": "OBSERVATION",
            "channel": "OBSERVATION",
            "node_id": 0,
        }
    monkeypatch.setattr(server, "onode_execute", fake_execute)

    return server


@pytest.fixture
def client(server):
    return TestClient(server.app)


def _auth():
    return {"Authorization": f"Bearer {TOKEN}"}


def test_observation_log_is_a_bounded_deque(server):
    import collections
    assert isinstance(server.observation_log, collections.deque)
    assert server.observation_log.maxlen == server.MAX_LOG_SIZE


def test_deque_enforces_hard_bound(server, client):
    # Append MAX_LOG_SIZE + 50 via the endpoint and confirm len cap.
    n = server.MAX_LOG_SIZE + 50
    for i in range(n):
        r = client.post(
            "/api/observe", headers=_auth(),
            json={"device": f"R{i % 200}", "command": "show ver"},
        )
        assert r.status_code == 200
    assert len(server.observation_log) == server.MAX_LOG_SIZE


def test_observations_endpoint_snapshots_before_iteration(server, client):
    """
    Before /api/observations slices/iterates, it must do list(deque).
    If it iterated the deque directly while another request appended,
    CPython would raise RuntimeError("deque mutated during iteration").
    Fire concurrent GETs alongside POSTs and confirm nothing crashes.
    """
    # Seed some entries first so the GETs have something to slice.
    for i in range(50):
        client.post("/api/observe", headers=_auth(),
                    json={"device": f"R{i}", "command": "show ver"})

    def do_get():
        r = client.get("/api/observations?limit=500", headers=_auth())
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data["observations"], list)
        return True

    def do_post(i):
        r = client.post("/api/observe", headers=_auth(),
                        json={"device": f"R{i % 200}", "command": "show ver"})
        assert r.status_code == 200
        return True

    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        futs = []
        for i in range(400):
            futs.append(ex.submit(do_post, i))
            if i % 3 == 0:
                futs.append(ex.submit(do_get))
        for f in futs:
            f.result()   # surface any RuntimeError from the handler


def test_cache_never_exceeds_cap_under_concurrent_observe(server, client):
    """
    Hammer /api/observe across 16 threads for enough requests that the
    cache must evict. Verify:
      - no exception escapes (the asyncio.Lock serializes writes);
      - len(cache) stays <= _OBS_CACHE_MAX throughout;
      - final len equals _OBS_CACHE_MAX (fully populated after eviction).
    """
    cap = server._OBS_CACHE_MAX
    total = cap * 4  # way past the cap so eviction definitely triggers

    def do_one(i):
        r = client.post("/api/observe", headers=_auth(),
                        json={"device": f"R{i % 200}", "command": "show ver"})
        assert r.status_code == 200
        # Probe the cache size after each request. This races the
        # writer, which is the whole point — if the bound isn't
        # enforced under the lock, this will see a value > cap.
        assert len(server._obs_payload_cache) <= cap, (
            f"cache overran cap: {len(server._obs_payload_cache)} > {cap}"
        )

    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        list(ex.map(do_one, range(total)))

    assert len(server._obs_payload_cache) == cap


def test_cache_move_to_end_updates_mru(server):
    """
    Hitting the same (device, sequence) twice should update the entry
    and mark it MRU — not duplicate it — so eviction doesn't silently
    throw away fresh data.
    """
    import asyncio
    async def run():
        await server._cache_observation("R1", 1, "p1", True)
        await server._cache_observation("R2", 1, "p2", True)
        await server._cache_observation("R1", 1, "p1-updated", True)
        # R1/1 should be MRU now; R2/1 the LRU candidate for eviction.
        keys = list(server._obs_payload_cache.keys())
        assert keys[-1] == ("R1", 1)
        assert server._obs_payload_cache[("R1", 1)]["payload"] == "p1-updated"

    asyncio.run(run())


def test_get_latest_cached_returns_highest_sequence(server):
    import asyncio
    async def run():
        await server._cache_observation("R1", 1, "old", True, timestamp=1.0)
        await server._cache_observation("R1", 5, "new", True, timestamp=5.0)
        await server._cache_observation("R1", 3, "mid", True, timestamp=3.0)
        latest = await server._get_latest_cached("R1")
        assert latest is not None
        assert latest["payload"] == "new"
        assert await server._get_latest_cached("nonexistent") is None

    asyncio.run(run())
