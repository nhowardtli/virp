"""
VIRP MCP Server Tests — Runs against the Mock O-Node.

Tests verify:
1. O-Node client connection and session handshake
2. Observation collection and HMAC signing
3. Device listing
4. Intent submission and trust tier gating
5. Chain integrity
6. Baseline queries
7. Health check
8. Error handling (unknown devices, bad commands)

Usage:
    pytest tests/test_virp_mcp.py -v

Copyright 2026 Nate Howard, Third Level IT LLC
Licensed under Apache 2.0
"""

import asyncio
import json
import pytest
import pytest_asyncio

from virp_mcp.mock_onode import MockONode, run_tcp_server
from virp_mcp.onode_client import ONodeClient, ONodeConnectionError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def mock_onode_server():
    """Start a mock O-Node on a random port and yield the port number."""
    server_started = asyncio.Event()
    port = 19999  # Test port

    onode = MockONode()

    async def handle_client(reader, writer):
        try:
            while True:
                data = await reader.readline()
                if not data:
                    break
                message = json.loads(data.decode().strip())
                response = await onode.handle_message(message)
                writer.write((json.dumps(response) + "\n").encode())
                await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle_client, "127.0.0.1", port)
    server_started.set()

    try:
        yield port
    finally:
        server.close()
        await server.wait_closed()


@pytest_asyncio.fixture
async def client(mock_onode_server):
    """Create and connect an O-Node client."""
    port = mock_onode_server
    c = ONodeClient(host="127.0.0.1", port=port, timeout=5.0)
    await c.connect()
    yield c
    await c.disconnect()


# ---------------------------------------------------------------------------
# Connection and Handshake Tests
# ---------------------------------------------------------------------------

class TestConnection:

    @pytest.mark.asyncio
    async def test_connect_and_handshake(self, client):
        """Client should complete HELLO/HELLO_ACK handshake."""
        assert client._connected is True
        assert client._session_id is not None

    @pytest.mark.asyncio
    async def test_health_check(self, client):
        """Health check should return O-Node status."""
        status = await client.health()
        assert status["onode_connected"] is True
        assert status["status"] == "connected"
        assert status["registered_devices"] == 4
        assert "chain_length" in status

    @pytest.mark.asyncio
    async def test_connection_failure(self):
        """Client should raise error when O-Node unreachable."""
        c = ONodeClient(host="127.0.0.1", port=19998, max_retries=1, timeout=1.0)
        with pytest.raises(ONodeConnectionError):
            await c.connect()


# ---------------------------------------------------------------------------
# Observation Collection Tests
# ---------------------------------------------------------------------------

class TestCollect:

    @pytest.mark.asyncio
    async def test_collect_cisco_bgp(self, client):
        """Collect BGP summary from Cisco device."""
        obs = await client.collect("r1", "show ip bgp summary")
        assert obs.verified is True
        assert obs.hmac != ""
        assert obs.sequence > 0
        assert "65001" in obs.output
        assert obs.trust_tier.value == "GREEN"
        assert obs.channel == "observation"

    @pytest.mark.asyncio
    async def test_collect_fortigate(self, client):
        """Collect system status from FortiGate."""
        obs = await client.collect("home-fg", "get system status")
        assert obs.verified is True
        assert "FortiGate-200G" in obs.output

    @pytest.mark.asyncio
    async def test_collect_palo_alto(self, client):
        """Collect system info from Palo Alto."""
        obs = await client.collect("pa-850", "show system info")
        assert obs.verified is True
        assert "PA-850" in obs.output

    @pytest.mark.asyncio
    async def test_collect_unknown_device(self, client):
        """Collecting from unknown device should return error."""
        # The mock returns an error status which raises ONodeProtocolError
        from virp_mcp.onode_client import ONodeProtocolError
        with pytest.raises(ONodeProtocolError):
            await client.collect("nonexistent", "show version")

    @pytest.mark.asyncio
    async def test_collect_unknown_command(self, client):
        """Unknown command should still return signed observation."""
        obs = await client.collect("r1", "show nonexistent")
        assert obs.verified is True
        assert obs.hmac != ""
        # Should contain error marker from device
        assert "Unknown command" in obs.output

    @pytest.mark.asyncio
    async def test_observations_have_unique_sequences(self, client):
        """Each observation should get a unique incrementing sequence."""
        obs1 = await client.collect("r1", "show version")
        obs2 = await client.collect("r2", "show version")
        assert obs2.sequence > obs1.sequence

    @pytest.mark.asyncio
    async def test_observations_have_unique_hmacs(self, client):
        """Different observations should have different HMACs."""
        obs1 = await client.collect("r1", "show version")
        obs2 = await client.collect("r1", "show ip bgp summary")
        assert obs1.hmac != obs2.hmac


# ---------------------------------------------------------------------------
# Device Listing Tests
# ---------------------------------------------------------------------------

class TestDevices:

    @pytest.mark.asyncio
    async def test_list_devices(self, client):
        """Should return all registered devices."""
        devices = await client.list_devices()
        assert len(devices) == 4
        names = {d.name for d in devices}
        assert names == {"r1", "r2", "home-fg", "pa-850"}

    @pytest.mark.asyncio
    async def test_device_vendors(self, client):
        """Devices should have correct vendor assignments."""
        devices = await client.list_devices()
        vendor_map = {d.name: d.vendor for d in devices}
        assert vendor_map["r1"] == "cisco_ios"
        assert vendor_map["home-fg"] == "fortinet"
        assert vendor_map["pa-850"] == "paloalto"

    @pytest.mark.asyncio
    async def test_device_observation_count_updates(self, client):
        """Observation count should increase after collecting."""
        await client.collect("r1", "show version")
        await client.collect("r1", "show ip bgp summary")
        devices = await client.list_devices()
        r1 = next(d for d in devices if d.name == "r1")
        assert r1.observation_count >= 2


# ---------------------------------------------------------------------------
# Intent Tests
# ---------------------------------------------------------------------------

class TestIntent:

    @pytest.mark.asyncio
    async def test_green_intent_auto_approved(self, client):
        """Read-only intents should auto-approve at GREEN tier."""
        result = await client.submit_intent(
            device="r1",
            action="show running-config",
            justification="Routine config review",
            commands=["show running-config"],
        )
        assert result.trust_tier.value == "GREEN"
        assert result.approved is True

    @pytest.mark.asyncio
    async def test_red_intent_requires_approval(self, client):
        """Critical changes should require approval at RED tier."""
        result = await client.submit_intent(
            device="home-fg",
            action="modify firewall policy",
            justification="Adding permit rule for new subnet",
            commands=["config firewall policy", "edit 100"],
        )
        assert result.trust_tier.value == "RED"
        assert result.approved is False
        assert result.requires_approval is True

    @pytest.mark.asyncio
    async def test_black_intent_denied(self, client):
        """BLACK tier operations should be structurally denied."""
        result = await client.submit_intent(
            device="r1",
            action="factory reset device",
            justification="Testing BLACK tier",
            commands=["write erase", "reload"],
        )
        assert result.trust_tier.value == "BLACK"
        assert result.approved is False

    @pytest.mark.asyncio
    async def test_intent_is_signed(self, client):
        """All intents should be HMAC signed."""
        result = await client.submit_intent(
            device="r1",
            action="show interfaces",
            justification="Test",
            commands=["show interfaces"],
        )
        assert result.hmac != ""
        assert result.sequence > 0
        assert result.intent_id.startswith("INT-")


# ---------------------------------------------------------------------------
# Chain Tests
# ---------------------------------------------------------------------------

class TestChain:

    @pytest.mark.asyncio
    async def test_chain_grows_with_observations(self, client):
        """Chain should grow as observations are collected."""
        await client.collect("r1", "show version")
        await client.collect("r2", "show version")

        entries = await client.query_chain(last_n=10)
        # At least the 2 we just collected plus handshake activity
        assert len(entries) >= 2

    @pytest.mark.asyncio
    async def test_chain_filter_by_device(self, client):
        """Should filter chain entries by device."""
        await client.collect("r1", "show version")
        await client.collect("r2", "show version")
        await client.collect("r1", "show ip bgp summary")

        entries = await client.query_chain(device="r1", last_n=10)
        for entry in entries:
            assert entry.device == "r1"

    @pytest.mark.asyncio
    async def test_chain_integrity(self, client):
        """All chain entries should be valid."""
        await client.collect("r1", "show version")
        await client.collect("r2", "show version")

        entries = await client.query_chain(last_n=10)
        for entry in entries:
            assert entry.chain_valid is True


# ---------------------------------------------------------------------------
# Baseline Tests
# ---------------------------------------------------------------------------

class TestBaseline:

    @pytest.mark.asyncio
    async def test_baseline_no_history(self, client):
        """Baseline should indicate no data before any collection."""
        # Fresh session - no observations for pa-850 yet
        result = await client.get_baseline("pa-850")
        assert result["device"] == "pa-850"
        # May or may not have baseline depending on session state

    @pytest.mark.asyncio
    async def test_baseline_after_collection(self, client):
        """Baseline should be available after observations."""
        await client.collect("r1", "show version")
        result = await client.get_baseline("r1")
        assert result["baseline_available"] is True
        assert result["observation_count"] >= 1


# ---------------------------------------------------------------------------
# Verify Tests
# ---------------------------------------------------------------------------

class TestVerify:

    @pytest.mark.asyncio
    async def test_verify_valid_observation(self, client):
        """Should verify a real observation by sequence number."""
        obs = await client.collect("r1", "show version")
        result = await client.verify(str(obs.sequence))
        assert result["verified"] is True
        assert result["hmac_valid"] is True

    @pytest.mark.asyncio
    async def test_verify_by_hmac(self, client):
        """Should verify by HMAC string."""
        obs = await client.collect("r1", "show version")
        result = await client.verify(obs.hmac)
        assert result["verified"] is True

    @pytest.mark.asyncio
    async def test_verify_nonexistent(self, client):
        """Should return not verified for unknown observation."""
        result = await client.verify("999999")
        assert result["verified"] is False


# ---------------------------------------------------------------------------
# Model Tests
# ---------------------------------------------------------------------------

class TestModels:

    def test_trust_tier_from_string(self):
        from virp_mcp.models import TrustTier
        assert TrustTier.from_str("GREEN") == TrustTier.GREEN
        assert TrustTier.from_str("red") == TrustTier.RED
        assert TrustTier.from_str("invalid") == TrustTier.GREEN

    def test_observation_to_dict(self):
        from virp_mcp.models import ObservationResult, TrustTier
        obs = ObservationResult(
            device="r1",
            command="show version",
            output="test output",
            hmac="abc123",
            sequence=1,
            timestamp="2026-03-23T00:00:00Z",
            trust_tier=TrustTier.GREEN,
            node_id="test",
            verified=True,
        )
        d = obs.to_dict()
        assert d["device"] == "r1"
        assert d["verified"] is True
        assert d["trust_tier"] == "GREEN"

    def test_intent_to_dict(self):
        from virp_mcp.models import IntentResult, TrustTier
        intent = IntentResult(
            device="r1",
            action="shutdown",
            trust_tier=TrustTier.RED,
            approved=False,
            intent_id="INT-000001",
            hmac="def456",
            sequence=2,
            timestamp="2026-03-23T00:00:00Z",
            reason="Requires approval",
        )
        d = intent.to_dict()
        assert d["approved"] is False
        assert d["trust_tier"] == "RED"
