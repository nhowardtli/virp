"""
Mock VIRP O-Node — For testing and demos.

Simulates a real VIRP O-Node daemon without requiring actual network
devices. Responds to all VIRP protocol messages with realistic signed
observations, making it possible to test the MCP server, demo to
clients, and develop agents without a lab.

Usage:
    python -m virp_mcp.mock_onode                    # TCP on localhost:9999
    python -m virp_mcp.mock_onode --port 9998         # Custom port
    python -m virp_mcp.mock_onode --socket /tmp/virp.sock  # Unix socket

Copyright 2026 Nate Howard, Third Level IT LLC
Licensed under Apache 2.0
"""

import asyncio
import hashlib
import hmac
import json
import logging
import time
import uuid
from typing import Optional

logger = logging.getLogger("virp-mock-onode")

# ---------------------------------------------------------------------------
# Simulated device data
# ---------------------------------------------------------------------------

MOCK_DEVICES = {
    "r1": {
        "address": "10.0.0.50",
        "vendor": "cisco_ios",
        "commands": {
            "show ip bgp summary": (
                "BGP router identifier 10.0.0.50, local AS number 65001\n"
                "BGP table version is 42, main routing table version 42\n"
                "3 network entries using 744 bytes of memory\n"
                "4 path entries using 512 bytes of memory\n"
                "\n"
                "Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd\n"
                "10.0.0.51       4 65002    1842    1839       42    0    0 01:23:45        2\n"
                "10.0.0.52       4 65003    1756    1751       42    0    0 01:22:30        1\n"
            ),
            "show version": (
                "Cisco IOS Software, C3850 Software (CAT3K_CAA-UNIVERSALK9-M), "
                "Version 16.12.4, RELEASE SOFTWARE (fc5)\n"
                "System uptime is 45 days, 3 hours, 22 minutes\n"
            ),
            "show ip interface brief": (
                "Interface              IP-Address      OK? Method Status                Protocol\n"
                "GigabitEthernet1/0/1   10.0.0.50       YES NVRAM  up                    up\n"
                "GigabitEthernet1/0/2   10.0.1.1        YES NVRAM  up                    up\n"
                "GigabitEthernet1/0/3   unassigned      YES NVRAM  administratively down down\n"
                "Loopback0              10.0.255.1      YES NVRAM  up                    up\n"
            ),
        },
    },
    "r2": {
        "address": "10.0.0.51",
        "vendor": "cisco_ios",
        "commands": {
            "show ip bgp summary": (
                "BGP router identifier 10.0.0.51, local AS number 65002\n"
                "BGP table version is 38, main routing table version 38\n"
                "2 network entries using 496 bytes of memory\n"
                "\n"
                "Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd\n"
                "10.0.0.50       4 65001    1839    1842       38    0    0 01:23:45        2\n"
            ),
            "show version": (
                "Cisco IOS Software, Version 16.12.4\n"
                "System uptime is 45 days, 3 hours, 20 minutes\n"
            ),
        },
    },
    "home-fg": {
        "address": "10.0.0.1",
        "vendor": "fortinet",
        "commands": {
            "get system status": (
                "Version: FortiGate-200G v7.4.1,build2463,231219 (GA)\n"
                "Serial-Number: FG200G1234567890\n"
                "Hostname: home-fg\n"
                "Operation Mode: NAT\n"
                "Current virtual domain: root\n"
                "System time: Mon Mar 23 14:30:00 2026\n"
            ),
            "get system performance status": (
                "CPU states: 3% user 2% system 0% nice 95% idle\n"
                "Memory: 8192 MB total, 2048 MB used (25%)\n"
                "Average network usage: 45 / 120 kbps in 1 minute\n"
            ),
            "get router info bgp summary": (
                "BGP router identifier 10.0.0.1, local AS number 65000\n"
                "2 BGP AS-PATH entries\n"
                "\n"
                "Neighbor        V    AS    MsgRcvd    MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd\n"
                "10.0.0.50       4  65001       2451       2449       15    0    0 02:15:30        3\n"
            ),
        },
    },
    "pa-850": {
        "address": "10.0.0.3",
        "vendor": "paloalto",
        "commands": {
            "show system info": (
                "hostname: pa-850\n"
                "ip-address: 10.0.0.3\n"
                "model: PA-850\n"
                "serial: 012345678901\n"
                "sw-version: 11.1.2\n"
                "uptime: 32 days, 5:42:18\n"
            ),
            "show interface all": (
                "Name           ID   Speed/Duplex  Link  State\n"
                "ethernet1/1    16   1000/full      up    up\n"
                "ethernet1/2    17   1000/full      up    up\n"
                "ethernet1/3    18   auto/auto      down  down\n"
                "loopback.1     20   0/unknown      up    up\n"
            ),
        },
    },
}

# Simulated signing key (in production this is in the C library)
MOCK_HMAC_KEY = b"virp-mock-onode-demo-key-2026"


class MockONode:
    """Simulated VIRP O-Node for testing."""

    def __init__(self):
        self._sequence = 0
        self._chain: list[dict] = []
        self._session_id: Optional[str] = None
        self._start_time = time.time()
        self._node_id = "mock-onode-001"

    def _sign(self, data: str) -> str:
        """Generate HMAC-SHA256 signature."""
        return hmac.new(
            MOCK_HMAC_KEY, data.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def _next_sequence(self) -> int:
        """Increment and return next chain sequence number."""
        self._sequence += 1
        return self._sequence

    def _prev_hash(self) -> str:
        """Get hash of previous chain entry."""
        if not self._chain:
            return "0" * 64
        last = self._chain[-1]
        return hashlib.sha256(
            json.dumps(last, sort_keys=True).encode()
        ).hexdigest()

    async def handle_message(self, message: dict) -> dict:
        """Route incoming messages to the appropriate handler."""
        action = message.get("action", "")

        handlers = {
            "hello": self._handle_hello,
            "collect": self._handle_collect,
            "verify": self._handle_verify,
            "list_devices": self._handle_list_devices,
            "baseline": self._handle_baseline,
            "intent": self._handle_intent,
            "query_chain": self._handle_query_chain,
            "health": self._handle_health,
        }

        handler = handlers.get(action)
        if not handler:
            return {"status": "error", "message": f"Unknown action: {action}"}

        return await handler(message)

    async def _handle_hello(self, msg: dict) -> dict:
        """VIRP session handshake — HELLO_ACK."""
        self._session_id = str(uuid.uuid4())[:8]
        return {
            "status": "hello_ack",
            "session_id": self._session_id,
            "node_id": self._node_id,
            "version": "1.0.0-mock",
            "capabilities": ["collect", "verify", "intent", "chain", "baseline"],
        }

    async def _handle_collect(self, msg: dict) -> dict:
        """Execute command on device and return signed observation."""
        device_name = msg.get("device", "")
        command = msg.get("command", "")

        device = MOCK_DEVICES.get(device_name)
        if not device:
            return {
                "status": "error",
                "message": f"Device not registered: {device_name}",
            }

        # Find matching command output (partial match)
        output = None
        for cmd_key, cmd_output in device["commands"].items():
            if cmd_key in command or command in cmd_key:
                output = cmd_output
                break

        if output is None:
            output = f"% Unknown command: {command}\n"

        # Sign the observation
        seq = self._next_sequence()
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        sign_payload = f"{device_name}|{command}|{output}|{seq}|{timestamp}"
        observation_hmac = self._sign(sign_payload)

        # Add to chain
        entry = {
            "sequence": seq,
            "device": device_name,
            "action_type": "observation",
            "command": command,
            "hmac": observation_hmac,
            "prev_hash": self._prev_hash(),
            "timestamp": timestamp,
            "channel": "observation",
            "node_id": self._node_id,
        }
        self._chain.append(entry)

        return {
            "status": "ok",
            "output": output,
            "hmac": observation_hmac,
            "sequence": seq,
            "timestamp": timestamp,
            "trust_tier": "GREEN",
            "node_id": self._node_id,
            "verified": True,
            "channel": "observation",
        }

    async def _handle_verify(self, msg: dict) -> dict:
        """Verify an observation against the chain."""
        obs_id = msg.get("observation_id", "")
        try:
            seq = int(obs_id)
        except ValueError:
            # Try matching by HMAC
            for entry in self._chain:
                if entry["hmac"] == obs_id:
                    return {
                        "status": "ok",
                        "verified": True,
                        "chain_intact": True,
                        "hmac_valid": True,
                        "sequence_valid": True,
                        "timestamp": entry["timestamp"],
                        "detail": "Observation verified against chain.",
                    }
            return {
                "status": "ok",
                "verified": False,
                "chain_intact": True,
                "hmac_valid": False,
                "detail": f"No observation found matching: {obs_id}",
            }

        for entry in self._chain:
            if entry["sequence"] == seq:
                return {
                    "status": "ok",
                    "verified": True,
                    "chain_intact": True,
                    "hmac_valid": True,
                    "sequence_valid": True,
                    "timestamp": entry["timestamp"],
                    "detail": f"Observation #{seq} verified.",
                }

        return {
            "status": "ok",
            "verified": False,
            "chain_intact": True,
            "detail": f"Sequence #{seq} not found in chain.",
        }

    async def _handle_list_devices(self, msg: dict) -> dict:
        """Return registered devices."""
        devices = []
        for name, info in MOCK_DEVICES.items():
            obs_count = sum(1 for e in self._chain if e["device"] == name)
            last_obs = ""
            for e in reversed(self._chain):
                if e["device"] == name:
                    last_obs = e["timestamp"]
                    break

            devices.append({
                "name": name,
                "address": info["address"],
                "vendor": info["vendor"],
                "last_observation": last_obs,
                "observation_count": obs_count,
                "reachable": True,
                "trust_tier": "GREEN",
            })

        return {"status": "ok", "devices": devices}

    async def _handle_baseline(self, msg: dict) -> dict:
        """Return baseline state for a device."""
        device_name = msg.get("device", "")
        if device_name not in MOCK_DEVICES:
            return {
                "status": "ok",
                "baseline_available": False,
                "device": device_name,
            }

        obs_count = sum(1 for e in self._chain if e["device"] == device_name)
        return {
            "status": "ok",
            "baseline_available": obs_count > 0,
            "baseline_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "observation_count": obs_count,
            "deviations": [],
            "deviation_count": 0,
            "current_state": {"status": "nominal"},
        }

    async def _handle_intent(self, msg: dict) -> dict:
        """Process a proposed change intent."""
        device_name = msg.get("device", "")
        action = msg.get("intent_action", "")
        commands = msg.get("commands", [])

        # Determine trust tier based on action
        tier = "RED"  # Default to requiring approval
        action_lower = action.lower()
        if any(kw in action_lower for kw in ["show", "display", "get", "ping"]):
            tier = "GREEN"
        elif any(kw in action_lower for kw in ["restart", "snapshot", "backup"]):
            tier = "YELLOW"
        elif any(kw in action_lower for kw in ["factory", "reset", "delete key", "disable virp"]):
            tier = "BLACK"

        seq = self._next_sequence()
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        intent_id = f"INT-{seq:06d}"
        sign_payload = f"{device_name}|{action}|{json.dumps(commands)}|{seq}|{timestamp}"
        intent_hmac = self._sign(sign_payload)

        entry = {
            "sequence": seq,
            "device": device_name,
            "action_type": "intent",
            "hmac": intent_hmac,
            "prev_hash": self._prev_hash(),
            "timestamp": timestamp,
            "channel": "intent",
            "node_id": self._node_id,
        }
        self._chain.append(entry)

        approved = tier == "GREEN"
        reason = {
            "GREEN": "Auto-approved: read-only operation.",
            "YELLOW": "Flagged for review. Non-critical change logged.",
            "RED": "Requires human approval before execution.",
            "BLACK": "DENIED: Operation structurally impossible under VIRP.",
        }.get(tier, "Unknown tier.")

        return {
            "status": "ok",
            "trust_tier": tier,
            "approved": approved,
            "intent_id": intent_id,
            "hmac": intent_hmac,
            "sequence": seq,
            "timestamp": timestamp,
            "reason": reason,
            "requires_approval": tier in ("YELLOW", "RED"),
        }

    async def _handle_query_chain(self, msg: dict) -> dict:
        """Return chain entries."""
        device = msg.get("device")
        last_n = min(msg.get("last_n", 20), 100)

        entries = self._chain
        if device:
            entries = [e for e in entries if e["device"] == device]

        entries = entries[-last_n:]

        # Validate chain integrity
        for entry in entries:
            entry["chain_valid"] = True  # Mock always valid

        return {"status": "ok", "entries": entries}

    async def _handle_health(self, msg: dict) -> dict:
        """Return O-Node health status."""
        uptime = int(time.time() - self._start_time)
        return {
            "status": "ok",
            "version": "1.0.0-mock",
            "uptime_seconds": uptime,
            "total_observations": sum(
                1 for e in self._chain if e["action_type"] == "observation"
            ),
            "total_intents": sum(
                1 for e in self._chain if e["action_type"] == "intent"
            ),
            "registered_devices": len(MOCK_DEVICES),
            "chain_length": len(self._chain),
            "chain_intact": True,
        }


# ---------------------------------------------------------------------------
# TCP Server
# ---------------------------------------------------------------------------

async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    onode: MockONode,
):
    """Handle a single client connection."""
    addr = writer.get_extra_info("peername")
    logger.info("Client connected: %s", addr)

    try:
        while True:
            data = await reader.readline()
            if not data:
                break

            try:
                message = json.loads(data.decode("utf-8").strip())
                response = await onode.handle_message(message)
            except json.JSONDecodeError:
                response = {"status": "error", "message": "Invalid JSON"}

            writer.write((json.dumps(response) + "\n").encode("utf-8"))
            await writer.drain()

    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.error("Client error: %s", e)
    finally:
        writer.close()
        await writer.wait_closed()
        logger.info("Client disconnected: %s", addr)


async def run_tcp_server(host: str = "127.0.0.1", port: int = 9999):
    """Run mock O-Node as TCP server."""
    onode = MockONode()

    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, onode),
        host,
        port,
    )

    addr = server.sockets[0].getsockname()
    logger.info("Mock VIRP O-Node listening on %s:%d", addr[0], addr[1])
    logger.info(
        "Devices: %s",
        ", ".join(f"{name} ({info['vendor']})" for name, info in MOCK_DEVICES.items()),
    )

    async with server:
        await server.serve_forever()


def main():
    """Entry point for mock O-Node."""
    import argparse

    parser = argparse.ArgumentParser(description="Mock VIRP O-Node for testing")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9999, help="Bind port (default: 9999)")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    print(f"""
╔══════════════════════════════════════════════════════╗
║          VIRP Mock O-Node — For Testing Only         ║
║                                                      ║
║  This simulates a real O-Node without actual devices ║
║  Devices: r1, r2 (Cisco), home-fg (Fortinet),       ║
║           pa-850 (Palo Alto)                         ║
║                                                      ║
║  Listening on {args.host}:{args.port:<24d}       ║
╚══════════════════════════════════════════════════════╝
""")

    asyncio.run(run_tcp_server(args.host, args.port))


if __name__ == "__main__":
    main()
