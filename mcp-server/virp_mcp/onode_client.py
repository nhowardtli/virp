"""
VIRP O-Node Client — Communicates with the VIRP O-Node daemon.

The O-Node is the isolated C daemon that handles all device interaction,
HMAC signing, and chain management. This client speaks to it over TCP
or Unix socket and translates responses into Python objects.

The O-Node protocol is JSON-over-TCP with newline delimiters:
  → Client sends: {"action": "collect", "device": "r1", "command": "show ip bgp summary"}\n
  ← O-Node returns: {"status": "ok", "observation": {...}, "hmac": "...", ...}\n

Copyright 2026 Nate Howard, Third Level IT LLC
Licensed under Apache 2.0
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from virp_mcp.models import (
    ObservationResult,
    IntentResult,
    DeviceInfo,
    ChainEntry,
    TrustTier,
)

logger = logging.getLogger("virp-mcp.onode")


class ONodeConnectionError(Exception):
    """Raised when the O-Node is unreachable or returns an error."""
    pass


class ONodeProtocolError(Exception):
    """Raised when the O-Node returns an unexpected response format."""
    pass


class ONodeClient:
    """
    Async client for the VIRP O-Node daemon.

    Supports both TCP (for remote O-Node via socat bridge) and
    Unix socket (for local O-Node) connections.

    Usage:
        client = ONodeClient(host="10.0.0.211", port=9999)
        await client.connect()
        obs = await client.collect("r1", "show ip bgp summary")
        await client.disconnect()
    """

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        socket_path: Optional[str] = None,
        timeout: float = 30.0,
        max_retries: int = 3,
        retry_delay: float = 2.0,
    ):
        self.host = host
        self.port = port
        self.socket_path = socket_path
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._lock = asyncio.Lock()
        self._connected = False
        self._session_id: Optional[str] = None

    async def connect(self) -> None:
        """Establish connection to O-Node and perform session handshake."""
        for attempt in range(1, self.max_retries + 1):
            try:
                if self.socket_path:
                    self._reader, self._writer = await asyncio.wait_for(
                        asyncio.open_unix_connection(self.socket_path),
                        timeout=self.timeout,
                    )
                    logger.info("Connected to O-Node via Unix socket: %s", self.socket_path)
                elif self.host and self.port:
                    self._reader, self._writer = await asyncio.wait_for(
                        asyncio.open_connection(self.host, self.port),
                        timeout=self.timeout,
                    )
                    logger.info("Connected to O-Node via TCP: %s:%d", self.host, self.port)
                else:
                    raise ONodeConnectionError(
                        "No connection target specified. Set onode_host/onode_port "
                        "or onode_socket in config."
                    )

                # Perform VIRP session handshake (HELLO → HELLO_ACK → SESSION_BIND)
                await self._session_handshake()
                self._connected = True
                return

            except (OSError, asyncio.TimeoutError) as e:
                logger.warning(
                    "O-Node connection attempt %d/%d failed: %s",
                    attempt, self.max_retries, e,
                )
                if attempt < self.max_retries:
                    await asyncio.sleep(self.retry_delay)
                else:
                    raise ONodeConnectionError(
                        f"Failed to connect to O-Node after {self.max_retries} attempts: {e}"
                    ) from e

    async def disconnect(self) -> None:
        """Close O-Node connection."""
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
        self._connected = False
        self._session_id = None
        logger.info("Disconnected from O-Node")

    async def _session_handshake(self) -> None:
        """
        VIRP session handshake per RFC Section 4.

        State machine: HELLO → HELLO_ACK → SESSION_BIND
        """
        hello = {
            "action": "hello",
            "client": "virp-mcp-server",
            "version": "1.0",
            "capabilities": ["collect", "verify", "intent", "chain", "baseline"],
        }
        response = await self._send(hello)

        if response.get("status") != "hello_ack":
            raise ONodeProtocolError(
                f"Expected HELLO_ACK, got: {response.get('status')}"
            )

        self._session_id = response.get("session_id")
        logger.info("VIRP session established: %s", self._session_id)

    async def _send(self, message: dict) -> dict:
        """
        Send a JSON message to the O-Node and read the response.

        Protocol: JSON + newline delimiter over TCP/Unix socket.
        Thread-safe via asyncio lock.
        """
        async with self._lock:
            if not self._writer or not self._reader:
                raise ONodeConnectionError("Not connected to O-Node")

            # Inject session_id if we have one
            if self._session_id:
                message["session_id"] = self._session_id

            payload = json.dumps(message) + "\n"

            try:
                self._writer.write(payload.encode("utf-8"))
                await self._writer.drain()

                raw = await asyncio.wait_for(
                    self._reader.readline(),
                    timeout=self.timeout,
                )

                if not raw:
                    raise ONodeConnectionError("O-Node closed the connection")

                response = json.loads(raw.decode("utf-8").strip())

                if response.get("status") == "error":
                    raise ONodeProtocolError(
                        f"O-Node error: {response.get('message', 'unknown')}"
                    )

                return response

            except asyncio.TimeoutError:
                raise ONodeConnectionError(
                    f"O-Node response timed out after {self.timeout}s"
                )
            except json.JSONDecodeError as e:
                raise ONodeProtocolError(
                    f"Invalid JSON from O-Node: {e}"
                )

    async def _ensure_connected(self) -> None:
        """Reconnect if the connection was lost."""
        if not self._connected:
            await self.connect()

    # -------------------------------------------------------------------
    # Public API — maps to MCP tools
    # -------------------------------------------------------------------

    async def collect(self, device: str, command: str) -> ObservationResult:
        """
        Collect a signed observation from a device.

        The O-Node will:
        1. SSH into the device
        2. Execute the command
        3. Sign the raw output with HMAC-SHA256
        4. Store in chain.db with sequence number
        5. Return the signed observation
        """
        await self._ensure_connected()
        response = await self._send({
            "action": "collect",
            "device": device,
            "command": command,
            "channel": "observation",
        })

        return ObservationResult(
            device=device,
            command=command,
            output=response.get("output", ""),
            hmac=response.get("hmac", ""),
            sequence=response.get("sequence", 0),
            timestamp=response.get("timestamp", ""),
            trust_tier=TrustTier.from_str(response.get("trust_tier", "GREEN")),
            node_id=response.get("node_id", ""),
            verified=response.get("verified", False),
            channel=response.get("channel", "observation"),
        )

    async def verify(self, observation_id: str) -> dict:
        """Verify an observation's HMAC against chain.db."""
        await self._ensure_connected()
        response = await self._send({
            "action": "verify",
            "observation_id": observation_id,
        })
        return {
            "observation_id": observation_id,
            "verified": response.get("verified", False),
            "chain_intact": response.get("chain_intact", False),
            "hmac_valid": response.get("hmac_valid", False),
            "sequence_valid": response.get("sequence_valid", False),
            "timestamp": response.get("timestamp", ""),
            "detail": response.get("detail", ""),
        }

    async def list_devices(self) -> list[DeviceInfo]:
        """List all devices registered with the O-Node."""
        await self._ensure_connected()
        response = await self._send({"action": "list_devices"})

        devices = []
        for d in response.get("devices", []):
            devices.append(DeviceInfo(
                name=d.get("name", ""),
                address=d.get("address", ""),
                vendor=d.get("vendor", "unknown"),
                last_observation=d.get("last_observation", ""),
                observation_count=d.get("observation_count", 0),
                reachable=d.get("reachable", False),
                trust_tier=TrustTier.from_str(d.get("trust_tier", "GREEN")),
            ))
        return devices

    async def get_baseline(
        self, device: str, metric: Optional[str] = None
    ) -> dict:
        """Get baseline state and deviations for a device."""
        await self._ensure_connected()
        msg = {"action": "baseline", "device": device}
        if metric:
            msg["metric"] = metric

        response = await self._send(msg)
        return {
            "device": device,
            "baseline_available": response.get("baseline_available", False),
            "baseline_timestamp": response.get("baseline_timestamp", ""),
            "observation_count": response.get("observation_count", 0),
            "deviations": response.get("deviations", []),
            "deviation_count": response.get("deviation_count", 0),
            "current_state": response.get("current_state", {}),
            "metric": metric,
        }

    async def submit_intent(
        self,
        device: str,
        action: str,
        justification: str,
        commands: list[str],
    ) -> IntentResult:
        """Submit a proposed change as a signed VIRP Intent."""
        await self._ensure_connected()
        response = await self._send({
            "action": "intent",
            "channel": "intent",
            "device": device,
            "intent_action": action,
            "justification": justification,
            "commands": commands,
        })

        return IntentResult(
            device=device,
            action=action,
            trust_tier=TrustTier.from_str(response.get("trust_tier", "RED")),
            approved=response.get("approved", False),
            intent_id=response.get("intent_id", ""),
            hmac=response.get("hmac", ""),
            sequence=response.get("sequence", 0),
            timestamp=response.get("timestamp", ""),
            reason=response.get("reason", ""),
            requires_approval=response.get("requires_approval", True),
        )

    async def query_chain(
        self,
        device: Optional[str] = None,
        last_n: int = 20,
    ) -> list[ChainEntry]:
        """Query the VIRP audit chain."""
        await self._ensure_connected()
        msg = {"action": "query_chain", "last_n": last_n}
        if device:
            msg["device"] = device

        response = await self._send(msg)

        entries = []
        for e in response.get("entries", []):
            entries.append(ChainEntry(
                sequence=e.get("sequence", 0),
                device=e.get("device", ""),
                action_type=e.get("action_type", "observation"),
                hmac=e.get("hmac", ""),
                prev_hash=e.get("prev_hash", ""),
                timestamp=e.get("timestamp", ""),
                channel=e.get("channel", "observation"),
                chain_valid=e.get("chain_valid", False),
                node_id=e.get("node_id", ""),
            ))
        return entries

    async def health(self) -> dict:
        """Get O-Node health status."""
        await self._ensure_connected()
        response = await self._send({"action": "health"})
        return {
            "status": "connected",
            "onode_connected": True,
            "onode_version": response.get("version", "unknown"),
            "uptime_seconds": response.get("uptime_seconds", 0),
            "total_observations": response.get("total_observations", 0),
            "total_intents": response.get("total_intents", 0),
            "registered_devices": response.get("registered_devices", 0),
            "chain_length": response.get("chain_length", 0),
            "chain_intact": response.get("chain_intact", True),
            "session_id": self._session_id,
        }
