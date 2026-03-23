"""
VIRP MCP Server — Cryptographic trust primitives for any AI agent.

Exposes VIRP (Verified Infrastructure Response Protocol) operations as
standard MCP tools. Any MCP-compatible client (Claude, GPT, Ollama,
OpenClaw, h-cli, etc.) can connect and get signed, verified observations
from network infrastructure.

This server is a translation layer: it accepts MCP tool calls, forwards
them to the VIRP O-Node over TCP/Unix socket, and returns cryptographically
signed results. The O-Node does all signing — this server never touches keys.

Copyright 2026 Nate Howard, Third Level IT LLC
Licensed under Apache 2.0
"""

import asyncio
import json
import logging
import os
from dataclasses import dataclass
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from typing import Optional

from mcp.server.fastmcp import FastMCP, Context

from virp_mcp.onode_client import ONodeClient, ONodeConnectionError
from virp_mcp.config import VIRPConfig, load_config
from virp_mcp.models import (
    TrustTier,
    ObservationResult,
    IntentResult,
    DeviceInfo,
    ChainEntry,
)

logger = logging.getLogger("virp-mcp")

# ---------------------------------------------------------------------------
# Lifespan: connect to O-Node on startup, disconnect on shutdown
# ---------------------------------------------------------------------------

@dataclass
class AppContext:
    """Typed context available to all tools."""
    onode: ONodeClient
    config: VIRPConfig


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """Manage O-Node connection lifecycle."""
    config = load_config()
    onode = ONodeClient(
        host=config.onode_host,
        port=config.onode_port,
        socket_path=config.onode_socket,
        timeout=config.onode_timeout,
    )
    try:
        await onode.connect()
        logger.info(
            "VIRP MCP Server connected to O-Node at %s",
            config.onode_socket or f"{config.onode_host}:{config.onode_port}",
        )
        yield AppContext(onode=onode, config=config)
    finally:
        await onode.disconnect()
        logger.info("VIRP MCP Server disconnected from O-Node")


# ---------------------------------------------------------------------------
# Server instance
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "virp",
    description=(
        "VIRP — Verified Infrastructure Response Protocol. "
        "Cryptographic trust primitives for AI agents operating on "
        "live network infrastructure. Every observation is HMAC-signed "
        "at the point of collection. The AI cannot fabricate what the "
        "network never said."
    ),
    lifespan=app_lifespan,
    dependencies=["asyncio"],
)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def virp_collect(
    device: str,
    command: str,
    ctx: Context,
) -> dict:
    """
    Collect a signed observation from a network device.

    Executes the given command on the specified device through the VIRP
    O-Node. The O-Node handles SSH connectivity, executes the command,
    and signs the raw output with HMAC-SHA256 before returning it.

    The returned observation includes:
    - output: The raw device output
    - hmac: HMAC-SHA256 signature proving collection happened
    - sequence: Chain sequence number for audit trail
    - timestamp: When the observation was collected
    - trust_tier: GREEN/YELLOW/RED/BLACK classification
    - node_id: Which O-Node collected the data
    - verified: Whether the HMAC signature is valid

    Args:
        device: Device identifier (e.g. "r1", "home-fg", "pa-850")
        command: CLI command to execute (e.g. "show ip bgp summary")
    """
    app: AppContext = ctx.request_context.lifespan_context
    try:
        result = await app.onode.collect(device=device, command=command)
        return result.to_dict()
    except ONodeConnectionError as e:
        return {
            "error": str(e),
            "verified": False,
            "trust_tier": "BLACK",
            "detail": "O-Node unreachable. Cannot collect observation.",
        }


@mcp.tool()
async def virp_verify(
    observation_id: str,
    ctx: Context,
) -> dict:
    """
    Verify a previously collected observation against the chain.

    Checks the HMAC signature and sequence number of an observation
    stored in chain.db. Returns verification status and chain integrity.

    Args:
        observation_id: The observation ID or sequence number to verify.
    """
    app: AppContext = ctx.request_context.lifespan_context
    try:
        result = await app.onode.verify(observation_id=observation_id)
        return result
    except ONodeConnectionError as e:
        return {"error": str(e), "verified": False}


@mcp.tool()
async def virp_devices(ctx: Context) -> dict:
    """
    List all devices registered with the VIRP O-Node.

    Returns each device's name, address, last observation timestamp,
    trust status, and whether the device is currently reachable.
    No arguments required.
    """
    app: AppContext = ctx.request_context.lifespan_context
    try:
        devices = await app.onode.list_devices()
        return {
            "devices": [d.to_dict() for d in devices],
            "count": len(devices),
        }
    except ONodeConnectionError as e:
        return {"error": str(e), "devices": [], "count": 0}


@mcp.tool()
async def virp_baseline(
    device: str,
    ctx: Context,
    metric: Optional[str] = None,
) -> dict:
    """
    Get the baseline state for a device from signed observation history.

    Compares current device state against historical signed observations.
    Returns deviations from baseline — anything that's changed since the
    last known-good state. If a metric is specified, narrows the comparison.

    Args:
        device: Device identifier (e.g. "r1", "home-fg")
        metric: Optional specific metric to check (e.g. "bgp_peers", "interfaces", "routes")
    """
    app: AppContext = ctx.request_context.lifespan_context
    try:
        result = await app.onode.get_baseline(device=device, metric=metric)
        return result
    except ONodeConnectionError as e:
        return {"error": str(e), "device": device, "baseline_available": False}


@mcp.tool()
async def virp_intent(
    device: str,
    action: str,
    justification: str,
    commands: list[str],
    ctx: Context,
) -> dict:
    """
    Submit a proposed change as a signed VIRP Intent.

    Intents are trust-tier gated:
    - GREEN: Auto-approved (read-only operations)
    - YELLOW: Logged and flagged for review
    - RED: Requires explicit human approval before execution
    - BLACK: Structurally impossible — the O-Node will refuse

    The intent is signed and stored in the chain regardless of approval
    status. This creates a complete audit trail of what was proposed,
    by whom, and whether it was executed.

    Args:
        device: Target device for the proposed change
        action: Short description of the action (e.g. "shutdown interface Gi1/0/1")
        justification: Why this change is being proposed, with evidence references
        commands: List of CLI commands to execute if approved
    """
    app: AppContext = ctx.request_context.lifespan_context
    try:
        result = await app.onode.submit_intent(
            device=device,
            action=action,
            justification=justification,
            commands=commands,
        )
        return result.to_dict()
    except ONodeConnectionError as e:
        return {
            "error": str(e),
            "approved": False,
            "trust_tier": "BLACK",
            "detail": "O-Node unreachable. Intent not submitted.",
        }


@mcp.tool()
async def virp_chain(
    ctx: Context,
    device: Optional[str] = None,
    last_n: int = 20,
) -> dict:
    """
    Query the VIRP audit chain.

    Returns the most recent chain entries — signed, immutable records
    of every observation and intent processed by the O-Node. Each entry
    hashes the previous one; tamper one and the chain breaks from that
    point forward.

    Args:
        device: Optional device filter. If omitted, returns entries for all devices.
        last_n: Number of recent entries to return (default 20, max 100).
    """
    app: AppContext = ctx.request_context.lifespan_context
    last_n = min(last_n, 100)
    try:
        entries = await app.onode.query_chain(device=device, last_n=last_n)
        return {
            "entries": [e.to_dict() for e in entries],
            "count": len(entries),
            "chain_intact": all(e.chain_valid for e in entries),
        }
    except ONodeConnectionError as e:
        return {"error": str(e), "entries": [], "count": 0}


@mcp.tool()
async def virp_status(ctx: Context) -> dict:
    """
    Check VIRP O-Node health and connection status.

    Returns O-Node version, uptime, total observations in chain,
    registered device count, and whether the session handshake is active.
    No arguments required.
    """
    app: AppContext = ctx.request_context.lifespan_context
    try:
        status = await app.onode.health()
        return status
    except ONodeConnectionError as e:
        return {
            "status": "unreachable",
            "error": str(e),
            "onode_connected": False,
        }


# ---------------------------------------------------------------------------
# Resources — expose VIRP metadata to agents
# ---------------------------------------------------------------------------

@mcp.resource("virp://trust-tiers")
def trust_tier_reference() -> str:
    """VIRP trust tier definitions and what each level permits."""
    return json.dumps({
        "GREEN": {
            "description": "Auto-execute. Read-only operations.",
            "examples": ["show commands", "ping", "device status checks"],
            "approval": "none",
        },
        "YELLOW": {
            "description": "Flagged. Non-critical changes logged for review.",
            "examples": ["restart non-critical service", "trigger snapshot"],
            "approval": "logged, post-review",
        },
        "RED": {
            "description": "Human approval required. Critical operations.",
            "examples": ["firewall rule changes", "interface shutdown", "BGP config"],
            "approval": "explicit human confirmation before execution",
        },
        "BLACK": {
            "description": "Structurally impossible. O-Node will refuse.",
            "examples": ["factory reset", "delete keys", "bypass approvals", "disable VIRP"],
            "approval": "cannot be approved — blocked at protocol level",
        },
    }, indent=2)


@mcp.resource("virp://protocol-info")
def protocol_info() -> str:
    """VIRP protocol overview for agent context."""
    return json.dumps({
        "name": "VIRP — Verified Infrastructure Response Protocol",
        "version": "1.0",
        "author": "Nate Howard, Third Level IT LLC",
        "license": "Apache 2.0",
        "rfc": "draft-howard-virp-01",
        "repository": "https://github.com/nhowardtli/virp",
        "doi": "10.5281/zenodo.18830236",
        "description": (
            "Cryptographic trust layer for AI agents operating on live "
            "network infrastructure. Every observation is HMAC-SHA256 signed "
            "at the point of collection. Two-channel separation: Observation "
            "(what the network said) vs Intent (what the AI wants to do). "
            "Trust tiers enforce structural limits on agent capabilities."
        ),
        "trust_primitives": [
            "Verified Observation",
            "Tiered Authorization",
            "Verified Intent",
            "Verified Outcome",
            "Baseline Memory",
            "Trust Chain",
            "Trust Federation",
        ],
    }, indent=2)


# ---------------------------------------------------------------------------
# Prompts — reusable templates for common VIRP workflows
# ---------------------------------------------------------------------------

@mcp.prompt()
def network_audit(scope: str = "all devices") -> str:
    """
    Run a VIRP-verified network audit.

    Collects signed observations from all devices in scope,
    checks baselines for deviations, and produces a summary
    with cryptographic proof of every claim.
    """
    return (
        f"Perform a VIRP-verified network audit on {scope}. "
        "For each device: (1) use virp_collect to gather current state, "
        "(2) use virp_baseline to check for deviations from known-good, "
        "(3) report findings with HMAC verification status for each claim. "
        "Flag any devices where evidence is degraded or missing. "
        "Do NOT draw conclusions about devices you haven't collected from. "
        "End with a summary that includes total devices checked, "
        "observations collected, deviations found, and chain integrity status."
    )


@mcp.prompt()
def investigate_device(device: str) -> str:
    """
    Deep investigation of a specific device with full VIRP verification.
    """
    return (
        f"Investigate device '{device}' using VIRP-verified observations. "
        "Step 1: virp_collect with 'show version' or equivalent for device identity. "
        "Step 2: virp_collect with interface status command. "
        "Step 3: virp_collect with routing protocol status (BGP/OSPF as applicable). "
        "Step 4: virp_baseline to check for any deviations from known-good state. "
        "Step 5: Summarize findings. Every claim must reference a verified observation. "
        "If any observation comes back unverified, flag it prominently."
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    """Run the VIRP MCP server."""
    logging.basicConfig(
        level=os.environ.get("VIRP_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    mcp.run()


if __name__ == "__main__":
    main()
