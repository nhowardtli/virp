"""
VIRP MCP Server Configuration.

Configuration priority (highest to lowest):
1. Environment variables (VIRP_ONODE_HOST, VIRP_ONODE_PORT, etc.)
2. Config file (virp-mcp.yaml or path in VIRP_CONFIG)
3. Defaults (localhost:9999)

Copyright 2026 Nate Howard, Third Level IT LLC
Licensed under Apache 2.0
"""

import os
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("virp-mcp.config")

# Default config file locations (checked in order)
CONFIG_SEARCH_PATHS = [
    Path("virp-mcp.yaml"),
    Path("virp-mcp.yml"),
    Path.home() / ".virp" / "mcp.yaml",
    Path("/etc/virp/mcp.yaml"),
]


@dataclass
class VIRPConfig:
    """VIRP MCP Server configuration."""

    # O-Node connection — TCP (for remote via socat bridge)
    onode_host: str = "127.0.0.1"
    onode_port: int = 9999

    # O-Node connection — Unix socket (for local O-Node, takes priority)
    onode_socket: Optional[str] = None

    # Timeouts
    onode_timeout: float = 30.0

    # Server identity
    server_name: str = "virp-mcp-server"

    # Logging
    log_level: str = "INFO"

    # Transport (stdio or sse)
    transport: str = "stdio"
    sse_host: str = "127.0.0.1"
    sse_port: int = 8399


def load_config() -> VIRPConfig:
    """
    Load configuration from environment variables and optional config file.

    Environment variables (all optional):
        VIRP_ONODE_HOST      — O-Node TCP host (default: 127.0.0.1)
        VIRP_ONODE_PORT      — O-Node TCP port (default: 9999)
        VIRP_ONODE_SOCKET    — O-Node Unix socket path (overrides TCP)
        VIRP_ONODE_TIMEOUT   — Command timeout in seconds (default: 30)
        VIRP_LOG_LEVEL       — Logging level (default: INFO)
        VIRP_TRANSPORT       — MCP transport: stdio or sse (default: stdio)
        VIRP_SSE_HOST        — SSE server bind host (default: 127.0.0.1)
        VIRP_SSE_PORT        — SSE server bind port (default: 8399)
        VIRP_CONFIG          — Path to config file (optional)
    """
    config = VIRPConfig()

    # Try loading YAML config file
    config_path = os.environ.get("VIRP_CONFIG")
    if config_path:
        _load_yaml_config(config, Path(config_path))
    else:
        for path in CONFIG_SEARCH_PATHS:
            if path.exists():
                _load_yaml_config(config, path)
                break

    # Environment variables override config file
    if host := os.environ.get("VIRP_ONODE_HOST"):
        config.onode_host = host

    if port := os.environ.get("VIRP_ONODE_PORT"):
        config.onode_port = int(port)

    if socket_path := os.environ.get("VIRP_ONODE_SOCKET"):
        config.onode_socket = socket_path

    if timeout := os.environ.get("VIRP_ONODE_TIMEOUT"):
        config.onode_timeout = float(timeout)

    if log_level := os.environ.get("VIRP_LOG_LEVEL"):
        config.log_level = log_level.upper()

    if transport := os.environ.get("VIRP_TRANSPORT"):
        config.transport = transport.lower()

    if sse_host := os.environ.get("VIRP_SSE_HOST"):
        config.sse_host = sse_host

    if sse_port := os.environ.get("VIRP_SSE_PORT"):
        config.sse_port = int(sse_port)

    logger.info(
        "VIRP config loaded — O-Node: %s, transport: %s",
        config.onode_socket or f"{config.onode_host}:{config.onode_port}",
        config.transport,
    )
    return config


def _load_yaml_config(config: VIRPConfig, path: Path) -> None:
    """Load configuration from a YAML file."""
    try:
        import yaml  # Optional dependency
    except ImportError:
        logger.debug("PyYAML not installed, skipping config file: %s", path)
        return

    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}

        onode = data.get("onode", {})
        if "host" in onode:
            config.onode_host = onode["host"]
        if "port" in onode:
            config.onode_port = int(onode["port"])
        if "socket" in onode:
            config.onode_socket = onode["socket"]
        if "timeout" in onode:
            config.onode_timeout = float(onode["timeout"])

        server = data.get("server", {})
        if "name" in server:
            config.server_name = server["name"]
        if "log_level" in server:
            config.log_level = server["log_level"]
        if "transport" in server:
            config.transport = server["transport"]
        if "sse_host" in server:
            config.sse_host = server["sse_host"]
        if "sse_port" in server:
            config.sse_port = int(server["sse_port"])

        logger.info("Loaded config from %s", path)

    except Exception as e:
        logger.warning("Failed to load config from %s: %s", path, e)
