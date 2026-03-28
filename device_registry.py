"""
VIRP Device Registry — Single Source of Truth
==============================================
Every component imports from here. Nobody parses their own device list.

Location: /root/virp/device_registry.py (CT 211 - ironclaw-onode)
Source:   /root/virp/devices.yaml

RULES:
  1. devices.yaml is the ONLY place device definitions live.
  2. Credentials are NEVER exposed — only credential_ref keys.
  3. The to_legacy_json() function bridges the gap during migration.
  4. CT 210 queries CT 211 for device metadata (no local device lists).

Copyright (c) 2026 Third Level IT LLC. All rights reserved.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

import yaml

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEVICES_YAML = Path(
    os.environ.get("VIRP_DEVICES_YAML", "/root/virp/devices.yaml")
)

# ---------------------------------------------------------------------------
# Cache — devices.yaml is read once and cached in-process.
# Call load_devices(force_reload=True) after editing devices.yaml at runtime.
# ---------------------------------------------------------------------------

_cache: Optional[dict] = None
_cache_mtime: float = 0.0


def load_devices(force_reload: bool = False) -> dict:
    """Load and cache all devices from the canonical YAML.

    Returns a dict keyed by device hostname, each value is the full
    device descriptor (minus credentials).  Auto-reloads if the file's
    mtime has changed since the last load.
    """
    global _cache, _cache_mtime

    try:
        current_mtime = DEVICES_YAML.stat().st_mtime
    except FileNotFoundError:
        if _cache is not None:
            return _cache
        raise FileNotFoundError(f"Device registry not found: {DEVICES_YAML}")

    if _cache is None or force_reload or current_mtime != _cache_mtime:
        with open(DEVICES_YAML) as f:
            _cache = yaml.safe_load(f) or {}
        _cache_mtime = current_mtime

    return _cache


# ---------------------------------------------------------------------------
# Single-device lookups
# ---------------------------------------------------------------------------

def get_device(hostname: str) -> Optional[dict]:
    """Get a single device by hostname. Returns None if not found."""
    return load_devices().get(hostname)


def get_device_or_raise(hostname: str) -> dict:
    """Get a single device by hostname. Raises KeyError if not found."""
    devices = load_devices()
    if hostname not in devices:
        raise KeyError(
            f"Device '{hostname}' not in registry. "
            f"Known devices: {', '.join(sorted(devices.keys()))}"
        )
    return devices[hostname]


# ---------------------------------------------------------------------------
# Filtered queries
# ---------------------------------------------------------------------------

def get_devices_by_tag(tag: str) -> dict:
    """Get all devices matching a tag (e.g., 'colo', 'gns3', 'production')."""
    return {
        k: v for k, v in load_devices().items()
        if tag in v.get("tags", [])
    }


def get_devices_by_vendor(vendor: str) -> dict:
    """Get all devices for a specific vendor (e.g., 'cisco_ios', 'fortinet')."""
    return {
        k: v for k, v in load_devices().items()
        if v.get("vendor") == vendor
    }


def get_devices_by_site(site: str) -> dict:
    """Get all devices at a specific site (e.g., 'colo-123net', 'home-lab')."""
    return {
        k: v for k, v in load_devices().items()
        if v.get("site") == site
    }


def get_devices_by_type(device_type: str) -> dict:
    """Get all devices of a specific type (e.g., 'router', 'firewall')."""
    return {
        k: v for k, v in load_devices().items()
        if v.get("type") == device_type
    }


def get_enabled_devices() -> dict:
    """Get all enabled devices."""
    return {
        k: v for k, v in load_devices().items()
        if v.get("enabled", False)
    }


def get_ssh_targets() -> dict:
    """Get all devices that use SSH collection (enabled + collector=ssh)."""
    return {
        k: v for k, v in load_devices().items()
        if v.get("collector") == "ssh" and v.get("enabled", False)
    }


# ---------------------------------------------------------------------------
# AI / Prompt generation
# ---------------------------------------------------------------------------

def get_device_list_for_prompt():
    """Generate device summary for AI system prompt injection."""
    devices = get_enabled_devices()
    lines = ["IMPORTANT: Always use the EXACT hostname shown below (before the colon) in all tool calls. Never abbreviate or rename devices."]
    for name, d in devices.items():
        lines.append(f"- {name}: {d['platform']} ({d['vendor']}) at {d['host']} "
                     f"[{d['type']}] [{d['trust_tier']}] site={d['site']}")
    return "\n".join(lines)

# ---------------------------------------------------------------------------
# Metadata export (no credentials)
# ---------------------------------------------------------------------------

def device_metadata(hostname: str) -> Optional[dict]:
    """Return device metadata dict (safe to send over the network).

    Strips credential_ref — this is for the socat bridge / CT 210 queries.
    """
    d = get_device(hostname)
    if d is None:
        return None
    return {
        "hostname": d.get("hostname", hostname),
        "host": d["host"],
        "port": d.get("port", 22),
        "vendor": d["vendor"],
        "platform": d.get("platform", ""),
        "type": d.get("type", ""),
        "site": d.get("site", ""),
        "customer": d.get("customer", ""),
        "node_id": d.get("node_id", ""),
        "trust_tier": d.get("trust_tier", "YELLOW"),
        "collector": d.get("collector", "none"),
        "enabled": d.get("enabled", False),
        "tags": d.get("tags", []),
        "notes": d.get("notes", ""),
    }


def all_device_metadata() -> list[dict]:
    """Return metadata for all enabled devices (safe for network transport)."""
    return [
        device_metadata(name)
        for name in sorted(load_devices().keys())
        if load_devices()[name].get("enabled", False)
    ]


# ---------------------------------------------------------------------------
# Legacy compatibility — generates the old devices.json format
# ---------------------------------------------------------------------------

def to_legacy_json(include_cred_ref: bool = False) -> dict:
    """Export to legacy devices.json format for C O-Node backward compat.

    The C O-Node expects:
      {"devices": [{"hostname": "R1", "host": "...", "port": 22,
                     "vendor": "cisco_ios", "node_id": "01010101", ...}]}

    Credentials are NOT included — they must be resolved separately
    from the age-encrypted store at O-Node startup time.

    Args:
        include_cred_ref: If True, include the credential_ref field so
                          the O-Node can resolve credentials from the
                          age store. Default False (pure metadata).
    """
    devices = get_ssh_targets()
    legacy = {"devices": []}

    for name, d in devices.items():
        entry = {
            "hostname": d.get("hostname", name),
            "host": d["host"],
            "port": d.get("port", 22),
            "vendor": d["vendor"],
            "type": d.get("type", "unknown"),
            "node_id": d.get("node_id", ""),
            "enabled": d.get("enabled", True),
        }
        if include_cred_ref:
            entry["credential_ref"] = d.get("credential_ref", "")
        legacy["devices"].append(entry)

    return legacy


def to_legacy_json_str(include_cred_ref: bool = False) -> str:
    """Export as formatted JSON string."""
    return json.dumps(to_legacy_json(include_cred_ref), indent=2)


# ---------------------------------------------------------------------------
# Node-ID helpers
# ---------------------------------------------------------------------------

def node_id_to_hostname() -> dict[int, str]:
    """Build a mapping of integer node_id -> hostname.

    Used by the Prometheus exporter to resolve artifact_id in chain.db.
    """
    mapping: dict[int, str] = {}
    for name, d in load_devices().items():
        nid = d.get("node_id", "")
        if nid:
            try:
                mapping[int(nid, 16)] = d.get("hostname", name)
            except ValueError:
                pass
    return mapping


# ---------------------------------------------------------------------------
# CLI — quick sanity check
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    devices = load_devices()
    enabled = get_enabled_devices()
    ssh = get_ssh_targets()

    print(f"Registry:  {DEVICES_YAML}")
    print(f"Total:     {len(devices)} devices")
    print(f"Enabled:   {len(enabled)}")
    print(f"SSH:       {len(ssh)}")
    print()

    # Verify demo devices
    for demo in ("colo-switch", "fortigate-200g", "pa-850"):
        d = get_device(demo)
        if d:
            print(f"  {demo}: {d['host']} ({d.get('platform', '?')}) "
                  f"[{d.get('trust_tier', '?')}] "
                  f"cred_ref={d.get('credential_ref', 'MISSING')}")
        else:
            print(f"  {demo}: NOT FOUND", file=sys.stderr)

    print()
    print("Sites:", sorted(set(d.get("site", "?") for d in devices.values())))
    print("Vendors:", sorted(set(d.get("vendor", "?") for d in devices.values())))

    # Credential safety check
    for name, d in devices.items():
        for key in ("password", "enable", "api_token", "secret"):
            if key in d:
                print(f"DANGER: {name} has plaintext credential: {key}",
                      file=sys.stderr)
                sys.exit(1)
    print("\nCredential check: PASSED (no plaintext creds in registry)")
