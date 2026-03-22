# VIRP Single Source of Truth — Refactor Plan
## For Claude Code execution on CT 210 + CT 211

---

## THE PROBLEM

Device definitions are duplicated across 9+ files. Adding or renaming a device
requires touching all of them. This has caused bugs, demo failures, and is the
#1 tech debt item.

## THE SOLUTION

One file: `/root/virp/devices.yaml` on CT 211 (ironclaw-onode).
Everything else reads from it. No exceptions.

---

## ARCHITECTURE

```
CT 211 (ironclaw-onode)
  /root/virp/devices.yaml        ← CANONICAL SOURCE (this file)
  /root/virp/credentials.age     ← age-encrypted creds (unchanged)
  O-Node daemon reads devices.yaml directly
  Serves device metadata (no creds) over socat bridge to CT 210

CT 210 (ironclaw-ai)
  AI layer queries O-Node for device list
  System prompt is generated from device metadata
  No local device definitions anywhere
```

## CREDENTIAL SEPARATION

The `credential_ref` field in devices.yaml maps to the age-encrypted store.
Passwords are NEVER in devices.yaml. The O-Node resolves credential_ref → 
actual creds at connection time by decrypting with /root/onode-key.txt.

Credential ref groups:
  - "colo-switch"      → rotated password (Lab2001-92!-Go-Run)
  - "fortigate-200g"   → rotated password (Lab2001-92!-Go-Run)
  - "pa-850"           → rotated password (Lab2001-92!-Go-Run)
  - "fortiwifi-60f"    → rotated password (Lab2001-92!-Go-Run)
  - "gns3-lab"         → old password (A!0ps-Svc#2026Lab) — NEEDS ROTATION
  - "wazuh"            → separate creds
  - "proxmox"          → separate creds

---

## REFACTOR STEPS (in order)

### Step 1: Deploy devices.yaml on CT 211
```bash
# Copy the file to CT 211
cp devices.yaml /root/virp/devices.yaml
```

### Step 2: Create a Python loader module (CT 211)
Create `/root/virp/device_registry.py`:
```python
"""
Single source of truth device loader.
Every component imports from here. Nobody parses their own device list.
"""
import yaml
from pathlib import Path

DEVICES_PATH = Path("/root/virp/devices.yaml")

_cache = None

def load_devices(force_reload=False):
    """Load and cache all devices from the canonical YAML."""
    global _cache
    if _cache is None or force_reload:
        with open(DEVICES_PATH) as f:
            _cache = yaml.safe_load(f)
    return _cache

def get_device(hostname):
    """Get a single device by hostname."""
    devices = load_devices()
    return devices.get(hostname)

def get_devices_by_tag(tag):
    """Get all devices matching a tag."""
    devices = load_devices()
    return {k: v for k, v in devices.items() if tag in v.get('tags', [])}

def get_devices_by_vendor(vendor):
    """Get all devices for a specific vendor."""
    devices = load_devices()
    return {k: v for k, v in devices.items() if v.get('vendor') == vendor}

def get_devices_by_site(site):
    """Get all devices at a specific site."""
    devices = load_devices()
    return {k: v for k, v in devices.items() if v.get('site') == site}

def get_enabled_devices():
    """Get all enabled devices."""
    devices = load_devices()
    return {k: v for k, v in devices.items() if v.get('enabled', False)}

def get_ssh_targets():
    """Get all devices that use SSH collection (for the executor)."""
    devices = load_devices()
    return {k: v for k, v in devices.items()
            if v.get('collector') == 'ssh' and v.get('enabled', False)}

def get_device_list_for_prompt():
    """Generate device summary for AI system prompt injection."""
    devices = get_enabled_devices()
    lines = []
    for name, d in devices.items():
        lines.append(f"- {name}: {d['platform']} ({d['vendor']}) at {d['host']} "
                     f"[{d['type']}] [{d['trust_tier']}] site={d['site']}")
    return "\n".join(lines)

def to_legacy_json():
    """Export to legacy devices.json format for backward compat during migration."""
    devices = get_ssh_targets()
    legacy = {"devices": []}
    for name, d in devices.items():
        legacy["devices"].append({
            "hostname": d["hostname"],
            "host": d["host"],
            "port": d.get("port", 22),
            "vendor": d["vendor"],
            "type": d.get("type", "unknown"),
            "node_id": d.get("node_id", ""),
            "enabled": d.get("enabled", True),
            # credential_ref only — actual creds resolved at runtime
            "credential_ref": d.get("credential_ref", "")
        })
    return legacy
```

### Step 3: O-Node metadata endpoint
Add a command to the O-Node socat interface that CT 210 can call:
```
DEVICE_LIST → returns JSON of all enabled devices (metadata only, no creds)
DEVICE_INFO <hostname> → returns JSON for one device (metadata only, no creds)
```
This replaces any hardcoded device lists on CT 210.

### Step 4: Rewrite consumers (one at a time, test after each)

These are the files that currently have their own device definitions.
Each one needs to be rewritten to import from device_registry.py
or query the O-Node metadata endpoint:

ON CT 211:
  1. O-Node daemon device loading → read from devices.yaml via device_registry
  2. executor (C level) config → O-Node passes device info to executor at runtime
  3. devices.json (all copies) → DELETE after migration, replaced by devices.yaml

ON CT 210:
  4. host_config.py → replace with O-Node DEVICE_LIST query
  5. customer.yaml → replace with devices.yaml customer field
  6. system_prompt.j2 → inject device list from get_device_list_for_prompt()
  7. pentest-scope.json → generate from devices.yaml tags
  8. aiops_executor.py → query O-Node for device connection info
  9. intent_router.py → query O-Node for device vendor/type to route commands
  10. pentest_engine.py → query O-Node for enabled devices
  11. .env device references → remove, query O-Node
  12. license_manager.py → query O-Node for device count

### Step 5: Delete all legacy device definition files
Once all consumers are migrated and tested:
```bash
# CT 211 — remove legacy JSON files
rm /root/virp/devices.json
rm /root/virp/devices-r35.json
rm /root/devices.json
rm /root/devices_plain.json

# CT 211 — clean up Docker overlay copies (or just rebuild images)
docker system prune

# CT 210 — remove any local device configs
# (specific paths depend on what exists there)
```

### Step 6: Validation
```bash
# Quick sanity check — should print 42 devices
python3 -c "from device_registry import *; print(len(get_enabled_devices()))"

# Check demo devices resolve
python3 -c "from device_registry import *; d=get_device('colo-switch'); print(d['host'], d['platform'])"
python3 -c "from device_registry import *; d=get_device('fortigate-200g'); print(d['host'], d['platform'])"
python3 -c "from device_registry import *; d=get_device('pa-850'); print(d['host'], d['platform'])"
```

---

## ADDING A NEW DEVICE (after refactor)

1. Edit `/root/virp/devices.yaml` — add the device entry
2. Add credentials to the age-encrypted store with matching credential_ref
3. Done. No other files to touch.

---

## NOTES

- The GNS3 routers (R1-R35) still use the OLD password (A!0ps-Svc#2026Lab).
  Consider rotating to match the physical devices.
- Wazuh and Proxmox have collector: none — they're in the registry for
  inventory/prompt awareness but IronClaw doesn't SSH into them for observations.
- The February 8th rule for FortiGate is preserved in the notes field.
- node_id values for new devices (wazuh, proxmox, fortiwifi) are placeholders.
  Update if the O-Node has specific ID requirements.
