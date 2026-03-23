# VIRP MCP Server

**Cryptographic trust primitives for any AI agent.**

Give your AI agent the ability to prove what it saw on your network. Every observation is HMAC-SHA256 signed at the point of collection, before the AI ever touches it. The AI cannot fabricate what the network never said.

VIRP MCP Server exposes the [VIRP protocol](https://github.com/nhowardtli/virp) as standard [MCP](https://modelcontextprotocol.io) tools. Any MCP-compatible client — Claude, GPT, Ollama, OpenClaw, or your own agent — connects and gets signed, verified infrastructure observations out of the box.

## What This Solves

Every AI operations platform on the market trusts its own telemetry implicitly. The AI says "I checked your firewall." Did it? Can you prove it?

VIRP MCP Server adds a cryptographic trust layer between your AI agent and your infrastructure:

```
Any AI Agent (Claude, GPT, Ollama, h-cli, OpenClaw)
        │
        │  MCP protocol (stdio or SSE)
        ▼
┌─────────────────────┐
│  VIRP MCP Server    │  ← You are here
│  (Python)           │
└────────┬────────────┘
         │  TCP / Unix socket
         ▼
┌─────────────────────┐
│  VIRP O-Node        │  Isolated C daemon
│  HMAC-SHA256 signing │  chain.db audit trail
│  Device SSH access   │  Key management
└────────┬────────────┘
         │  SSH
         ▼
┌─────────────────────┐
│  Network Devices    │  Cisco, Fortinet, Palo Alto, ...
└─────────────────────┘
```

The MCP server is a translation layer. It takes tool calls from your AI agent, forwards them to the VIRP O-Node, and returns cryptographically signed results. The O-Node does all signing — this server never touches keys.

## Quick Start

### Install

```bash
pip install virp-mcp-server
```

Or from source:

```bash
git clone https://github.com/nhowardtli/virp.git
cd virp/mcp-server
pip install -e .
```

### Configure

```bash
# Point to your O-Node (TCP via socat bridge)
export VIRP_ONODE_HOST=10.0.0.211
export VIRP_ONODE_PORT=9999

# Or use Unix socket for local O-Node
# export VIRP_ONODE_SOCKET=/tmp/virp-onode.sock
```

### Run

```bash
virp-mcp
```

### Connect from Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "virp": {
      "command": "virp-mcp",
      "env": {
        "VIRP_ONODE_HOST": "10.0.0.211",
        "VIRP_ONODE_PORT": "9999"
      }
    }
  }
}
```

### Connect from Claude Code

```bash
claude mcp add virp -- virp-mcp
```

## Tools

| Tool | Description |
|------|-------------|
| `virp_collect` | Collect a signed observation from a device. Returns output + HMAC + sequence + trust tier. |
| `virp_verify` | Verify a previously collected observation against the chain. |
| `virp_devices` | List all devices registered with the O-Node. |
| `virp_baseline` | Get baseline state for a device, flag deviations from known-good. |
| `virp_intent` | Submit a proposed change. Trust-tier gated: GREEN/YELLOW/RED/BLACK. |
| `virp_chain` | Query the immutable audit trail. Each entry hashes the previous one. |
| `virp_status` | Check O-Node health and connection status. |

## Trust Tiers

VIRP enforces structural limits on what the AI can do:

| Tier | What it means | Example |
|------|---------------|---------|
| **GREEN** | Auto-execute. Read-only. | `show ip bgp summary`, `ping` |
| **YELLOW** | Flagged for review. | Restart a non-critical service |
| **RED** | Human approval required. | Firewall rule change, interface shutdown |
| **BLACK** | Structurally impossible. | Factory reset, delete keys, disable VIRP |

BLACK tier operations cannot be approved. The O-Node refuses them at the protocol level.

## Resources and Prompts

**MCP Resources** (agents can read for context):
- `virp://trust-tiers` — Trust tier definitions and examples
- `virp://protocol-info` — Protocol overview, version, DOI, links

**Built-in Prompts:**
- `network_audit` — Full VIRP-verified audit across all devices
- `investigate_device` — Deep investigation of a specific device

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `VIRP_ONODE_HOST` | `127.0.0.1` | O-Node TCP host |
| `VIRP_ONODE_PORT` | `9999` | O-Node TCP port |
| `VIRP_ONODE_SOCKET` | — | Unix socket path (overrides TCP) |
| `VIRP_ONODE_TIMEOUT` | `30` | Command timeout (seconds) |
| `VIRP_LOG_LEVEL` | `INFO` | Logging level |
| `VIRP_TRANSPORT` | `stdio` | MCP transport: `stdio` or `sse` |

Also supports YAML config files. See [`virp-mcp.example.yaml`](virp-mcp.example.yaml).

## Prerequisites

A running VIRP O-Node with registered devices. See the [VIRP repository](https://github.com/nhowardtli/virp) for O-Node setup.

Or use the built-in Mock O-Node to test without any hardware:

```bash
# Terminal 1: Start mock O-Node (simulates Cisco, Fortinet, Palo Alto devices)
virp-mock-onode

# Terminal 2: Start MCP server pointing at mock
VIRP_ONODE_PORT=9999 virp-mcp
```

## Testing

```bash
pip install virp-mcp-server[dev]
pytest tests/ -v
```

28 tests covering connection, collection, verification, intents, trust tiers, chain integrity, and baselines. All tests run against the Mock O-Node, no hardware required.

## How It Works

1. Your AI agent calls `virp_collect("r1", "show ip bgp summary")` via MCP
2. The MCP server forwards the request to the O-Node
3. The O-Node SSHs into the device, executes the command
4. The O-Node signs the raw output with HMAC-SHA256
5. The observation is stored in chain.db with a sequence number
6. The MCP server returns the signed observation to your agent
7. Your agent makes claims about the network with cryptographic proof

If the AI references a device without a matching signed observation, the Observation Gate catches it. No signed observation = no verified claim.

## Protocol

**VIRP** — Verified Infrastructure Response Protocol

- **RFC:** draft-howard-virp-01 (submitted to IETF)
- **DOI:** [10.5281/zenodo.18830236](https://doi.org/10.5281/zenodo.18830236)
- **Repository:** [github.com/nhowardtli/virp](https://github.com/nhowardtli/virp)
- **Author:** Nate Howard, Third Level IT LLC
- **License:** Apache 2.0
