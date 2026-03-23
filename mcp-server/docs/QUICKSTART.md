# VIRP MCP Server — Deployment Quickstart

This guide covers deploying the VIRP MCP Server as a service
at a client site or on your own infrastructure.

## Prerequisites

1. A VIRP O-Node running and accessible (TCP or Unix socket)
2. Devices registered with the O-Node (see main VIRP docs)
3. Python 3.10+

## Option 1: Client Site Audit Deployment

Show up, deploy, audit, leave a report.

```bash
# On your laptop or a client VM
pip install virp-mcp-server

# Point to the O-Node you deployed at the client site
export VIRP_ONODE_HOST=<onode-ip>
export VIRP_ONODE_PORT=9999

# Test connectivity
python -c "
import asyncio
from virp_mcp.onode_client import ONodeClient
async def test():
    c = ONodeClient(host='<onode-ip>', port=9999)
    await c.connect()
    status = await c.health()
    print(status)
    await c.disconnect()
asyncio.run(test())
"

# Start the MCP server — Claude Desktop or Claude Code connects to it
virp-mcp
```

## Option 2: Persistent Service

Run as a systemd service for always-on VIRP MCP access.

```bash
# Install
pip install virp-mcp-server

# Create config
sudo mkdir -p /etc/virp
cat << 'EOF' | sudo tee /etc/virp/mcp.yaml
onode:
  host: "10.0.0.211"
  port: 9999
  timeout: 30
server:
  transport: "sse"
  sse_host: "127.0.0.1"
  sse_port: 8399
  log_level: "INFO"
EOF

# Create systemd service
cat << 'EOF' | sudo tee /etc/systemd/system/virp-mcp.service
[Unit]
Description=VIRP MCP Server
After=network.target

[Service]
Type=simple
User=virp
Group=virp
Environment=VIRP_CONFIG=/etc/virp/mcp.yaml
ExecStart=/usr/local/bin/virp-mcp
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable virp-mcp
sudo systemctl start virp-mcp
```

## Option 3: Docker

```dockerfile
FROM python:3.12-slim
RUN pip install virp-mcp-server
COPY virp-mcp.yaml /etc/virp/mcp.yaml
ENV VIRP_CONFIG=/etc/virp/mcp.yaml
CMD ["virp-mcp"]
```

```bash
docker build -t virp-mcp .
docker run -d --name virp-mcp \
  -e VIRP_ONODE_HOST=10.0.0.211 \
  -e VIRP_ONODE_PORT=9999 \
  virp-mcp
```

## Verifying the Deployment

Once running, connect any MCP client and test:

1. Call `virp_status` — should show O-Node connected, device count, chain length
2. Call `virp_devices` — should list registered devices
3. Call `virp_collect` with a device and show command — should return signed output
4. Check `verified: true` and `hmac` field in the response

If `verified: false`, check O-Node connectivity and device SSH access.

## Security Notes

- The MCP server itself holds no keys. All signing happens on the O-Node.
- Bind SSE transport to localhost unless behind a reverse proxy with auth.
- For remote deployments, tunnel the O-Node connection over SSH.
- The O-Node's `devices.json` is age-encrypted at rest.
