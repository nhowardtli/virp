#!/bin/bash
# VIRP Dashboard Deployment — CT 210 (ironclaw-ai)
# Run as root on CT 210
#
# Architecture:
#   Browser → nginx :80 → uvicorn :8080 → O-Node TCP 9999 → CT 211
#
# Usage: bash deploy.sh

set -e

DEPLOY_DIR="/opt/virp-dashboard"
SERVICE_USER="ironclaw"

echo "═══════════════════════════════════════════"
echo "  VIRP Dashboard — Deploying to CT 210"
echo "═══════════════════════════════════════════"

# 1. Create deploy directory
echo "[1/6] Creating deployment directory..."
mkdir -p $DEPLOY_DIR
cp server.py $DEPLOY_DIR/
cp requirements.txt $DEPLOY_DIR/

# 2. Install Python dependencies
echo "[2/6] Installing Python dependencies..."
pip3 install -r $DEPLOY_DIR/requirements.txt --break-system-packages 2>/dev/null || \
pip3 install -r $DEPLOY_DIR/requirements.txt

# 3. Test O-Node connectivity
echo "[3/6] Testing O-Node connectivity on 10.0.0.211:9999..."
if timeout 3 bash -c 'echo > /dev/tcp/10.0.0.211/9999' 2>/dev/null; then
    echo "  ✓ O-Node reachable"
else
    VIRP_ONODE_SOCKET="${VIRP_ONODE_SOCKET:-/tmp/virp-onode.sock}"
    echo "  ⚠ O-Node not reachable — check socat bridge on CT 211"
    echo "  Expected: socat TCP-LISTEN:9999,fork,reuseaddr UNIX-CONNECT:${VIRP_ONODE_SOCKET}"
    echo "  (set VIRP_ONODE_SOCKET to override socket path; default: /tmp/virp-onode.sock)"
    echo "  Continuing deployment anyway..."
fi

# 4. Create systemd service
echo "[4/6] Creating systemd service..."
cat > /etc/systemd/system/virp-dashboard.service << 'EOF'
[Unit]
Description=VIRP Dashboard API
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=ironclaw
Group=ironclaw
WorkingDirectory=/opt/virp-dashboard
ExecStart=/usr/bin/python3 -m uvicorn server:app --host 0.0.0.0 --port 8080 --workers 2
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/virp-dashboard
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# 5. Set permissions and start
echo "[5/6] Setting permissions and starting service..."
chown -R $SERVICE_USER:$SERVICE_USER $DEPLOY_DIR
systemctl daemon-reload
systemctl enable virp-dashboard.service
systemctl restart virp-dashboard.service

# Wait for startup
sleep 2

# 6. Verify
echo "[6/6] Verifying deployment..."
if systemctl is-active --quiet virp-dashboard.service; then
    echo "  ✓ Service running"
else
    echo "  ✕ Service failed to start"
    journalctl -u virp-dashboard.service -n 10
    exit 1
fi

# Test API
if curl -s http://localhost:8080/api/health | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  ✓ API healthy — O-Node: {d[\"onode\"]}')" 2>/dev/null; then
    :
else
    echo "  ⚠ API not responding yet — may need a moment"
fi

echo ""
echo "═══════════════════════════════════════════"
echo "  VIRP Dashboard deployed!"
echo ""
echo "  API:       http://10.0.0.210:8080"
echo "  Health:    http://10.0.0.210:8080/api/health"
echo "  Sweep:     http://10.0.0.210:8080/api/sweep"
echo "  Cage test: POST http://10.0.0.210:8080/api/intent"
echo ""
echo "  Logs:      journalctl -u virp-dashboard -f"
echo "  Status:    systemctl status virp-dashboard"
echo "═══════════════════════════════════════════"
echo ""
echo "NEXT STEPS:"
echo "  1. Test sweep:  curl http://localhost:8080/api/sweep | python3 -m json.tool"
echo "  2. Test cage:   curl -X POST http://localhost:8080/api/intent \\"
echo "                    -H 'Content-Type: application/json' \\"
echo "                    -d '{\"hostname\":\"ASA-5525\",\"command\":\"shutdown interface Gi0/0\"}'"
echo "  3. Open React dashboard pointing at http://10.0.0.210:8080"
echo ""
