# VIRP Dashboard — IronClaw Operations Center

## Architecture

```
Browser → React UI → FastAPI (CT 210 :8080) → TCP 9999 → O-Node (CT 211) → Devices
```

No Claude API in the loop. No 60-second waits. O-Node handles SSH, HMAC signing,
and parallel batch execution directly. Target: sub-5-second sweeps.

## Files

| File | Purpose |
|------|---------|
| `server.py` | FastAPI backend — talks to O-Node via TCP 9999 |
| `dashboard-live.jsx` | React frontend — fetches from API, FortiGate style |
| `deploy.sh` | Deployment script for CT 210 |
| `requirements.txt` | Python dependencies |

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check + O-Node connectivity |
| GET | `/api/devices` | List registered devices |
| GET | `/api/sweep` | Run BGP sweep across all devices |
| GET | `/api/sweep?devices=R1,ASA-5525` | Sweep specific devices |
| GET | `/api/device/{hostname}` | Query single device |
| POST | `/api/intent` | File intent — The Cage checks RED-tier |

## Deployment

### On CT 210 (ironclaw-ai):

```bash
# Copy files to CT 210
scp -r virp-dashboard-api/ root@10.0.0.210:/tmp/

# SSH in and deploy
ssh root@10.0.0.210
cd /tmp/virp-dashboard-api
bash deploy.sh
```

### Prerequisites on CT 211:
Socat bridge must be running:
```bash
socat TCP-LISTEN:9999,fork,reuseaddr UNIX-CONNECT:/tmp/virp-onode.sock
```

### Test:
```bash
# Health check
curl http://10.0.0.210:8080/api/health

# Run sweep
curl http://10.0.0.210:8080/api/sweep | python3 -m json.tool

# Test The Cage
curl -X POST http://10.0.0.210:8080/api/intent \
  -H 'Content-Type: application/json' \
  -d '{"hostname":"ASA-5525","command":"shutdown interface Gi0/0"}'
```

## React Frontend

The `dashboard-live.jsx` file is a React component that can be:

1. **Rendered in Claude.ai** — paste as artifact for instant preview
2. **Built standalone** — wrap in a Create React App or Vite project
3. **Served from CT 210** — build to static and serve via nginx alongside the API

The frontend auto-detects the API URL. When running on CT 210, it uses
the same host. When running in dev/Claude, it points at `http://10.0.0.210:8080`.

## How It Works

1. **Sweep**: Frontend calls `GET /api/sweep` → FastAPI builds batch commands →
   sends to O-Node via TCP 9999 → O-Node spawns pthread per device →
   SSH + HMAC signing in parallel → returns signed observations →
   FastAPI parses BGP output → returns structured JSON to frontend

2. **The Cage**: Frontend calls `POST /api/intent` with a RED-tier command →
   FastAPI pattern-matches against RED_TIER_PATTERNS → returns cage denial
   with three-wall breakdown before the command ever reaches the O-Node

3. **No AI in the loop**: The dashboard is pure infrastructure.
   IronClaw (OpenClaw + Claude) remains available for analysis and
   troubleshooting via the TUI. The dashboard is the monitoring layer.
