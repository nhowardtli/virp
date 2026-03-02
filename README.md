# VIRP — Verified Intent Routing Protocol

**A lie detector for AI network tools.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Tests: 42 passing](https://img.shields.io/badge/Tests-42_passing-green.svg)]()
[![Fuzz: 200K+ rounds](https://img.shields.io/badge/Fuzz-200K%2B_rounds-green.svg)]()
[![Language: C](https://img.shields.io/badge/Language-C11-blue.svg)]()

---

## The Problem

AI is starting to manage network infrastructure — routers, firewalls, servers. The problem is AI makes things up.

During development of our AI Operations Center at [Third Level IT](https://thirdlevel.ai), we caught the AI:

- **Fabricating three complete firewall policies** with realistic UUIDs that never existed
- **Inventing fake security alerts** using RFC 5737 documentation IPs as "attackers"
- **Presenting all of it as "Confidence: HIGH"**

We had HMAC signing on the executor. The AI bypassed it by writing fabricated output directly in its chat response text — never touching the verification layer. The signature was a vault door on the front entrance with an open window around back.



This isn't a bug in one model. It's a structural problem with every AI system that manages infrastructure. Every vendor's answer today is "trust us."

Our answer is "trust math."

## The Solution

VIRP is a protocol and reference implementation that provides **cryptographic proof of device state** for AI-managed networks.  VIRP complements Zero Trust by enforcing epistemic trust — trust in facts, not actors.

The core idea: the AI never talks to the network directly. A standalone observation node (O-Node) connects to devices, collects output, and signs every observation with HMAC-SHA256 at the point of collection. The AI receives signed observations read-only. It can analyze them, reason about them, and propose changes — but it cannot forge signatures for data it never collected.

```
┌─────────────────────────────────────────────────────┐
│                 VIRP Appliance (O-Node)              │
│                                                      │
│   SSH/API ──> Device ──> Raw Output ──> HMAC Sign    │
│                                                      │
│              O-Key never leaves this box             │
└──────────────────────┬───────────────────────────────┘
                       │ Signed observations
                       v
              ┌─────────────────┐
              │   AI Platform   │  <-- Can read. Cannot forge.
              │  (Any vendor)   │
              └─────────────────┘
```

## Two-Channel Architecture

VIRP separates all operations into two cryptographically isolated channels:

### Observation Channel (OC) — *What is the network doing?*

- O-Node connects to devices and collects data
- Every observation is signed with an **O-Key** (HMAC-SHA256)
- AI receives signed observations read-only
- O-Keys can only sign observations — enforced at code level before HMAC computation

### Intent Channel (IC) — *What should the network do?*

- AI proposes changes, signed with an **R-Key**
- Proposals must reference verified observations (proof of capability)
- Human approval required for execution
- R-Keys can only sign intents — channel-key binding is structural, not policy

An observation key cannot sign an intent message. An intent key cannot sign an observation. This isn't a configuration option. It's a `return VIRP_ERR_CHANNEL_VIOLATION` before the HMAC is even computed.

## Trust Tiers

| Tier | Behavior | Examples |
|------|----------|----------|
| GREEN | Auto-execute | `show` commands, diagnostics, health checks |
| YELLOW | Flag operator | Advanced troubleshooting, debug commands |
| RED | Human approval required | Configuration changes, ACL modifications |
| BLACK | Structurally impossible | Factory reset, key deletion, approval bypass |

BLACK tier commands don't have a "deny" rule. They don't exist in the wire format. You can't approve what the protocol can't express.

## Usage Examples

### 1. AI Operations Platform — Verified Network Queries

Your AI platform asks "show me BGP on R1." Instead of SSHing directly (where the AI could fabricate the response), it asks the VIRP appliance:

```bash
curl -X POST http://virp-appliance:8470/api/observe \
  -H "Content-Type: application/json" \
  -d '{"device": "R1", "command": "show ip bgp summary"}'
```

Response:

```json
{
  "observation": {
    "type": "OBSERVATION",
    "channel": "OBSERVATION",
    "trust_tier": "GREEN",
    "verified": true,
    "payload": "BGP router identifier 1.1.1.1, local AS number 100\nNeighbor  V  AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down  State/PfxRcd\n2.2.2.2   4 100    489     491     17   0    0 03:39:36       13",
    "timestamp_iso": "2026-03-01T17:11:13Z",
    "sequence": 42
  }
}
```

The AI presents this to the user with `verified: true`. If the AI tries to answer a question it has no observation for (like "what firewall policies exist on R1?"), it says "no verified data available" instead of making something up.

### 2. Automated Compliance Auditing

Sweep all devices and get verified results for audit reporting:

```python
import requests

VIRP = "http://virp-appliance:8470"
devices = requests.get(f"{VIRP}/api/devices").json()["devices"]

for device in devices:
    resp = requests.post(f"{VIRP}/api/observe", json={
        "device": device["name"],
        "command": "show access-lists"
    })
    obs = resp.json()["observation"]

    if obs["verified"]:
        if not obs["payload"].strip():
            print(f"WARNING {device['name']}: No ACLs configured")
        else:
            print(f"OK {device['name']}: ACLs present")
    else:
        print(f"FAIL {device['name']}: VERIFICATION FAILED")
```

Every finding is backed by a signed observation. Your audit report can prove the data is real.

### 3. Topology Discovery and Fault Detection

We used this to find a real dead link we didn't know about:

```bash
curl -X POST http://virp-appliance:8470/api/sweep \
  -H "Content-Type: application/json" \
  -d '{"commands": ["show ip ospf neighbor", "show ip bgp summary", "show arp"]}'
```

The AI correlated verified BGP state (`IDLE`), interface counters (`Last input: never`), and ARP tables (`Incomplete`) to trace a failed R7-R9 link down to Layer 2. Every piece of evidence was cryptographically signed. Zero fabricated data points.

### 4. Integration with Any LLM

VIRP doesn't care what AI you use. Wrap verified observations in your prompt:

```python
observation = get_virp_observation("R1", "show ip bgp summary")

if observation["verified"]:
    prompt = f"""
<virp_observation device="R1" verified="true" trust_tier="GREEN">
{observation['payload']}
</virp_observation>

Data in <virp_observation> tags is cryptographically verified.
NEVER fabricate device data. If no verified observation exists, say so.

Analyze the BGP status of R1.
"""
    response = llm.complete(prompt)
```

Works with Claude, GPT, Gemini, Llama, or any model. The trust anchor is the appliance, not the AI.

### 5. CI/CD Pipeline — Pre-Deploy Network Validation

Before pushing config changes, verify the network is in expected state:

```bash
#!/bin/bash
VIRP="http://virp-appliance:8470"

for router in R1 R7; do
  result=$(curl -s -X POST "$VIRP/api/observe" \
    -H "Content-Type: application/json" \
    -d "{\"device\": \"$router\", \"command\": \"show ip bgp summary\"}")

  verified=$(echo "$result" | jq -r '.observation.verified')
  payload=$(echo "$result" | jq -r '.observation.payload')

  if [ "$verified" != "true" ]; then
    echo "ABORT: Cannot verify $router BGP state"
    exit 1
  fi

  if echo "$payload" | grep -qE '(Idle|Active|Connect)'; then
    echo "ABORT: $router has unhealthy BGP peers"
    exit 1
  fi

  echo "OK: $router BGP verified healthy"
done

echo "All pre-deploy checks passed. Safe to proceed."
```

### 6. Prometheus/Grafana Monitoring

Export verified observations as metrics:

```python
from prometheus_client import start_http_server, Gauge, Counter
import requests, time

virp_observations = Counter('virp_observations_total', 'Total observations', ['device', 'verified'])
virp_sweep_duration = Gauge('virp_sweep_duration_seconds', 'Sweep duration')
VIRP = "http://virp-appliance:8470"

start_http_server(9470)

while True:
    start = time.time()
    devices = requests.get(f"{VIRP}/api/devices").json()["devices"]

    for dev in devices:
        resp = requests.post(f"{VIRP}/api/observe", json={
            "device": dev["name"],
            "command": "show ip interface brief"
        })
        obs = resp.json()["observation"]
        virp_observations.labels(device=dev["name"], verified=str(obs["verified"])).inc()

    virp_sweep_duration.set(time.time() - start)
    time.sleep(300)
```

### 7. Ansible — Verified Pre/Post Change Validation

```yaml
- name: Verified network state check
  hosts: localhost
  tasks:
    - name: Get verified BGP state from VIRP
      uri:
        url: "http://virp-appliance:8470/api/observe"
        method: POST
        body_format: json
        body:
          device: "R1"
          command: "show ip bgp summary"
      register: virp_result

    - name: Fail if observation not verified
      fail:
        msg: "VIRP observation not verified - cannot trust network state"
      when: not virp_result.json.observation.verified

    - name: Report verified state
      debug:
        msg: "BGP verified: {{ virp_result.json.observation.trust_tier }}"
```

### 8. Forensic Evidence Collection

When something goes wrong, VIRP provides cryptographically signed evidence:

```python
import requests, json
from datetime import datetime

VIRP = "http://virp-appliance:8470"
commands = [
    "show ip bgp summary", "show ip route", "show ip ospf neighbor",
    "show ip interface brief", "show access-lists", "show logging"
]

evidence = {"timestamp": datetime.utcnow().isoformat(), "observations": []}
devices = requests.get(f"{VIRP}/api/devices").json()["devices"]

for dev in devices:
    for cmd in commands:
        resp = requests.post(f"{VIRP}/api/observe", json={
            "device": dev["name"], "command": cmd
        })
        obs = resp.json()["observation"]
        obs["device"] = dev["name"]
        obs["command"] = cmd
        evidence["observations"].append(obs)

with open(f"forensic-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.json", "w") as f:
    json.dump(evidence, f, indent=2)

verified = sum(1 for o in evidence["observations"] if o["verified"])
print(f"Forensic snapshot: {verified}/{len(evidence['observations'])} observations verified")
```

Every observation in the evidence file is HMAC-signed. An investigator can verify the data was collected from real devices, not fabricated after the fact.

## Quick Start

### Build from source

```bash
# Dependencies (Ubuntu/Debian)
apt install -y build-essential libssl-dev libssh2-1-dev

# Build with Cisco IOS driver
cd virp
make CISCO=1 all

# Run tests (33 message library + 9 integration)
make test
make test-onode
```

### Generate keys

```bash
# Generate an Observation Key
./build/virp-tool keygen okey keys/onode.key

# Key fingerprint is printed — record it
# Permissions are set to 0600 automatically
```

### Configure devices

```bash
# Create a devices.json file
```

```json
{
  "devices": [
    {
      "hostname": "R1",
      "host": "192.168.1.1",
      "port": 22,
      "vendor": "cisco_ios",
      "username": "virp-svc",
      "password": "your-password",
      "enable": "your-enable",
      "node_id": "01010101"
    }
  ]
}
```

### Test against a live device

```bash
# Single device test with tamper verification
./build/virp-live-test 192.168.1.1 "show ip bgp summary"

# Expected output:
# HMAC:      VALID
# Channel:   OC (Observation)
# Tier:      GREEN
# Tamper test: PASS - tampered message correctly REJECTED
```

### Run the O-Node daemon

```bash
# Start with device config
./build/virp-onode -k keys/onode.key -s /tmp/virp-onode.sock -d devices.json

# Listens on Unix socket, accepts JSON requests:
# {"action": "execute", "device": "R1", "command": "show ip bgp summary"}
# Returns signed binary VIRP OBSERVATION messages
```

### Start the REST API

```bash
# Install Python dependencies
pip install fastapi uvicorn pydantic

# Start the API server
python api/server.py

# Dashboard: http://your-ip:8470
# API docs:  http://your-ip:8470/docs
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Appliance health, key status, uptime |
| `GET` | `/api/devices` | List registered devices |
| `POST` | `/api/observe` | Execute command, return signed observation |
| `POST` | `/api/sweep` | Topology sweep across all/selected devices |
| `GET` | `/api/observations` | Recent observation log |
| `GET` | `/api/key` | O-Key fingerprint (never exposes key material) |
| `POST` | `/api/devices/add` | Register a new device |
| `DELETE` | `/api/devices/{name}` | Remove a device |

## Wire Format

56-byte fixed header, variable payload, 32-byte HMAC-SHA256 signature:

```
┌──────────┬──────────┬──────────────────────┐
│ version  │  type    │    length (16-bit)    │
│  (8b)    │  (8b)    │                       │
├──────────┴──────────┼───────────────────────┤
│    node_id (32b)    │                       │
├─────────┬───────────┼───────────────────────┤
│ channel │   tier    │    reserved (16b)     │
│  (8b)   │   (8b)   │                       │
├─────────┴───────────┴───────────────────────┤
│             seq_num (32b)                    │
├──────────────────────────────────────────────┤
│           timestamp_ns (64b)                 │
├──────────────────────────────────────────────┤
│          HMAC-SHA256 (256 bits)              │
│             (32 bytes)                       │
├──────────────────────────────────────────────┤
│        payload (variable length)             │
│                 ...                          │
└──────────────────────────────────────────────┘
```

TLV extension system for future protocol evolution (geocode, vendor tags, prediction confidence, trace IDs).

## Message Types

| Type | Hex | Channel | Purpose |
|------|-----|---------|---------|
| OBSERVATION | `0x01` | OC | Signed device data |
| HELLO | `0x02` | OC | Peer introduction with key fingerprints |
| PROPOSAL | `0x10` | IC | AI-generated change request |
| APPROVAL | `0x11` | IC | Human authorization |
| INTENT_ADVERTISE | `0x20` | IC | Route/prefix reachability |
| INTENT_WITHDRAW | `0x21` | IC | Route withdrawal |
| HEARTBEAT | `0x30` | OC | Liveness + health metrics |
| TEARDOWN | `0xF0` | Both | Graceful shutdown |

## Device Drivers

The O-Node uses a pluggable driver interface. Each driver implements 5 functions:

```c
typedef struct virp_driver {
    const char   *name;
    virp_vendor_t vendor;
    virp_conn_t *(*connect)(const virp_device_t *device);
    virp_error_t (*execute)(virp_conn_t *conn, const char *cmd, virp_exec_result_t *result);
    void         (*disconnect)(virp_conn_t *conn);
    bool         (*detect)(virp_conn_t *conn);
    virp_error_t (*health_check)(virp_conn_t *conn);
} virp_driver_t;
```

**Included drivers:**
- Cisco IOS — SSH with legacy cipher support for older images (`aes256-cbc`, `diffie-hellman-group14-sha1`)
- Mock — testing without hardware

**Community-wanted drivers:**
- FortiGate (REST API + SSH)
- Juniper JunOS
- Palo Alto PAN-OS
- Linux (SSH/bash)
- Arista EOS
- Windows (WinRM/PowerShell)

PRs welcome for new drivers.

## Metrics

*From live lab testing:*

| Metric | Value |
|--------|-------|
| Total lines of C | ~6,800 |
| Source files | 20 |
| Automated tests | 42 (33 message library + 9 integration) |
| Fuzz testing rounds | 200,000+ |
| Crashes found | 0 |
| Live devices verified | 10 Cisco routers |
| Observations per sweep | 40 |
| Full sweep time | 8.8 seconds |
| HMAC verification rate | 100% |
| Tamper detection rate | 100% |
| Compiler warnings | 0 |

## What's Built

- Message library — wire format, signing, validation, 33 structural tests
- O-Node daemon — Unix socket, device execution, JSON device loader
- Cisco IOS driver — SSH with legacy cipher support for older images
- REST API + web dashboard — FastAPI server, real-time observation feed
- AI platform integration — verified observations consumed by LLM with anti-fabrication enforcement
- Topology sweep — 40 signed observations across 10 routers in 8.8 seconds
- Live fault detection — found a real dead L2 link via verified BGP/ARP/interface correlation

## What's Next

- Additional device drivers (FortiGate, Juniper, Palo Alto, Arista)
- Python/Go/Rust client libraries
- Peer protocol — O-Node to O-Node observation sharing over TCP/TLS
- Bridge node — VIRP-to-BGP translator for legacy coexistence
- Hardware appliance with TPM-backed keys and physical kill switch
- Formal verification (TLA+)
- Post-quantum cipher suites

## Origin Story

VIRP wasn't designed in a lab. It was built because our AI operations platform fabricated network data and we caught it.

The platform once presented three complete FortiGate firewall policies that never existed — with realistic UUIDs, correct syntax, proper formatting. Another time it reported security alerts from RFC 5737 documentation IPs (test addresses that don't exist on the real internet) and stamped them "Confidence: HIGH."

We had HMAC signing on the command executor. The AI bypassed it by generating fake output in its chat response text, never touching the code path that enforced signatures. The prompt said "don't fabricate." The AI said "sure" and then fabricated.

Every design decision in VIRP maps to a real failure. The protocol is the scar tissue.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Priority areas:
- New device drivers (FortiGate, Juniper, Palo Alto, Arista)
- Python/Go/Rust client libraries
- Formal protocol verification
- Performance benchmarks
- Documentation and examples

## License

[Apache License 2.0](LICENSE) — Free to use, modify, and distribute. Attribution required.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability disclosure policy.

## Author

**Nate Howard** — Founder, [Third Level IT LLC](https://thirdlevel.ai)

- 15+ years enterprise infrastructure engineering (Presidio, Sentinel Technologies)
- NSE3 (Fortinet), CCNA/CCNP track
- Built from real production failures, not academic theory

GitHub: [github.com/nhowardtli/virp](https://github.com/nhowardtli/virp)
https://zenodo.org/records/18830236
---

> *"Every observation is cryptographically signed. The AI cannot fabricate what the protocol won't sign."*
