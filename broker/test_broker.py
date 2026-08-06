#!/usr/bin/env python3
"""
test_broker.py — Stage-1 acceptance tests for the VIRP intent-broker.

Run as the interactive operator (uid 1000, socket-allowed), NOT root:

    python3 /opt/virp/broker/test_broker.py

What runs where, and why:

  FUNCTIONAL tests (positive + negatives) run against a broker instance
  this script spawns on 127.0.0.1:7421 as the INVOKING user. uid 1000
  is in the daemon's socket_allowed_uids, so the forward path can be
  proven end-to-end through the real gate today. The production unit
  runs as `virp-broker`, whose uid is NOT yet in the daemon allowlist —
  adding it is an operator step (edit devices.template.json + daemon
  restart), deliberately out of Stage-1 scope, like the firewall
  pinhole. The broker code under test is byte-identical either way.

  IDENTITY tests use sudo to prove virp-broker has no supplementary
  groups and cannot read /run/virp/devices.json.

  DEPLOYMENT checks confirm the production listener (7420) is bound to
  127.0.0.1 only and that no firewall rule references the broker port.

Copyright (c) 2026 Third Level IT LLC. All rights reserved.
"""

import json
import socket
import subprocess
import sys
import time

sys.path.insert(0, "/opt/virp/autopilot")
from virp_autopilot import parse_observation, TIER_NAMES  # noqa: E402

BROKER = "/opt/virp/broker/virp_broker.py"
TEST_PORT = 7421
PROD_PORT = 7420
GREEN_DEVICE = "clab-frr-ospf-frr1"
GREEN_COMMAND = 'vtysh -c "show ip ospf neighbor"'

PASS, FAIL, results = "PASS", "FAIL", []


def record(name, ok, detail=""):
    results.append((name, ok, detail))
    print("  [%s] %s%s" % (PASS if ok else FAIL, name,
                           (" — " + detail) if detail else ""), flush=True)


def broker_roundtrip(payload_bytes, port=TEST_PORT, timeout=90):
    """One request per connection: send, half-close, read reply to EOF."""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.sendall(payload_bytes)
        s.shutdown(socket.SHUT_WR)
        buf = b""
        while True:
            c = s.recv(65536)
            if not c:
                return buf
            buf += c
    finally:
        s.close()


def expect_broker_reject(name, payload_bytes, want_reason_substr):
    """The reply must be a broker_error — i.e. the broker rejected it
    itself; a daemon reply would be a signed binary observation."""
    raw = broker_roundtrip(payload_bytes)
    try:
        reply = json.loads(raw.decode())
        reason = reply.get("broker_error", "")
        ok = want_reason_substr in reason
        record(name, ok, "broker_error=%r" % reason)
    except (ValueError, UnicodeDecodeError):
        record(name, False, "reply was not a broker_error: %r..." % raw[:40])


def daemon_alive():
    # `health` answers with a bare 4-byte status code on this path, so
    # use list_devices: alive means a signed observation comes back.
    raw = broker_roundtrip(json.dumps({"action": "list_devices"}).encode())
    return len(raw) > 4 and b"broker_error" not in raw


def main():
    print("== VIRP intent-broker Stage-1 tests ==")

    # Spawn the functional test instance (same code as production).
    proc = subprocess.Popen(
        [sys.executable, BROKER, "--port", str(TEST_PORT)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(0.5)
    if proc.poll() is not None:
        print("FATAL: test broker failed to start:\n" + proc.stdout.read())
        return 1

    try:
        # ── POSITIVE: GREEN read through broker → daemon classifies ──
        print("\n-- positive: allowlisted execute reaches the real gate --")
        raw = broker_roundtrip(json.dumps({
            "action": "execute", "device": GREEN_DEVICE,
            "command": GREEN_COMMAND}).encode())
        obs = parse_observation(raw)
        tier = TIER_NAMES.get(obs.get("tier"), "?")
        record("execute GREEN read returns signed observation",
               "tier" in obs and obs.get("obs_type") == 0x07,
               "%d bytes, obs_type=0x%02x" % (len(raw), obs.get("obs_type", 0)))
        record("daemon CLASSIFIED it GREEN (gate not bypassed)",
               tier == "GREEN", "tier=%s seq=%s" % (tier, obs.get("seq")))

        # A config command through the same path must come back RED /
        # ERROR — proof the broker forwards into the gate, not around it.
        raw = broker_roundtrip(json.dumps({
            "action": "execute", "device": GREEN_DEVICE,
            "command": 'vtysh -c "configure terminal"'}).encode())
        obs = parse_observation(raw)
        record("gate still fires: config cmd rejected AT THE DAEMON",
               TIER_NAMES.get(obs.get("tier")) == "RED",
               "tier=%s obs_type=0x%02x" % (TIER_NAMES.get(obs.get("tier")),
                                            obs.get("obs_type", 0)))

        # ── NEGATIVE: broker rejects, daemon never sees these ──
        print("\n-- negative: rejected by the BROKER, never forwarded --")
        for action in ("shutdown", "chain_append", "sign_intent",
                       "no_such_action_xyz"):
            expect_broker_reject(
                "action=%s rejected" % action,
                json.dumps({"action": action}).encode(),
                "not in allowlist")
        expect_broker_reject(
            "encoded NUL (\\u0000) rejected",
            b'{"action": "execute", "device": "a\\u0000b", "command": "x"}',
            "NUL")
        expect_broker_reject(
            "raw NUL byte rejected",
            b'{"action": "health"}\x00', "NUL")
        expect_broker_reject(
            "non-object root (array) rejected",
            b'["action", "health"]', "not a JSON object")
        expect_broker_reject(
            "non-object root (string) rejected",
            b'"health"', "not a JSON object")
        expect_broker_reject(
            "oversized payload rejected",
            (b'{"action": "health", "pad": "' + b"A" * 30000 + b'"}'),
            "oversized")
        record("daemon still alive after shutdown attempt (health OK)",
               daemon_alive())

        # ── IDENTITY: virp-broker is credential-less ──
        print("\n-- identity: virp-broker --")
        groups = subprocess.run(["id", "-Gn", "virp-broker"],
                                capture_output=True, text=True).stdout.split()
        record("virp-broker has no supplementary groups",
               groups == ["virp-broker"], "groups=%s" % groups)
        r = subprocess.run(
            ["sudo", "-n", "-u", "virp-broker",
             "cat", "/run/virp/devices.json"], capture_output=True, text=True)
        record("virp-broker CANNOT read /run/virp/devices.json",
               r.returncode != 0 and not r.stdout,
               "rc=%d stderr=%s" % (r.returncode, r.stderr.strip()[:60]))

        # ── DEPLOYMENT: localhost bind only, no firewall change ──
        print("\n-- deployment: bind + firewall --")
        ss = subprocess.run(["ss", "-tln"], capture_output=True,
                            text=True).stdout
        # Column 4 of `ss -tln` is the LOCAL address; the peer column is
        # always 0.0.0.0:* for listeners and must not be matched.
        local_addrs = [l.split()[3] for l in ss.splitlines()[1:]
                       if l.split() and
                       l.split()[3].endswith(":%d" % PROD_PORT)]
        record("port %d bound on 127.0.0.1 only" % PROD_PORT,
               local_addrs == ["127.0.0.1:%d" % PROD_PORT],
               "local=%s" % (local_addrs or "no listener (unit down?)"))
        nft = subprocess.run(["sudo", "-n", "nft", "list", "ruleset"],
                             capture_output=True, text=True).stdout
        record("no firewall rule references port %d" % PROD_PORT,
               str(PROD_PORT) not in nft)

        # ── STAGE GATE (informational): daemon's own UID allowlist ──
        print("\n-- stage gate: daemon SO_PEERCRED allowlist --")
        probe = ("import socket,struct,json,sys\n"
                 "s=socket.socket(socket.AF_UNIX); s.settimeout(5)\n"
                 "s.connect('/run/virp/onode.sock')\n"
                 "p=json.dumps({'action':'health'}).encode()\n"
                 "s.sendall(struct.pack('>I',1+len(p))+b'\\x02'+p)\n"
                 "sys.exit(0 if s.recv(4) else 3)\n")
        r = subprocess.run(["sudo", "-n", "-u", "virp-broker",
                            "python3", "-c", probe],
                           capture_output=True, text=True)
        print("  [INFO] virp-broker → daemon socket: %s" %
              ("ACCEPTED (allowlist already updated)" if r.returncode == 0
               else "REJECTED by daemon UID allowlist (rc=%d) — EXPECTED "
                    "until the operator adds virp-broker's uid to "
                    "socket_allowed_uids and restarts virp-onode"
                    % r.returncode))
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    failed = [n for n, ok, _ in results if not ok]
    print("\n== %d/%d passed ==" % (len(results) - len(failed), len(results)))
    if failed:
        print("FAILED: " + "; ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
