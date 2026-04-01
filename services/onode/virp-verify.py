#!/usr/bin/env python3
"""
VIRP Chain Verification Service — read-only hash lookups against chain.db.

Listens on TCP 9996, accepts: VERIFY <hash>
Returns: CONFIRMED chain_id=<id> device=<name> timestamp=<iso> command=<cmd>
     or: NO_MATCH

Copyright (c) 2026 Third Level IT LLC. All rights reserved.
"""

import json
import os
import socket
import sqlite3
import sys
from datetime import datetime, timezone

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 9996
CHAIN_DB = "/var/lib/virp/chain.db"
DEVICES_JSON = "/opt/virp/devices.json"
MAX_LINE = 4096


def load_node_id_map():
    """Build signer_node_id (int) -> hostname from devices.json."""
    mapping = {}
    try:
        with open(DEVICES_JSON, "r") as f:
            data = json.load(f)
        devices = data.get("devices", data) if isinstance(data, dict) else data
        for dev in devices:
            nid_hex = dev.get("node_id", "")
            hostname = dev.get("hostname", "")
            if nid_hex and hostname:
                mapping[int(nid_hex, 16)] = hostname
    except Exception as e:
        print(f"[virp-verify] WARNING: could not load {DEVICES_JSON}: {e}",
              file=sys.stderr, flush=True)
    return mapping


def open_chain_db():
    """Open chain.db read-only via URI."""
    uri = f"file:{CHAIN_DB}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def lookup(conn, node_map, hash_input):
    """Look up a hash prefix or full hash in chain_entries + artifacts."""
    cur = conn.cursor()
    h = hash_input.lower().strip()

    if len(h) <= 12:
        # Prefix match — use LIKE (safe: h is validated hex below)
        cur.execute(
            """SELECT ce.id, ce.chain_hmac, ce.signer_node_id, ce.timestamp_ns,
                      ce.artifact_type, ce.artifact_id,
                      a.artifact_content
               FROM chain_entries ce
               LEFT JOIN artifacts a ON ce.artifact_id = a.artifact_id
               WHERE ce.chain_hmac LIKE ? || '%'
               ORDER BY ce.id DESC LIMIT 1""",
            (h,),
        )
    else:
        # Full hash — exact match
        cur.execute(
            """SELECT ce.id, ce.chain_hmac, ce.signer_node_id, ce.timestamp_ns,
                      ce.artifact_type, ce.artifact_id,
                      a.artifact_content
               FROM chain_entries ce
               LEFT JOIN artifacts a ON ce.artifact_id = a.artifact_id
               WHERE ce.chain_hmac = ?
               LIMIT 1""",
            (h,),
        )

    row = cur.fetchone()
    if not row:
        return "NO_MATCH"

    chain_id = row["id"]
    node_id = row["signer_node_id"]
    ts_ns = row["timestamp_ns"]
    content = row["artifact_content"] or row["artifact_id"]

    device = node_map.get(node_id, f"node:0x{node_id:08X}")
    ts_iso = datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    # Collapse multiline content to first meaningful line for the response
    cmd = content.strip().replace("\n", " | ") if content else "N/A"
    # Truncate to keep response sane
    if len(cmd) > 200:
        cmd = cmd[:197] + "..."

    return f"CONFIRMED chain_id={chain_id} device={device} timestamp={ts_iso} command={cmd}"


def is_valid_hex(s):
    """Check that string is valid hex."""
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def serve():
    node_map = load_node_id_map()
    print(f"[virp-verify] Loaded {len(node_map)} devices from {DEVICES_JSON}",
          file=sys.stderr, flush=True)

    # Verify chain.db is accessible
    conn = open_chain_db()
    count = conn.execute("SELECT COUNT(*) FROM chain_entries").fetchone()[0]
    print(f"[virp-verify] chain.db: {count} entries at {CHAIN_DB}",
          file=sys.stderr, flush=True)
    conn.close()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(8)
    print(f"[virp-verify] Listening on {LISTEN_HOST}:{LISTEN_PORT}",
          file=sys.stderr, flush=True)

    while True:
        client, addr = srv.accept()
        try:
            data = client.recv(MAX_LINE).decode("utf-8", errors="replace").strip()
            if not data:
                client.sendall(b"ERROR bad request\n")
                continue

            parts = data.split(None, 1)
            if len(parts) != 2 or parts[0].upper() != "VERIFY":
                client.sendall(b"ERROR usage: VERIFY <hash>\n")
                continue

            hash_input = parts[1].strip()
            if not is_valid_hex(hash_input) or len(hash_input) < 4:
                client.sendall(b"ERROR hash must be >= 4 hex characters\n")
                continue

            # Open a fresh read-only connection per query
            conn = open_chain_db()
            try:
                result = lookup(conn, node_map, hash_input)
            finally:
                conn.close()

            client.sendall((result + "\n").encode("utf-8"))

        except Exception as e:
            print(f"[virp-verify] error from {addr}: {e}",
                  file=sys.stderr, flush=True)
            try:
                client.sendall(b"ERROR internal\n")
            except Exception:
                pass
        finally:
            client.close()


if __name__ == "__main__":
    serve()
