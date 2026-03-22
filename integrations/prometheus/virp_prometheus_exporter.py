#!/usr/bin/env python3
"""VIRP Prometheus Exporter — reads chain.db (read-only) and exposes /metrics."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import struct
import socket
import sys
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Info,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
CHAIN_DB_PATH: str = os.environ.get("VIRP_CHAIN_DB", "/var/lib/virp/chain.db")
DEVICES_JSON_PATH: str = os.environ.get("VIRP_DEVICES_JSON", "/run/virp/devices.json")
LISTEN_PORT: int = int(os.environ.get("VIRP_EXPORTER_PORT", "9100"))
LISTEN_ADDR: str = os.environ.get("VIRP_EXPORTER_ADDR", "0.0.0.0")
POLL_INTERVAL: float = float(os.environ.get("VIRP_POLL_INTERVAL", "15"))

# ---------------------------------------------------------------------------
# Logging — structured JSON to journald (stderr)
# ---------------------------------------------------------------------------
class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        obj = {
            "ts": self.formatTime(record),
            "level": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
        }
        if record.exc_info and record.exc_info[0] is not None:
            obj["exc"] = self.formatException(record.exc_info)
        return json.dumps(obj)


log = logging.getLogger("virp-exporter")
log.setLevel(logging.INFO)
_handler = logging.StreamHandler(sys.stderr)
_handler.setFormatter(JSONFormatter())
log.addHandler(_handler)

# ---------------------------------------------------------------------------
# Prometheus registry & metrics
# ---------------------------------------------------------------------------
registry = CollectorRegistry()

chain_entries_total = Gauge(
    "virp_chain_entries_total",
    "Total entries in the VIRP chain",
    registry=registry,
)

chain_entries_by_type = Gauge(
    "virp_chain_entries_by_type",
    "Chain entries by artifact type",
    ["artifact_type"],
    registry=registry,
)

intents_total = Gauge(
    "virp_intents_total",
    "Total intents recorded",
    registry=registry,
)

intents_by_confidence = Gauge(
    "virp_intents_by_confidence",
    "Intents by confidence level",
    ["confidence"],
    registry=registry,
)

intents_by_tier = Gauge(
    "virp_intents_by_tier",
    "Intent proposed actions by trust tier",
    ["tier"],
    registry=registry,
)

devices_observed = Gauge(
    "virp_devices_observed",
    "Number of unique devices with observations",
    registry=registry,
)

observation_age_seconds = Gauge(
    "virp_observation_age_seconds",
    "Seconds since last observation for each device",
    ["device", "node_id"],
    registry=registry,
)

observation_count_by_device = Gauge(
    "virp_observation_count_by_device",
    "Total observations per device",
    ["device", "node_id"],
    registry=registry,
)

last_observation_timestamp = Gauge(
    "virp_last_observation_timestamp",
    "Unix epoch of the most recent observation",
    registry=registry,
)

observation_rate_per_minute = Gauge(
    "virp_observation_rate_per_minute",
    "Observation rate averaged over the last 10 minutes",
    registry=registry,
)

milestones_total = Gauge(
    "virp_milestones_total",
    "Total chain milestones",
    registry=registry,
)

onode_up = Gauge(
    "virp_onode_up",
    "1 if chain.db is readable and onode is producing entries, 0 otherwise",
    registry=registry,
)

exporter_info = Info(
    "virp_exporter",
    "VIRP Prometheus exporter metadata",
    registry=registry,
)
exporter_info.info({"version": "1.0.0", "chain_db": CHAIN_DB_PATH})

# ---------------------------------------------------------------------------
# Device mapping: node_id (hex) → hostname
# Uses device_registry (single source of truth) with legacy JSON fallback.
# ---------------------------------------------------------------------------
def _node_id_hex_to_int(hex_id: str) -> int:
    """Convert 8-char hex node_id from devices.json to the integer used in artifact_id."""
    return int(hex_id, 16)


def load_device_map() -> dict[int, str]:
    """Build node_id_int → hostname map.

    Tries device_registry.node_id_to_hostname() first (reads devices.yaml),
    falls back to parsing legacy JSON files.
    """
    # Try canonical device registry first
    try:
        import sys
        sys.path.insert(0, "/root/virp")
        from device_registry import node_id_to_hostname
        mapping = node_id_to_hostname()
        if mapping:
            log.info("Loaded %d device mappings from device_registry (devices.yaml)", len(mapping))
            return mapping
    except Exception as e:
        log.warning("device_registry unavailable, falling back to JSON: %s", e)

    # Legacy fallback — parse devices.json directly
    mapping: dict[int, str] = {}
    paths = [DEVICES_JSON_PATH, "/opt/virp/devices.json"]
    for path in paths:
        try:
            with open(path) as f:
                raw = f.read().strip()
            if raw.startswith("{"):
                obj = json.loads(raw)
                devices = obj.get("devices", []) if isinstance(obj, dict) else []
            elif raw.startswith("devices"):
                devices = json.loads(raw[raw.index("["):])
            else:
                devices = []
            for dev in devices:
                nid = dev.get("node_id", "")
                hostname = dev.get("hostname", "")
                if nid and hostname:
                    mapping[_node_id_hex_to_int(nid)] = hostname
            log.info("Loaded devices from %s (legacy fallback)", path)
            break
        except FileNotFoundError:
            continue
        except Exception as e:
            log.warning("Error parsing %s: %s", path, e)
            continue
    if not mapping:
        log.error("Could not load device mappings from any source")
    log.info("Loaded %d device mappings", len(mapping))
    return mapping


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    """Open chain.db in read-only mode."""
    conn = sqlite3.connect(
        f"file:{CHAIN_DB_PATH}?mode=ro",
        uri=True,
        timeout=5,
    )
    conn.row_factory = sqlite3.Row
    return conn


def safe_query(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[Any]:
    """Execute a query, returning rows. Returns empty list on error."""
    try:
        return conn.execute(sql, params).fetchall()
    except Exception as e:
        log.error("Query failed: %s — %s", sql[:80], e)
        return []


# ---------------------------------------------------------------------------
# Metric collection
# ---------------------------------------------------------------------------
def collect_metrics(device_map: dict[int, str]) -> None:
    """Read chain.db and update all Prometheus metrics."""
    try:
        conn = get_db()
    except Exception as e:
        log.error("Cannot open chain.db: %s", e)
        onode_up.set(0)
        return

    try:
        now_ns = time.time_ns()

        # --- chain_entries totals ---
        rows = safe_query(conn, "SELECT COUNT(*) AS cnt FROM chain_entries")
        total = rows[0]["cnt"] if rows else 0
        chain_entries_total.set(total)

        # --- by artifact_type ---
        rows = safe_query(
            conn,
            "SELECT artifact_type, COUNT(*) AS cnt FROM chain_entries GROUP BY artifact_type",
        )
        seen_types: set[str] = set()
        for row in rows:
            chain_entries_by_type.labels(artifact_type=row["artifact_type"]).set(row["cnt"])
            seen_types.add(row["artifact_type"])

        # --- intents total ---
        rows = safe_query(conn, "SELECT COUNT(*) AS cnt FROM intents")
        intents_total.set(rows[0]["cnt"] if rows else 0)

        # --- intents by confidence ---
        rows = safe_query(
            conn,
            "SELECT confidence, COUNT(*) AS cnt FROM intents GROUP BY confidence",
        )
        for row in rows:
            intents_by_confidence.labels(confidence=row["confidence"]).set(row["cnt"])

        # --- intents by tier (from proposed_actions JSON) ---
        rows = safe_query(conn, "SELECT proposed_actions FROM intents")
        tier_counts: dict[str, int] = {}
        for row in rows:
            try:
                actions = json.loads(row["proposed_actions"])
                for action in actions:
                    tier = action.get("tier", "UNKNOWN")
                    tier_counts[tier] = tier_counts.get(tier, 0) + 1
            except (json.JSONDecodeError, TypeError):
                pass
        for tier, count in tier_counts.items():
            intents_by_tier.labels(tier=tier).set(count)

        # --- observation freshness & per-device counts ---
        # Observations have artifact_id = "{node_id_int}:{seq}"
        rows = safe_query(
            conn,
            """SELECT artifact_id, MAX(timestamp_ns) AS last_ts, COUNT(*) AS cnt
               FROM chain_entries
               WHERE artifact_type = 'observation'
               GROUP BY CAST(SUBSTR(artifact_id, 1, INSTR(artifact_id, ':') - 1) AS INTEGER)""",
        )
        seen_devices: set[str] = set()
        for row in rows:
            aid: str = row["artifact_id"]
            colon = aid.index(":")
            nid_int = int(aid[:colon])
            hostname = device_map.get(nid_int, f"node_{nid_int}")
            node_hex = format(nid_int, "08X")

            age_s = (now_ns - row["last_ts"]) / 1e9
            observation_age_seconds.labels(device=hostname, node_id=node_hex).set(
                round(age_s, 1)
            )
            observation_count_by_device.labels(device=hostname, node_id=node_hex).set(
                row["cnt"]
            )
            seen_devices.add(hostname)

        devices_observed.set(len(seen_devices))

        # --- last observation timestamp ---
        rows = safe_query(
            conn,
            "SELECT MAX(timestamp_ns) AS ts FROM chain_entries WHERE artifact_type = 'observation'",
        )
        if rows and rows[0]["ts"]:
            last_ts_epoch = rows[0]["ts"] / 1e9
            last_observation_timestamp.set(round(last_ts_epoch, 3))

        # --- observation rate (last 10 minutes) ---
        window_ns = 10 * 60 * 1_000_000_000
        cutoff_ns = now_ns - window_ns
        rows = safe_query(
            conn,
            "SELECT COUNT(*) AS cnt FROM chain_entries WHERE artifact_type = 'observation' AND timestamp_ns > ?",
            (cutoff_ns,),
        )
        if rows:
            rate = rows[0]["cnt"] / 10.0  # per minute over 10 min window
            observation_rate_per_minute.set(round(rate, 2))

        # --- milestones ---
        rows = safe_query(conn, "SELECT COUNT(*) AS cnt FROM chain_milestones")
        milestones_total.set(rows[0]["cnt"] if rows else 0)

        # --- onode up (if we got here and there are entries, it's up) ---
        onode_up.set(1 if total > 0 else 0)

    except Exception as e:
        log.error("Error collecting metrics: %s", e)
        onode_up.set(0)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------
class MetricsHandler(BaseHTTPRequestHandler):
    """Serves /metrics and /health."""

    device_map: dict[int, str] = {}

    def do_GET(self) -> None:
        if self.path == "/metrics":
            collect_metrics(self.device_map)
            output = generate_latest(registry)
            self.send_response(200)
            self.send_header("Content-Type", CONTENT_TYPE_LATEST)
            self.end_headers()
            self.wfile.write(output)
        elif self.path == "/health":
            healthy = True
            try:
                conn = get_db()
                conn.execute("SELECT 1")
                conn.close()
            except Exception:
                healthy = False

            status = 200 if healthy else 503
            body = json.dumps({"status": "ok" if healthy else "error", "chain_db": CHAIN_DB_PATH})
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found\n")

    def log_message(self, fmt: str, *args: Any) -> None:
        # Suppress default stderr access logs; we use structured logging
        pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    log.info(
        "Starting VIRP Prometheus Exporter on %s:%d (db=%s, poll=%ss)",
        LISTEN_ADDR, LISTEN_PORT, CHAIN_DB_PATH, POLL_INTERVAL,
    )

    device_map = load_device_map()
    MetricsHandler.device_map = device_map

    # Initial metric collection
    collect_metrics(device_map)

    server = HTTPServer((LISTEN_ADDR, LISTEN_PORT), MetricsHandler)
    log.info("Listening on %s:%d", LISTEN_ADDR, LISTEN_PORT)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
