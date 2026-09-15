#!/usr/bin/env python3
"""
virp-shell — a Cisco-IOS-style operator REPL for the VIRP O-Node.

Reads execute; config mode proposes and never applies (see below).
Phase 1 2026-09-14, phase 2a 2026-09-15. Runs as uid 988 (`virp-shell`,
group virp) and talks
to /run/virp/onode.sock as an ordinary socket client. Everything that
touches a device or the chain goes THROUGH the gate, so it is judged under
uid 988's tier ceiling and action allowlist and lands on the chain like any
other client. This file never reads chain.db, never runs anything as root,
and refuses to start as uid 0.

Normal gate actions this shell can emit:

    show devices            list_fleet
    show device <name>      health      (a chained `show version` on that device)
    show node               heartbeat   (node liveness)
    verify chain <sid> ...  chain_verify
    show chain [n]          list_sessions + chain_verify per session
    (config-R1)# <line>     execute     (phase 2a — see below)

Config mode (phase 2a, 2026-09-15): `enable` → `configure terminal` →
`device <name>` gives a `host(config-<name>)#` context where every line
is sent to that device THROUGH THE GATE as `execute`. uid 988 keeps its
GREEN ceiling, so: a GREEN read executes and returns signed output; a
YELLOW/RED change is NOT applied — the gate files a signed PROPOSAL and
this shell prints its id for an operator to `virp-tool approve` / `apply`
as uid 1000; BLACK is refused outright. Nothing on a device can be
changed from this seat alone. `show proposals` lists the proposals THIS
session filed (the daemon exposes no node-wide listing).

tests/test_virp_shell.py asserts that this set is exactly uid 988's
allowlist in deploy/devices.template.json, so a new command the uid cannot
run fails the build.

Local read-only commands (no gate, no root): show services / show log /
show version / show uid. `show log` and `show services` need journal read
(group systemd-journal); when that is missing they print
"% journal not readable at this uid" rather than failing.

Protocol: the v2 framing and the frame decoder are copied from the in-tree
clients (autopilot/virp_autopilot.py onode_send + parse_observation, also
carried verbatim by broker/virp_broker.py). This is deliberately NOT a
second protocol implementation — keep it byte-for-byte in step with those.

Reply signatures: the O-Node signs replies with the O-Key (HMAC-SHA256).
uid 988 holds no key, so this client CANNOT verify them. Every reply ends
with a fixed trailer saying so. This client never prints "VALID".
"""

# Demo deployments may set VIRP_SHELL_DEMO_SESSION=1 to record login and
# command correlations with chain_append/evidence_item. This additionally
# requires the DEMO template's uid policy; the production seat cannot append.
import cmd
import hashlib
import json
import os
import re
import shlex
import socket
import struct
import subprocess
import sys
import time
import uuid

try:
    import readline          # noqa: F401  (side effect: line editing in cmd)
except ImportError:          # pragma: no cover
    readline = None

# ── identity / paths ───────────────────────────────────────────────────

SHELL_UID = 988
SHELL_USER = "virp-shell"
# `enable` is a real identity change, not a flag: the wrapper re-runs this
# program as the admin seat through sudo (PASSWD rule, so the operator's own
# password is asked), and the gate judges that uid with its own (YELLOW)
# ceiling. The chain and the daemon log carry the uid, so the escalation is
# on the record. `disable` goes back the same way.
ADMIN_UID = 985
ADMIN_USER = "virp-shell-admin"
EXIT_ENABLE = 42       # wrapper: re-run as virp-shell-admin (sudo asks a password)
EXIT_DISABLE = 43      # wrapper: re-run as virp-shell
ONODE_SOCKET = os.environ.get("VIRP_SHELL_SOCKET", "/run/virp/onode.sock")
RENDERED_DEVICES = "/run/virp/devices.json"        # what the daemon loaded
TEMPLATE_DEVICES = "/etc/virp/devices.template.json"
INSTALL_DIR = "/usr/local/lib/virp"
DAEMON_BIN = os.path.join(INSTALL_DIR, "virp-onode-prod")
TOOL_BIN = os.path.join(INSTALL_DIR, "virp-tool")
DEPLOYED_MD = "/opt/virp/DEPLOYED.md"
ONODE_UNIT = "virp-onode"

TRAILER_FMT = "HMAC present, not verified by this client (no O-Key at uid %d)"


def trailer():
    """The fixed honesty line under every gate reply, naming the seat that
    actually received it (988 read seat, 985 admin seat, or whatever uid
    is running the file)."""
    return TRAILER_FMT % os.geteuid()

# ── the ONLY gate actions this shell emits ─────────────────────────────
# Keyed by resolved command path. tests/test_virp_shell.py compares the
# VALUES of this map against the template allowlist for uid 988.

COMMAND_ACTIONS = {
    "show devices": "list_fleet",
    "show device": "health",
    "show node": "heartbeat",
    "verify chain": "chain_verify",
    "config execute": "execute",       # only inside (config-<device>)#
    "show chain": "list_sessions",     # + one chain_verify per listed session
}

DEMO_ACTIONS = {"session record": "chain_append"}

PROPOSAL_RE = re.compile(r"proposal_id=([0-9a-f]{32})")
BLOCKED_RE = re.compile(r"tier gate blocked '(.*)' on '([^']+)' \(tier=([A-Z]+) max=([A-Z]+)\)")

# ── wire constants (include/virp.h) ────────────────────────────────────

HEADER_FMT = "!BBHIBBHIQ"        # 24 bytes, then 32-byte HMAC
HEADER_LEN = 24
HMAC_LEN = 32
FRAME_HDR = HEADER_LEN + HMAC_LEN  # 56

MSG_OBSERVATION = 0x01
MSG_HEARTBEAT = 0x30

TIER_NAMES = {0x00: "UNCLASSIFIED", 0x01: "GREEN", 0x02: "YELLOW",
              0x03: "RED", 0xFF: "BLACK"}

OBS_TYPES = {
    0x01: "prefix_reachable", 0x02: "link_state", 0x03: "peer_state",
    0x04: "forwarding_state", 0x05: "resource_state", 0x06: "security_state",
    0x07: "device_output", 0x08: "intent_signed", 0x09: "outcome_signed",
    0x0A: "chain_entry", 0x0B: "chain_verify", 0x0C: "intent_stored",
    0x0D: "intent_fetched", 0x0E: "intent_executed", 0x0F: "error",
    0x10: "validation_decision", 0x11: "approval_challenge",
    0x12: "approval_result",
}

SCOPES = {0x01: "local", 0x02: "adjacent", 0x03: "measured"}

VIRP_ERRORS = {
    -1: "NULL_PTR", -2: "BUFFER_TOO_SMALL", -3: "INVALID_VERSION",
    -4: "INVALID_TYPE", -5: "INVALID_CHANNEL", -6: "INVALID_TIER",
    -7: "INVALID_LENGTH", -8: "HMAC_FAILED", -9: "CHANNEL_VIOLATION",
    -10: "TIER_VIOLATION", -11: "REPLAY_DETECTED", -12: "NO_EVIDENCE",
    -13: "STALE_OBSERVATION", -14: "KEY_NOT_LOADED", -15: "MESSAGE_TOO_LARGE",
    -16: "RESERVED_NONZERO", -17: "CHAIN_DB", -18: "CHAIN_BROKEN",
    -19: "CHAIN_SEQUENCE", -20: "FED_KEY_VERSION", -21: "FED_REVOKED",
    -22: "FED_UNVERIFIED", -23: "TENANT_VIOLATION", -24: "INTENT_NOT_FOUND",
    -25: "INTENT_EXPIRED", -26: "INTENT_EXHAUSTED", -27: "VERSION_MISMATCH",
    -28: "ALGORITHM_MISMATCH", -29: "CHANNEL_UNSUPPORTED",
    -30: "SESSION_INVALID", -31: "CONTEXT_MISMATCH", -32: "CRYPTO",
    -33: "HOST_KEY_MISMATCH", -34: "HOST_KEY_UNKNOWN", -35: "PROTOCOL_VERSION",
    -36: "APPROVAL_EXPIRED", -37: "APPROVAL_REUSED",
    -38: "APPROVAL_HASH_MISMATCH", -39: "APPROVAL_DEVICE_MISMATCH",
    -40: "APPROVAL_BAD_SIGNATURE", -41: "APPROVAL_NOT_FOUND",
    -42: "APPROVAL_CONSUMED", -43: "APPROVAL_KEY_UNENROLLED",
    -44: "APPROVAL_KEY_DISABLED", -45: "NO_PROMPT", -46: "DUPLICATE_DEVICE",
    -47: "CHAIN_READONLY", -48: "OUTCOME_UNKNOWN", -49: "OBS_SIG_INVALID",
    -50: "ACTION_FORBIDDEN", -51: "DUPLICATE_MISMATCH",
    -52: "APPROVAL_STORE_UNREADABLE", -53: "EVIDENCE_UNAVAILABLE",
    -54: "TRANSPORT_WRITE", -55: "TRANSPORT_CLOSED",
    -56: "APPROVAL_STORE_ABSENT",
}


class GateError(Exception):
    """A '% ...' line the REPL prints. Transport, refusal and decode."""


# ── transport: copied from autopilot/virp_autopilot.py onode_send ──────

def onode_send(request, sock_path=ONODE_SOCKET, timeout=60):
    """v2 framing: send [4B len][0x02][JSON], receive [4B len][payload]."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sock_path)
        payload = json.dumps(request).encode()
        s.sendall(struct.pack(">I", 1 + len(payload)) + b"\x02" + payload)
        hdr = b""
        while len(hdr) < 4:
            c = s.recv(4 - len(hdr))
            if not c:
                raise IOError("short read on frame length")
            hdr += c
        n = struct.unpack(">I", hdr)[0]
        buf = b""
        while len(buf) < n:
            c = s.recv(n - len(buf))
            if not c:
                raise IOError("short read on frame body")
            buf += c
        return buf
    finally:
        s.close()


def gate(request, sock_path=None):
    """Submit one request; map transport failures to '% ' errors."""
    action = request.get("action")
    demo_append = (os.environ.get("VIRP_SHELL_DEMO_SESSION") == "1"
                   and action in DEMO_ACTIONS.values())
    if action not in COMMAND_ACTIONS.values() and not demo_append:
        # Belt and braces: the map above is the whole vocabulary.
        raise GateError("internal: action %r is not in this shell's vocabulary"
                        % action)
    try:
        return onode_send(request, sock_path or ONODE_SOCKET)
    except FileNotFoundError:
        raise GateError("gate unreachable: %s does not exist (is %s running?)"
                        % (sock_path or ONODE_SOCKET, ONODE_UNIT))
    except PermissionError:
        raise GateError("gate refused the connection at the socket "
                        "(uid %d is not permitted on %s)"
                        % (os.geteuid(), sock_path or ONODE_SOCKET))
    except socket.timeout:
        raise GateError("gate timeout: no reply from the O-Node")
    except (ConnectionError, IOError, OSError) as e:
        raise GateError("gate connection lost: %s"
                        % (getattr(e, "strerror", None) or e))


# ── decode: structure of autopilot parse_observation, plus heartbeat ───

def decode_reply(raw):
    """Return a dict describing the reply. Structure only: no signature
    check is possible here (see module docstring)."""
    if len(raw) == 4:
        (code,) = struct.unpack(">i", raw)
        return {"kind": "error", "code": code,
                "name": VIRP_ERRORS.get(code, "UNKNOWN")}
    if len(raw) < FRAME_HDR:
        raise GateError("undecodable reply: %d bytes is shorter than a header"
                        % len(raw))
    (version, mtype, length, node_id, channel, tier, reserved,
     seq, ts_ns) = struct.unpack(HEADER_FMT, raw[:HEADER_LEN])
    if length != len(raw):
        raise GateError("undecodable reply: header length %d != frame %d"
                        % (length, len(raw)))
    info = {
        "kind": "frame", "version": version, "msg_type": mtype,
        "node_id": node_id, "channel": channel, "tier": tier,
        "tier_name": TIER_NAMES.get(tier, "0x%02x" % tier),
        "seq": seq, "timestamp_ns": ts_ns,
        "hmac_hex": raw[HEADER_LEN:FRAME_HDR].hex(),
    }
    body = raw[FRAME_HDR:]
    if mtype == MSG_OBSERVATION:
        if len(body) < 4:
            raise GateError("undecodable observation: no TLV header")
        obs_type, obs_scope, data_len = struct.unpack("!BBH", body[:4])
        info.update(kind="observation",
                    obs_type=obs_type,
                    obs_type_name=OBS_TYPES.get(obs_type, "0x%02x" % obs_type),
                    scope=SCOPES.get(obs_scope, "0x%02x" % obs_scope),
                    text=body[4:4 + data_len].decode("utf-8", errors="replace"))
    elif mtype == MSG_HEARTBEAT:
        if len(body) < 12:
            raise GateError("undecodable heartbeat: %d-byte payload" % len(body))
        uptime, onode_ok, rnode_ok, active_obs, active_props = \
            struct.unpack("!IBBHI", body[:12])
        info.update(kind="heartbeat", uptime_seconds=uptime,
                    onode_ok=bool(onode_ok), rnode_ok=bool(rnode_ok),
                    active_observations=active_obs,
                    active_proposals=active_props)
    else:
        info.update(kind="frame", text="", raw_len=len(body))
    return info


# ── rendering helpers ──────────────────────────────────────────────────

def table(rows, headers):
    """Fixed-width table, IOS style. rows: list of tuples of str."""
    rows = [tuple(str(c) for c in r) for r in rows]
    widths = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(c))
    fmt = "  ".join("%%-%ds" % w for w in widths)
    out = [fmt % tuple(headers), fmt % tuple("-" * w for w in widths)]
    out += [fmt % r for r in rows]
    return "\n".join(line.rstrip() for line in out)


def ts_iso(ns):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ns / 1e9))


def header_lines(info):
    """The signed-header block printed above every gate reply."""
    kind = info["kind"]
    what = info.get("obs_type_name", kind)
    return [
        "node_id 0x%08x  seq %d  tier %s  type %s  scope %s  at %s" % (
            info["node_id"], info["seq"], info["tier_name"], what,
            info.get("scope", "-"), ts_iso(info["timestamp_ns"])),
        "hmac %s..%s" % (info["hmac_hex"][:8], info["hmac_hex"][-8:]),
    ]


def fmt_uptime(sec):
    d, r = divmod(int(sec), 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    return "%dd %02dh %02dm %02ds" % (d, h, m, s)


def parse_fleet_text(text):
    """list_fleet body:  'VIRP Fleet (N devices)' / 'Name Class Status' /
    dashes / one row per device; 'refused: ...' rows for rejected ones."""
    rows, refused, count = [], [], None
    for line in text.splitlines():
        m = re.match(r"VIRP Fleet \((\d+) devices\)", line)
        if m:
            count = int(m.group(1))
            continue
        if not line.strip() or line.startswith("---") or \
           line.split()[:2] == ["Name", "Class"]:
            continue
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        name, cls, status = parts
        if status.startswith("refused:"):
            refused.append((name, cls, status[len("refused:"):].strip()))
        else:
            rows.append((name, cls, status))
    return count, rows, refused


# ── IOS abbreviation expansion for device lines ────────────────────────
# The gate's Cisco classifier is deliberately literal and fail-closed:
# it vouches only for the canonical spellings in its table, so
# "sh ip int br" is unmatched and falls through RED (a proposal) while
# "show ip interface brief" is GREEN. The device would expand the
# abbreviation itself, so the honest fix is to expand BEFORE sending —
# then the classified bytes, the executed bytes and the chained bytes
# are all the canonical form, and the operator is shown what was sent.
# Only tokens in this curated map (or interface short names) change;
# anything else is passed through untouched. Applied only to devices
# whose fleet class is cisco_ios / cisco_iosxe.

IOS_VENDORS = ("cisco_ios", "cisco_iosxe")

IOS_WORDS = {
    "show": ("sh", "sho"),
    "interface": ("int", "inte", "inter", "interf", "interfa"),
    "brief": ("br", "bri", "brie"),
    "version": ("ver", "vers", "versi"),
    "running-config": ("run", "runn", "running", "running-c", "running-conf"),
    "startup-config": ("start", "startup", "startup-c", "startup-conf"),
    "configure": ("conf", "confi", "config"),
    "terminal": ("t", "term", "termi"),
    "description": ("des", "desc", "descr", "descri"),
    "route": ("ro", "rou", "rout"),
    "neighbors": ("nei", "neig", "neigh", "neighb", "neighbor"),
    "summary": ("sum", "summ", "summa"),
    "detail": ("det", "deta", "detai"),
    "clock": ("clo", "cloc"),
    "inventory": ("inv", "inve", "invent"),
    "environment": ("env", "envi", "environ"),
    "processes": ("proc", "proce", "process"),
    "memory": ("mem", "memo"),
    "logging": ("log", "logg", "loggi"),
    "users": ("us", "use"),
    "access-lists": ("acc", "acce", "access", "access-l", "access-list"),
    "spanning-tree": ("span", "spann", "spanning", "spanning-t"),
    "address-table": ("add", "addr", "address", "address-t"),
    "protocols": ("prot", "proto", "protoc"),
    "switchport": ("sw", "swi", "switch", "switchp"),
    "status": ("stat", "statu"),
    "counters": ("coun", "count", "counter"),
    "trunk": ("tr", "tru", "trun"),
    "shutdown": ("shut", "shutd"),
    "reload": ("rel", "relo", "reloa"),
    "write": ("wr", "wri", "writ"),
    "erase": ("era", "eras"),
    "copy": ("cop",),
    "ping": ("pi", "pin"),
    "traceroute": ("tra", "trac", "trace", "tracer"),
    "enable": ("en", "ena"),
    "password": ("pass", "passw"),
    "secret": ("sec", "secr"),
    "vlan": ("vl", "vla"),
    "hostname": ("host", "hostn"),
    "translations": ("trans", "transl"),
    "protocol": (),
}
IOS_ABBREV = {}
for _canon, _abbrs in IOS_WORDS.items():
    for _a in _abbrs:
        IOS_ABBREV[_a] = _canon

IOS_IFACES = [
    (re.compile(r"^(?:gi|gig|g|gigabitethernet)(\d[\d/.]*)$", re.I), "GigabitEthernet"),
    (re.compile(r"^(?:te|ten|tengigabitethernet)(\d[\d/.]*)$", re.I), "TenGigabitEthernet"),
    (re.compile(r"^(?:twe|twentyfivegige)(\d[\d/.]*)$", re.I), "TwentyFiveGigE"),
    (re.compile(r"^(?:hu|hundredgige)(\d[\d/.]*)$", re.I), "HundredGigE"),
    (re.compile(r"^(?:fa|fast|f|fastethernet)(\d[\d/.]*)$", re.I), "FastEthernet"),
    (re.compile(r"^(?:lo|loop|loopback)(\d+)$", re.I), "Loopback"),
    (re.compile(r"^(?:po|port-channel)(\d+)$", re.I), "Port-channel"),
    (re.compile(r"^(?:vl|vlan)(\d+)$", re.I), "Vlan"),
    (re.compile(r"^(?:tu|tunnel)(\d+)$", re.I), "Tunnel"),
]


def expand_ios(line):
    """Expand curated IOS abbreviations and interface short names to
    their canonical spellings. Unknown tokens pass through unchanged.
    Returns the (possibly identical) line."""
    out = []
    toks = line.split()
    for i, tok in enumerate(toks):
        low = tok.lower()
        if low in IOS_ABBREV:
            out.append(IOS_ABBREV[low])
        elif low in IOS_WORDS:
            out.append(low)
        else:
            # IOS rule: a unique prefix (2+ chars) of a known keyword is
            # that keyword; an ambiguous one is left alone (the gate then
            # fails closed to RED, exactly as the device would say
            # "% Ambiguous command").
            cands = [w for w in IOS_WORDS if len(low) >= 2 and w.startswith(low)]
            if len(cands) == 1:
                out.append(cands[0])
            else:
                for rx, canon in IOS_IFACES:
                    m = rx.match(tok)
                    if m:
                        tok = canon + m.group(1)
                        break
                out.append(tok)
        # Free text follows these keywords: copy the rest verbatim.
        if out[-1] in ("description", "hostname", "password", "secret"):
            out.extend(toks[i + 1:])
            break
    return " ".join(out)


READ_VERBS = ("show", "ping", "traceroute", "dir", "more", "test")


def is_read_verb(cmd):
    """A command that only reads/probes: a YELLOW/RED one still needs an
    approval to RUN, but nothing would be 'applied'. Drives the wording."""
    first = cmd.split()[0].lower() if cmd.split() else ""
    return first in READ_VERBS


OUTPUT_FILTERS = ("include", "exclude", "begin", "section", "count")


def split_output_filter(line):
    """'show run | include ntp' -> ('show run', ('include', 'ntp')).
    Only the IOS output filters are recognised; anything else after a
    pipe is left on the line for the gate to judge (it refuses '|')."""
    if " | " not in line:
        return line, None
    base, _, rest = line.partition(" | ")
    parts = rest.strip().split(None, 1)
    if not parts:
        return line, None
    kw = parts[0].lower()
    matches = [f for f in OUTPUT_FILTERS if f.startswith(kw)]
    if len(matches) != 1:
        return line, None
    kw = matches[0]
    arg = parts[1] if len(parts) > 1 else ""
    if kw != "count" and not arg:
        return line, None
    return base.rstrip(), (kw, arg)


def apply_output_filter(lines, filt):
    """Apply an IOS-style output filter to already-received lines."""
    kw, arg = filt
    try:
        rx = re.compile(arg) if arg else None
    except re.error:
        rx = re.compile(re.escape(arg))
    if kw == "include":
        return [l for l in lines if rx.search(l)]
    if kw == "exclude":
        return [l for l in lines if not rx.search(l)]
    if kw == "begin":
        for i, l in enumerate(lines):
            if rx.search(l):
                return lines[i:]
        return []
    if kw == "section":
        out, keep = [], False
        for l in lines:
            if l and not l[0].isspace():
                keep = bool(rx.search(l))
            if keep:
                out.append(l)
        return out
    if kw == "count":
        n = len([l for l in lines if (rx.search(l) if rx else True)])
        return ["Number of lines which match regexp = %d" % n]
    return lines


# ── the command tree + IOS-style abbreviation resolver ─────────────────
# node: {word: (subtree-or-None, min_args, max_args)}; None max = any.

COMMAND_TREE = {
    "show": {
        "devices": (None, 0, 0),
        "device": (None, 1, 1),
        "node": (None, 0, 0),
        "services": (None, 0, 0),
        "chain": (None, 0, 1),
        "proposals": (None, 0, 0),
        "uid": (None, 0, 1),
        "log": (None, 0, 1),
        "version": (None, 0, 0),
        "whoami": (None, 0, 0),
    },
    "verify": {
        "chain": (None, 1, 3),
    },
    "configure": {
        "terminal": (None, 0, 0),
    },
    "device": (None, 1, 1),
    "enable": (None, 0, 0),
    "disable": (None, 0, 0),
    "end": (None, 0, 0),
    "exit": (None, 0, 0),
    "quit": (None, 0, 0),
    "help": (None, 0, 0),
}

COMMAND_HELP = {
    "show": "Show gate, fleet and node information (read-only)",
    "verify": "Verify a chain session through the gate",
    "configure": "Enter configuration mode (from enable)",
    "show devices": "Fleet listing via the gate (list_fleet)",
    "show device": "Chained `show version` on one device via the gate (health), green ceiling",
    "show node": "O-Node liveness via the gate (heartbeat)",
    "show services": "systemctl list-units 'virp-*' (local, read-only)",
    "show chain": "Recent chain sessions (list_sessions), each verified (chain_verify)",
    "show proposals": "Proposals filed by THIS session (the daemon has no node-wide listing)",
    "show uid": "Per-uid allowlist and ceiling from the loaded template",
    "show log": "Last N journal lines for virp-onode (local, read-only)",
    "show version": "Installed binary sha256, build string, node_id, DEPLOYED.md head",
    "show whoami": "This seat: uid, user, tier ceiling and verbs the gate grants it",
    "verify chain": "chain_verify <session-id> [from] [to] via the gate",
    "configure terminal": "Enter config mode; then `device <name>` to pick the target",
    "device": "(config) Select the device the next lines are sent to, through the gate",
    "enable": "Become the admin seat (uid 985, YELLOW ceiling) — your password is asked",
    "disable": "Back to the read seat (uid 988, GREEN ceiling)",
    "end": "Return to privileged exec mode",
    "exit": "Leave the shell",
    "quit": "Leave the shell",
    "help": "This list",
}


PREFERRED = ("enable", "exit")


class Ambiguous(Exception):
    def __init__(self, word, choices):
        super().__init__(word)
        self.word, self.choices = word, sorted(choices)


def _match(word, choices):
    """IOS rule: exact match wins, else unique prefix, else ambiguous."""
    if word in choices:
        return [word]
    return [c for c in choices if c.startswith(word)]


def resolve(tokens):
    """Resolve abbreviated tokens against COMMAND_TREE.

    Returns (path, args) where path is the canonical command string.
    Raises Ambiguous or ValueError('% Invalid input ...').
    A prefix that matches several words (e.g. 'dev' -> device/devices)
    is disambiguated by ARITY when exactly one candidate fits the number
    of remaining tokens: 'sh dev' -> show devices, 'sh dev sw1' -> show
    device sw1. Otherwise it is reported ambiguous, as IOS would.
    """
    node = COMMAND_TREE
    path = []
    i = 0
    while i < len(tokens):
        word = tokens[i]
        if not isinstance(node, dict):
            break
        cands = _match(word.lower(), list(node.keys()))
        if not cands:
            raise ValueError("Invalid input detected at '%s'" % word)
        if len(cands) > 1:
            rest = len(tokens) - i - 1
            fits = []
            for c in cands:
                sub = node[c]
                if isinstance(sub, dict):
                    fits.append(c)          # deeper tree: cannot judge yet
                else:
                    _, lo, hi = sub
                    if lo <= rest and (hi is None or rest <= hi):
                        fits.append(c)
            if len(fits) > 1:
                # IOS precedent: 'en' is enable (end is a config-mode
                # verb there), 'ex' is exit. Prefer those over 'end'.
                pref = [c for c in fits if c in PREFERRED]
                if len(pref) == 1:
                    fits = pref
            if len(fits) != 1:
                raise Ambiguous(word, cands)
            cands = fits
        chosen = cands[0]
        path.append(chosen)
        sub = node[chosen]
        i += 1
        if isinstance(sub, dict):
            node = sub
            continue
        _, lo, hi = sub
        args = tokens[i:]
        if len(args) < lo or (hi is not None and len(args) > hi):
            raise ValueError("Incomplete command" if len(args) < lo
                             else "Invalid input detected at '%s'" % args[hi])
        return " ".join(path), args
    if isinstance(node, dict):
        raise ValueError("Incomplete command")
    return " ".join(path), []  # pragma: no cover


# Argument placeholders shown by '?' at a leaf, by position. IOS shows
# "WORD" for a free-form argument; these are never Tab-inserted.
ARG_HELP = {
    "show device": [("<name>", "Device hostname (see show devices)")],
    "device": [("<name>", "Device hostname (see show devices)")],
    "show uid": [("[uid]", "One uid, or all allowlisted uids")],
    "show log": [("[lines]", "Number of journal lines (default 20)")],
    "show chain": [("[sessions]", "Recent sessions to list and verify (default 10, max 200)")],
    "verify chain": [("<session-id>", "Chain session id (hex)"),
                     ("[from-sequence]", "First sequence to check"),
                     ("[to-sequence]", "Last sequence to check")],
}


def is_placeholder(word):
    return word.startswith("<") or word.startswith("[")


def completions(tokens, partial):
    """Words that could follow `tokens` and start with `partial`. At a
    leaf: the next argument placeholder while more are accepted, and
    <cr> once enough have been typed."""
    node = COMMAND_TREE
    path = []
    for i, word in enumerate(tokens):
        if not isinstance(node, dict):
            break
        cands = _match(word.lower(), list(node.keys()))
        if len(cands) != 1:
            return []
        path.append(cands[0])
        node = node[cands[0]]
    if isinstance(node, dict):
        return sorted(w for w in node if w.startswith(partial.lower()))
    _, lo, hi = node
    typed = tokens[len(path):]
    nargs = len(typed)
    out = []
    if hi is None or nargs < hi:
        slots = ARG_HELP.get(" ".join(path), [])
        out.append(slots[nargs][0] if nargs < len(slots) else "WORD")
    if nargs >= lo and not partial:
        out.append("<cr>")
    return out


# ── local (non-gate) read-only helpers ─────────────────────────────────

def _run(argv, timeout=20):
    """Run a read-only local command as THIS uid. Never sudo, never root."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise GateError("%s not found on this host" % argv[0])
    except subprocess.TimeoutExpired:
        raise GateError("%s timed out" % argv[0])
    return p.returncode, p.stdout, p.stderr


JOURNAL_DENIED = "journal not readable at this uid"


def journal_denied(rc, err):
    low = (err or "").lower()
    return rc != 0 and ("permission" in low or "no journal files" in low
                        or "not permitted" in low or "access denied" in low)


def load_uid_policy():
    """The daemon's loaded per-uid policy. Prefer the RENDERED file the
    daemon actually read; fall back to the template (placeholders shown
    as-is). Returns (doc, source_path)."""
    for path in (RENDERED_DEVICES, TEMPLATE_DEVICES):
        try:
            with open(path) as f:
                return json.load(f), path
        except (OSError, ValueError):
            continue
    raise GateError("template not readable at this uid (%s, %s)"
                    % (RENDERED_DEVICES, TEMPLATE_DEVICES))


def username(uid):
    try:
        import pwd
        return pwd.getpwuid(int(uid)).pw_name
    except (KeyError, ValueError, ImportError):
        return "?"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def deployed_head(path=DEPLOYED_MD, limit=6):
    """The 'Current live state' block's first bullet lines."""
    try:
        with open(path) as f:
            lines = f.read().splitlines()
    except OSError:
        return None
    out, inblock = [], False
    for line in lines:
        if line.startswith("## Current live state"):
            inblock = True
            out.append(line.lstrip("# ").strip())
            continue
        if inblock and line.startswith("- **"):
            out.append(line.strip())
            if len(out) > limit:
                break
        elif inblock and line.startswith("## "):
            break
    return out or None


# ── the REPL ───────────────────────────────────────────────────────────

class VirpShell(cmd.Cmd):
    intro = ("virp-shell — operator REPL for the VIRP O-Node (reads execute; "
             "config mode proposes, never applies). Type ? for commands.")
    doc_header = "Commands (abbreviations accepted, e.g. sh dev):"

    def __init__(self, sock_path=None, stdout=None, host=None, privileged=False):
        super().__init__(stdout=stdout)
        self.sock_path = sock_path or ONODE_SOCKET
        self.host = host or socket.gethostname().split(".")[0]
        self.privileged = privileged
        self.exit_code = 0          # EXIT_ENABLE / EXIT_DISABLE ask the wrapper to re-seat
        self.mode = "exec"          # exec | config
        self.device = None          # (config-<device>)# context
        self.proposals = []         # (when, device, command, tier, proposal_id)
        # Opt-in ONLY in the demo deployment. The production template does
        # not grant this seat chain_append. Session ids are random login
        # identifiers, not assertions of a visitor's real identity.
        self.demo_session = ("demo-" + uuid.uuid4().hex
                             if os.environ.get("VIRP_SHELL_DEMO_SESSION") == "1"
                             else None)
        self._set_prompt()
        if readline is not None:
            # IOS: '?' lists what can come next, at any point on the line,
            # with help text, and never submits the line.
            # '?' is a macro: insert it and submit. default() sees the
            # trailing '?', prints the list, and pre_input_hook re-types
            # the line so the operator keeps going, IOS-style.
            readline.parse_and_bind('"?": "\\C-v?\\n"')   # quoted-insert: no recursion
            readline.set_completer_delims(" \t\n")
            readline.set_completion_display_matches_hook(self._display_matches)
            readline.set_pre_input_hook(self._prefill_hook)
        self._prefill = ""

    # -- prompt / modes ---------------------------------------------------
    def _set_prompt(self):
        if self.mode == "config":
            ctx = "config-%s" % self.device if self.device else "config"
            self.prompt = "%s(%s)#" % (self.host, ctx)
        else:
            self.prompt = "%s%s" % (self.host, "#" if self.privileged else ">")

    def out(self, text=""):
        self.stdout.write(text + "\n")

    # -- dispatch ---------------------------------------------------------
    def parseline(self, line):
        # Route EVERYTHING through the resolver so abbreviations work.
        return None, None, line

    def precmd(self, line):
        # Scripted use (stdin not a terminal): input() does not echo, so a
        # transcript would show the prompt glued to the output. Echo the
        # command after the prompt the way a terminal would.
        if not sys.stdin.isatty() and line.strip():
            self.stdout.write(line + "\n")
        return line

    def emptyline(self):
        return False

    def default(self, line):
        line = line.strip()
        if not line:
            return False
        if line.endswith("?"):
            prefix = line[:-1]
            self.show_completions(prefix)
            self._prefill = prefix.rstrip() + (" " if prefix.endswith(" ") else "")
            if readline is not None:
                n = readline.get_current_history_length()
                if n and readline.get_history_item(n) == line:
                    readline.remove_history_item(n - 1)
            return False
        try:
            tokens = shlex.split(line)
        except ValueError as e:
            self.out("%% Invalid input: %s" % e)
            return False
        try:
            path, args = resolve(tokens)
        except Ambiguous as a:
            self.out("%% Ambiguous command: '%s' (%s)"
                     % (a.word, ", ".join(a.choices)))
            return False
        except ValueError as e:
            if self.mode == "config" and self.device:
                # Not a shell word: it is a line for the device, via the gate.
                # shlex may have mangled quotes; send the operator's raw line.
                try:
                    return self.cmd_config_execute(line)
                except GateError as ge:
                    self.out("% " + str(ge))
                    return False
            if self.mode == "config" and not self.device and \
               str(e).startswith("Invalid input"):
                self.out("% no device selected: device <name>")
                return False
            self.out("% " + str(e))
            if self.mode != "config" and str(e).startswith("Invalid input") \
               and tokens and _match(tokens[0].lower(), ["show"]) == ["show"]:
                # Looks like a device command typed at the O-Node prompt.
                self.out("% this prompt is the O-Node, not a device. To run "
                         "that on a device:  enable → configure terminal → "
                         "device <name> → %s" % line)
            return False
        handler = getattr(self, "cmd_" + path.replace(" ", "_"))
        try:
            return handler(args)
        except GateError as e:
            self.out("% " + str(e))
            return False

    def show_completions(self, prefix):
        tokens = prefix.split()
        partial = ""
        if tokens and not prefix.endswith(" "):
            partial = tokens.pop()
        words = completions(tokens, partial)
        if not words:
            if self.mode == "config" and self.device:
                self.out("% no device-side help through the gate: the line is "
                         "sent to %s exactly as typed (full command per line)"
                         % self.device)
            else:
                self.out("% Invalid input")
            return
        if "<name>" in words:
            # A device argument: list the fleet (through the gate) instead
            # of the bare placeholder, IOS-style. Falls back when the gate
            # cannot be reached.
            rows = self.fleet_rows()
            if rows is not None:
                shown = [r for r in rows if r[0].lower().startswith(partial.lower())]
                if not shown:
                    self.out("%% no device matches '%s'" % partial)
                    return
                self.out(table(shown, ("name", "vendor", "status")))
                return
        for w in words:
            if w == "<cr>":
                self.out("  <cr>")
            elif is_placeholder(w) or w == "WORD":
                help_ = dict(sum(ARG_HELP.values(), [])).get(w, "")
                self.out("  %-16s %s" % (w, help_))
            else:
                self.out("  %-12s %s" % (w, COMMAND_HELP.get(
                    " ".join(tokens + [w]), "")))

    # readline completion over the same tree. cmd.Cmd.complete() is NOT
    # used: it re-parses the line through parseline(), which this shell
    # short-circuits (cmd=None), and 'complete_' + None raises inside the
    # completer — readline swallows that silently and Tab/? after the
    # first word never completed (found live on virp-lab, 2026-09-15).
    def complete(self, text, state):
        if state == 0:
            line = readline.get_line_buffer() if readline else ""
            begidx = readline.get_begidx() if readline else 0
            tokens = line[:begidx].split()
            words = completions(tokens, text)
            self.completion_matches = [w + " " for w in words
                                       if w != "<cr>" and w != "WORD"
                                       and not is_placeholder(w)]
            if "<name>" in words:
                self.completion_matches = [n + " " for n in self.device_names(text)]
        try:
            return self.completion_matches[state]
        except IndexError:
            return None

    # -- fleet cache for device-name listing / completion ------------------
    FLEET_TTL = 30.0

    def fleet_rows(self):
        """[(name, vendor, status)] via list_fleet, cached FLEET_TTL seconds.
        None when the gate cannot answer (the caller falls back)."""
        now = time.time()
        cached = getattr(self, "_fleet", None)
        if cached and now - cached[0] < self.FLEET_TTL:
            return cached[1]
        try:
            info = self._reply({"action": COMMAND_ACTIONS["show devices"]})
        except GateError:
            return None
        _, rows, _ = parse_fleet_text(info.get("text", ""))
        self._fleet = (now, rows)
        return rows

    def device_names(self, partial=""):
        rows = self.fleet_rows() or []
        return [r[0] for r in rows if r[0].lower().startswith(partial.lower())]

    def _display_matches(self, substitution, matches, longest):
        """IOS-style '?' listing: word + one-line help, then the prompt
        and the line the operator was typing are redrawn."""
        line = readline.get_line_buffer()
        tokens = line[:readline.get_begidx()].split()
        self.stdout.write("\n")
        for m in matches:
            w = m.strip()
            self.stdout.write("  %-12s %s\n" % (
                w, COMMAND_HELP.get(" ".join(tokens + [w]), "")))
        self.stdout.write(self.prompt + line)
        self.stdout.flush()
        if hasattr(readline, "redisplay"):
            readline.redisplay()

    def _prefill_hook(self):
        """After a '?' listing, re-type the operator's line at the new
        prompt (IOS keeps what you had typed)."""
        if self._prefill:
            readline.insert_text(self._prefill)
            self._prefill = ""
            if hasattr(readline, "redisplay"):
                readline.redisplay()

    # -- gate-backed commands ---------------------------------------------
    def _reply(self, request):
        record = self.demo_session and request.get("action") in ("execute", "health")
        if record:
            self._demo_record("request", request)
        raw = gate(request, self.sock_path)
        info = decode_reply(raw)
        if record:
            try:
                self._demo_record("reply", {
                    "request": request,
                    "observation_sha256": hashlib.sha256(raw).hexdigest(),
                    "proposal_ids": PROPOSAL_RE.findall(info.get("text", "")),
                    "reply_kind": info.get("kind"),
                    "observation_type": info.get("obs_type_name"),
                })
            except GateError as exc:
                info["demo_record_warning"] = (
                    "device request returned, but demo receipt failed; "
                    "do not retry automatically: %s" % exc)
        if info["kind"] == "error":
            raise GateError("gate refused: VIRP_ERR_%s (%d); no device "
                            "output was produced" % (info["name"], info["code"]))
        return info

    def _demo_record(self, event, detail):
        """Demo-only correlation metadata; never pretends to verify an HMAC.

        The daemon owns signing and admission. These evidence_item bodies
        name the visitor session and correlate a reply by digest; they are
        not copies of the full observation, nor daemon execution outcomes.
        """
        body = json.dumps({"schema": "virp-demo-session/1", "event": event,
                           "session_id": self.demo_session, "detail": detail},
                          sort_keys=True, separators=(",", ":"))
        if len(body.encode()) >= 8191:
            raise GateError("demo session record too large; request not submitted")
        reply = decode_reply(gate({
            "action": "chain_append", "artifact_type": "evidence_item",
            "artifact_id": "demo-" + uuid.uuid4().hex,
            "session_id": self.demo_session,
            "artifact_hash": hashlib.sha256(body.encode()).hexdigest(),
            "artifact_content": body,
        }, self.sock_path))
        if reply.get("kind") == "error" or reply.get("obs_type_name") == "error":
            raise GateError("demo session append refused: %s" % reply)

    def _print_signed(self, info, body_lines):
        for line in header_lines(info):
            self.out(line)
        for line in body_lines:
            self.out(line)
        self.out(trailer())
        if info.get("demo_record_warning"):
            self.out("% WARNING: " + info["demo_record_warning"])

    def cmd_show_devices(self, args):
        info = self._reply({"action": COMMAND_ACTIONS["show devices"]})
        count, rows, refused = parse_fleet_text(info.get("text", ""))
        self._fleet = (time.time(), rows)      # warm the ?/Tab device cache
        body = []
        if count is not None:
            body.append("VIRP fleet: %d devices" % count)
        body.append(table(rows, ("name", "vendor", "status")))
        if refused:
            body.append("")
            body.append(table(refused, ("refused", "vendor", "reason")))
        self._print_signed(info, body)

    def cmd_show_device(self, args):
        (device,) = args
        info = self._reply({"action": COMMAND_ACTIONS["show device"],
                            "device": device})
        text = info.get("text", "").rstrip("\n")
        body = ["device %s — chained `show version` under this uid's "
                "ceiling" % device] + text.splitlines()
        self._print_signed(info, body)

    def cmd_show_node(self, args):
        info = self._reply({"action": COMMAND_ACTIONS["show node"]})
        if info["kind"] != "heartbeat":
            raise GateError("unexpected reply to heartbeat: %s" % info["kind"])
        rows = [
            ("node_id", "0x%08x" % info["node_id"]),
            ("uptime", fmt_uptime(info["uptime_seconds"])),
            ("onode_ok", "yes" if info["onode_ok"] else "NO"),
            ("rnode_ok", "yes" if info["rnode_ok"] else "NO"),
            ("active_observations", info["active_observations"]),
            ("active_proposals", info["active_proposals"]),
        ]
        self._print_signed(info, [table(rows, ("field", "value"))])

    def cmd_verify_chain(self, args):
        sid = args[0]
        req = {"action": COMMAND_ACTIONS["verify chain"], "session_id": sid}
        try:
            if len(args) > 1:
                req["from_sequence"] = int(args[1])
            if len(args) > 2:
                req["to_sequence"] = int(args[2])
        except ValueError:
            raise GateError("from/to must be integers")
        info = self._reply(req)
        try:
            res = json.loads(info.get("text", "") or "{}")
        except ValueError:
            raise GateError("chain_verify reply was not JSON")
        rows = [
            ("session", sid),
            ("valid", "yes" if res.get("valid") else "NO"),
            ("entries_checked", res.get("entries_checked", "?")),
            ("executions_open", res.get("executions_open", "?")),
            ("first_broken", res.get("first_broken", "?")),
            ("from_sequence", res.get("from_sequence", "?")),
            ("to_sequence", res.get("to_sequence", "?")),
        ]
        body = [table(rows, ("field", "value"))]
        if not res.get("entries_checked"):
            body.append("(no entries under this session id — check the id; "
                        "valid=NO here means nothing was checked)")
        self._print_signed(info, body)

    # -- local read-only commands -----------------------------------------
    def cmd_show_services(self, args):
        rc, out, err = _run(["systemctl", "list-units", "--all", "--plain",
                             "--no-legend", "--no-pager", "virp-*"])
        if journal_denied(rc, err):
            raise GateError(JOURNAL_DENIED)
        if rc != 0:
            raise GateError("systemctl failed: %s" % err.strip())
        rows = []
        for line in out.splitlines():
            parts = line.split(None, 4)
            if len(parts) >= 4:
                rows.append(tuple(parts[:4]) + (parts[4] if len(parts) > 4 else "",))
        if not rows:
            self.out("% no virp-* units on this host")
            return
        self.out(table(rows, ("unit", "load", "active", "sub", "description")))

    def cmd_show_log(self, args):
        n = 20
        if args:
            try:
                n = max(1, min(int(args[0]), 5000))
            except ValueError:
                raise GateError("line count must be an integer")
        rc, out, err = _run(["journalctl", "-u", ONODE_UNIT, "-n", str(n),
                             "--no-pager", "-o", "short-iso"])
        if journal_denied(rc, err) or "No journal files" in out:
            raise GateError(JOURNAL_DENIED)
        if rc != 0:
            raise GateError("journalctl failed: %s" % err.strip())
        for line in out.splitlines():
            self.out(line)

    def cmd_show_version(self, args):
        rows = []
        for label, path in (("daemon", DAEMON_BIN), ("virp-tool", TOOL_BIN)):
            try:
                rows.append((label + " sha256", sha256_file(path)))
            except OSError as e:
                rows.append((label + " sha256", "%% unreadable (%s)"
                             % (e.strerror or e)))
        rc, out, err = _run([TOOL_BIN, "version"])
        build = out.strip().splitlines()[-1] if out.strip() else \
            "%% unavailable (%s)" % (err.strip().splitlines()[-1] if err.strip() else rc)
        rows.append(("build", build))
        try:
            hb = self._reply({"action": COMMAND_ACTIONS["show node"]})
            rows.append(("node_id", "0x%08x" % hb["node_id"]))
        except GateError as e:
            rows.append(("node_id", "% " + str(e)))
        self.out(table(rows, ("field", "value")))
        head = deployed_head()
        if head:
            self.out("")
            self.out("DEPLOYED.md — " + head[0])
            for line in head[1:]:
                self.out("  " + line)
        else:
            self.out("%% %s not readable at this uid" % DEPLOYED_MD)

    def cmd_show_uid(self, args):
        doc, src = load_uid_policy()
        allowed = [str(u) for u in doc.get("socket_allowed_uids", [])]
        ceilings = {str(k): v for k, v in
                    (doc.get("socket_uid_tier_ceilings") or {}).items()}
        actions = {str(k): v for k, v in
                   (doc.get("socket_uid_action_allow") or {}).items()}
        types = {str(k): v for k, v in
                 (doc.get("socket_uid_chain_append_types") or {}).items()}
        want = [args[0]] if args else allowed
        rows = []
        for u in want:
            if u not in allowed and u not in actions:
                raise GateError("uid %s is not in the loaded allowlist" % u)
            import textwrap
            acts = textwrap.wrap(" ".join(actions.get(u, [])) or "-", 56) or ["-"]
            typs = textwrap.wrap(" ".join(types.get(u, [])) or "-", 30) or ["-"]
            for i in range(max(len(acts), len(typs))):
                rows.append((u if i == 0 else "", username(u) if i == 0 else "",
                             ceilings.get(u, "node-wide") if i == 0 else "",
                             acts[i] if i < len(acts) else "",
                             typs[i] if i < len(typs) else ""))
        self.out("policy source: %s" % src)
        self.out(table(rows, ("uid", "user", "ceiling", "actions",
                              "chain_append types")))

    def cmd_show_chain(self, args):
        """Recent sessions via list_sessions, then chain_verify on each:
        sessions / entries / broken / seconds since the last write."""
        n = 10
        if args:
            try:
                n = max(1, min(int(args[0]), 200))
            except ValueError:
                raise GateError("session count must be an integer")
        if self.demo_session:
            self._demo_record("view_chain", {})
            self.out("Your demo session: %s" % self.demo_session)
            # Check it explicitly even if concurrent visitors push it out
            # of the requested recent-session window between the two calls.
            self.cmd_verify_chain([self.demo_session])
        info = self._reply({"action": COMMAND_ACTIONS["show chain"], "limit": n})
        try:
            doc = json.loads(info.get("text", "") or "{}")
            sessions = doc["sessions"]
        except (ValueError, KeyError):
            raise GateError("list_sessions reply was not the expected JSON")
        now_ns = time.time() * 1e9
        rows, broken = [], 0
        for s in sessions:
            sid = s.get("session_id", "?")
            try:
                # verify the WHOLE listed range; without to_sequence the
                # daemon checks 0..0 (one entry) and reports valid for it
                v = self._reply({"action": COMMAND_ACTIONS["verify chain"],
                                 "session_id": sid,
                                 "from_sequence": int(s.get("first_sequence", 0)),
                                 "to_sequence": int(s.get("last_sequence", 0))})
                res = json.loads(v.get("text", "") or "{}")
                valid = "yes" if res.get("valid") else "NO"
                checked = res.get("entries_checked", "?")
                fb = res.get("first_broken", -1)
                opened = res.get("executions_open", "?")
                if not res.get("valid"):
                    broken += 1
            except GateError as e:
                valid, checked, fb, opened = "% " + str(e), "?", "?", "?"
            age = max(0, (now_ns - s.get("last_timestamp_ns", now_ns)) / 1e9)
            rows.append((sid, s.get("entries", "?"),
                         "%s-%s" % (s.get("first_sequence", "?"), s.get("last_sequence", "?")),
                         valid, checked, fb if fb not in (-1, None) else "-",
                         opened, "%ds" % age))
        body = ["chain sessions: %d listed of the most recent %d%s; %d broken"
                % (doc.get("count", len(rows)), doc.get("limit", n),
                   " (listing truncated)" if doc.get("truncated") else "", broken),
                table(rows, ("session", "entries", "range", "valid", "checked",
                             "first_broken", "exec_open", "last_write"))]
        self._print_signed(info, body)

    def cmd_show_proposals(self, args):
        if not self.proposals:
            self.out("% no proposals filed by this session (the daemon "
                     "exposes no node-wide listing; show node reports a count)")
            return
        rows = [(ts_iso(w * 1e9), d, tier, pid, c)
                for (w, d, c, tier, pid) in self.proposals]
        self.out(table(rows, ("filed", "device", "tier", "proposal_id", "command")))
        self.out("approve/apply as an operator:  virp-tool approve <id>  then  virp-tool apply <id>")

    # -- modes / misc -----------------------------------------------------
    def cmd_enable(self, args):
        if self.privileged:
            return False
        if os.geteuid() == SHELL_UID and sys.stdin.isatty():
            # Real escalation: hand back to the wrapper, which re-runs this
            # program as virp-shell-admin through a PASSWD sudo rule. The
            # password prompt is sudo's; a wrong password lands you back
            # here at '>'. Session-local state (show proposals) does not
            # cross the seat boundary — the chain has it.
            self.out("Escalating to the admin seat (%s, uid %d) — sudo will ask "
                     "for your password." % (ADMIN_USER, ADMIN_UID))
            self.exit_code = EXIT_ENABLE
            return True
        # Not the read seat (a bare uid running the file, tests, scripts):
        # mode only, and say so — the gate still judges this uid's ceiling.
        self.privileged = True
        self._set_prompt()
        if os.geteuid() not in (SHELL_UID, ADMIN_UID):
            self.out("%% mode only: uid %d keeps its own ceiling (see show whoami)"
                     % os.geteuid())

    def cmd_disable(self, args):
        if os.geteuid() == ADMIN_UID and sys.stdin.isatty():
            self.out("Back to the read seat (%s, uid %d)." % (SHELL_USER, SHELL_UID))
            self.exit_code = EXIT_DISABLE
            return True
        self.privileged = False
        self.mode, self.device = "exec", None
        self._set_prompt()

    def cmd_show_whoami(self, args):
        uid = os.geteuid()
        seat = {SHELL_UID: "read seat", ADMIN_UID: "admin seat"}.get(uid, "not a shell seat")
        rows = [("uid", uid), ("user", username(uid)), ("seat", seat),
                ("mode", "privileged" if self.privileged else "exec")]
        try:
            doc, src = load_uid_policy()
            u = str(uid)
            ceilings = {str(k): v for k, v in (doc.get("socket_uid_tier_ceilings") or {}).items()}
            actions = {str(k): v for k, v in (doc.get("socket_uid_action_allow") or {}).items()}
            allowed = [str(x) for x in doc.get("socket_allowed_uids", [])]
            rows.append(("allowlisted", "yes" if u in allowed else "NO — the gate refuses this uid"))
            rows.append(("ceiling", ceilings.get(u, "node-wide (%s)" % doc.get("gate_max_tier", "?"))))
            rows.append(("verbs", " ".join(actions.get(u, [])) or "-"))
            rows.append(("policy", src))
        except GateError as e:
            rows.append(("policy", "% " + str(e)))
        self.out(table(rows, ("field", "value")))
        self.out("GREEN reads execute; YELLOW applies only at or above a YELLOW ceiling, "
                 "else a proposal; RED is always a proposal; BLACK never runs.")

    def cmd_end(self, args):
        # IOS: end leaves config mode and lands in privileged exec.
        self.mode, self.device = "exec", None
        self._set_prompt()

    def cmd_configure_terminal(self, args):
        if not self.privileged:
            self.out("% configure terminal requires enable")
            return
        self.mode, self.device = "config", None
        self._set_prompt()
        self.out("Config mode: device <name>, then each line goes to that "
                 "device through the gate as uid %d (GREEN ceiling)." % SHELL_UID)
        self.out("Changes are NOT applied here: YELLOW/RED file a signed "
                 "proposal for an operator to approve; BLACK is refused.")
        self.out("Each line is sent on its own (no interface sub-mode): write "
                 "full commands, e.g.  interface Gi1/0/48 description uplink")

    def cmd_device(self, args):
        if self.mode != "config":
            self.out("% device is a config-mode command (configure terminal)")
            return
        self.device = args[0]
        self._set_prompt()

    def cmd_config_execute(self, line):
        """(config-<device>)#: send one line to the device through the gate.
        IOS abbreviations are expanded first for cisco_ios/cisco_iosxe
        devices (see expand_ios); the operator is told what was sent."""
        # IOS output filters ("| include x") are applied HERE, to the signed
        # output, never sent: the gate refuses '|' as a separator by design.
        base, filt = split_output_filter(line)
        sent = base
        if self.device_vendor(self.device) in IOS_VENDORS:
            sent = expand_ios(base)
        info = self._reply({"action": COMMAND_ACTIONS["config execute"],
                            "device": self.device, "command": sent})
        text = info.get("text", "").rstrip("\n")
        note = ["sent as: %s" % sent] if sent != base else []
        if info.get("obs_type_name") == "error":
            m = BLOCKED_RE.search(text)
            pid = PROPOSAL_RE.search(text)
            if m and pid:
                tier = m.group(3)
                self.proposals.append((time.time(), self.device, sent, tier,
                                       pid.group(1)))
                verb = ("PROPOSED (needs approval to run)" if is_read_verb(sent)
                        else "PROPOSED, not applied")
                body = ["%s: '%s' on %s is %s; this seat's ceiling is %s"
                        % (verb, sent, self.device, tier, m.group(4)),
                        "proposal_id %s" % pid.group(1),
                        "operator: virp-tool approve %s && virp-tool apply %s"
                        % (pid.group(1), pid.group(1))]
            elif m:
                body = ["REFUSED: '%s' on %s is %s (ceiling %s); no proposal "
                        "was filed" % (sent, self.device, m.group(3), m.group(4))]
            else:
                body = ["device error (signed, %s): %s"
                        % (info["tier_name"], re.sub(r"^ERROR:\s*", "", text))]
            self._print_signed(info, note + body)
            return False
        lines = text.splitlines()
        if filt:
            # The device echoes the command as its first line ("SW-3850#show
            # clock"); it is not output, so it is neither filtered nor counted.
            if lines and lines[0].rstrip().endswith(sent) and "#" in lines[0]:
                lines = lines[1:]
            kept = apply_output_filter(lines, filt)
            note.append("filtered locally: | %s %s (%d of %d lines shown; the "
                        "chained observation is the full output)"
                        % (filt[0], filt[1], len(kept), len(lines)))
            lines = kept
        self._print_signed(info, note + ["%s: '%s' executed (%s)"
                                         % (self.device, sent, info["tier_name"])]
                           + lines)
        return False

    def device_vendor(self, name):
        """Fleet class of a device from the cached list_fleet, or None."""
        for n, vendor, _ in (self.fleet_rows() or []):
            if n == name:
                return vendor
        return None

    def cmd_exit(self, args):
        if self.mode == "config":
            if self.device:
                self.device = None
            else:
                self.mode = "exec"
            self._set_prompt()
            return False
        return True

    cmd_quit = cmd_exit

    def cmd_help(self, args):
        for path in sorted(COMMAND_HELP):
            self.out("  %-20s %s" % (path, COMMAND_HELP[path]))

    def do_EOF(self, line):
        self.out("")
        return True


# ── entry point ────────────────────────────────────────────────────────

def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if os.geteuid() == 0:
        sys.stderr.write("%% refusing to run as root; use the %s wrapper "
                         "(uid %d)\n" % (SHELL_USER, SHELL_UID))
        return 2
    if os.geteuid() not in (SHELL_UID, ADMIN_UID):
        sys.stderr.write("%% note: running as uid %d, not %d (%s) or %d (%s); the "
                         "gate judges the PEER uid, so this session is not a "
                         "virp-shell seat\n" % (os.geteuid(), SHELL_UID, SHELL_USER,
                                                ADMIN_UID, ADMIN_USER))
    sock_path = None
    once = None
    privileged = False
    while argv:
        a = argv.pop(0)
        if a == "--socket" and argv:
            sock_path = argv.pop(0)
        elif a == "-c" and argv:
            once = argv.pop(0)
        elif a == "--privileged":
            privileged = True
        else:
            sys.stderr.write("usage: virp-shell [--socket PATH] [--privileged] [-c 'command']\n")
            return 2
    if privileged and os.geteuid() != ADMIN_UID:
        # The flag only means something when the wrapper actually re-seated
        # us; a bare uid asking for it gets the mode, not the ceiling.
        sys.stderr.write("%% note: --privileged as uid %d, not %d (%s); the gate "
                         "judges the PEER uid\n" % (os.geteuid(), ADMIN_UID, ADMIN_USER))
    sh = VirpShell(sock_path=sock_path, privileged=privileged)
    if once is not None:
        sh.default(once)
        return 0
    if sh.demo_session:
        try:
            sh._demo_record("login", {})
        except GateError as exc:
            sys.stderr.write("%% demo session could not start: %s\n" % exc)
            return 2
        sh.intro += "\nYour demo session: %s" % sh.demo_session
    motd_path = os.environ.get("VIRP_SHELL_MOTD")
    if motd_path:
        try:
            with open(motd_path, encoding="utf-8") as motd_file:
                motd = motd_file.read(16385)
            if len(motd) > 16384:
                raise ValueError("MOTD exceeds 16384 characters")
            if any(ord(c) < 32 and c not in "\n\t" for c in motd):
                raise ValueError("MOTD contains terminal control characters")
        except (OSError, UnicodeError, ValueError) as exc:
            sys.stderr.write("%% cannot load VIRP_SHELL_MOTD: %s\n" % exc)
            return 2
        sh.intro += "\n\n" + motd.rstrip()
    try:
        sh.cmdloop()
    except KeyboardInterrupt:
        sh.out("")
    return sh.exit_code


if __name__ == "__main__":
    sys.exit(main())
