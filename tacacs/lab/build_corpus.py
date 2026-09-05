#!/usr/bin/env python3
"""Phase 2a: build the IOS command-respelling corpus from a real router.

For each command we type, capture what IOS put in the accounting `cmd=`
field. That is the ground truth the canonicalizer targets -- it is NOT
derived from anyone's memory of IOS.

The corpus is keyed by what was TYPED and records what was ACCOUNTED,
plus the mode it was typed in, plus the IOS version. Anything the
canonicalizer cannot reproduce from the typed form is a gap, not a
passthrough.
"""
import json, os, sqlite3, sys, time

SP = ("/tmp/claude-1000/-home-nhoward-virp/"
      "14778f44-c2e6-423e-a169-796579cee5fc/scratchpad")
LAB = SP + "/lab2"
sys.path.insert(0, SP)
sys.path.insert(0, "/home/nhoward/virp/tacacs")
from console import Console
import virp_tacacs_reconcile as rc

# Only THIS console session counts. The gate's watchdog runs `show clock`
# as virp-ro on a vty every few seconds, which made almost every capture
# AMBIGUOUS -- correctly, since the window really did contain someone
# else's command. Filtering by console port makes the window exclusive
# without weakening the refuse-to-guess rule.
CONSOLE_PORT = "tty0"

EXEC_CMDS = [
    "show version", "sh version", "sho ver", "show ver",
    "show ip interface brief", "sh ip int br", "show ip int brief",
    "show ip route", "sh ip ro", "show ip protocols",
    "show users", "sh users", "show inventory", "show clock",
    "show sessions", "show cdp neighbors", "sh cdp nei",
    "show processes cpu", "show memory statistics",
    "show interfaces Loopback0", "show interfaces lo0",
    "show interfaces GigabitEthernet0/0", "show int gi0/0",
    "show running-config | include hostname",
    "show running-config | begin line",
    "show ip interface brief | exclude unassigned",
    "SHOW VERSION", "Show Clock",
    "show   ip    route",
    "show file systems", "show logging",
    "show running-config", "sh run", "show ip bgp summary",
    "terminal length 0",
]
# CONFIG-MODE probes run ONLY against a throwaway loopback.
#
# The first version of this list included `shutdown`, `no ip address` and
# `interface GigabitEthernet0/0`. It ran them on R1's MANAGEMENT
# interface, took the lab link down mid-capture, and every command after
# that point recorded "no accounting record" -- because the router could
# no longer reach the accounting server. R1 needed its address put back
# by hand from the console.
#
# A corpus builder types commands for a living. It must not be able to
# type one that removes the path its own evidence travels over.
CORPUS_IF = "Loopback301"
CONFIG_CMDS = [
    "interface %s" % CORPUS_IF, "interface Loopback 301", "int lo301",
    "description CORPUS-TEST", "no description",
    "ip address 10.30.1.1 255.255.255.255", "no ip address",
    "shutdown", "no shutdown",
    "do show clock", "do sh ver",
    "logging buffered 16384",
]

# Destructive verbs are refused in ANY mode.
FORBIDDEN_ANYWHERE = ("reload", "write erase", "erase ", "format ")

# The management interface may be READ (a `show` is harmless and is a
# useful corpus row) but never CONFIGURED. That distinction is the whole
# lesson: the first version configured it.
MGMT_IF_TOKENS = ("gigabitethernet0/0", "gi0/0")


def _assert_safe(exec_cmds, config_cmds):
    for c in exec_cmds + config_cmds:
        low = c.lower()
        for bad in FORBIDDEN_ANYWHERE:
            if bad in low:
                raise SystemExit("corpus command %r is destructive (%r); "
                                 "refusing to run" % (c, bad))
    for c in config_cmds:
        low = c.lower()
        for bad in MGMT_IF_TOKENS:
            if bad in low:
                raise SystemExit(
                    "corpus CONFIG command %r targets the management "
                    "interface, which carries this tool's own evidence; "
                    "refusing to run" % c)


def receipts_since(seq_after):
    conn = sqlite3.connect("file:%s?mode=ro" % (LAB + "/chain.db"), uri=True)
    try:
        rows = conn.execute(
            "SELECT e.sequence, a.artifact_content FROM chain_entries e "
            "JOIN artifacts a ON a.artifact_hash=e.artifact_hash "
            "AND a.artifact_id=e.artifact_id "
            "WHERE e.session_id LIKE 'tacacs:%' AND e.sequence > ? "
            "ORDER BY e.sequence", (seq_after,)).fetchall()
    finally:
        conn.close()
    out = []
    for seq, content in rows:
        try:
            b = json.loads(content)
        except ValueError:
            continue
        if b.get("port") != CONSOLE_PORT:
            continue
        cmd = None
        for a in b.get("args", []):
            if a.startswith("cmd="):
                cmd = a[4:]
        if cmd is not None:
            out.append({"sequence": seq, "accounted_cmd": cmd,
                        "user": b.get("user"), "port": b.get("port")})
    return out


def max_seq():
    conn = sqlite3.connect("file:%s?mode=ro" % (LAB + "/chain.db"), uri=True)
    try:
        r = conn.execute("SELECT COALESCE(MAX(sequence),-1) FROM chain_entries "
                         "WHERE session_id LIKE 'tacacs:%'").fetchone()
    finally:
        conn.close()
    return r[0]


def main():
    _assert_safe(EXEC_CMDS, CONFIG_CMDS)
    c = Console(5000)
    c.send("terminal length 0", 1.5)
    entries = []

    def capture(typed, mode):
        """Refuses to guess.

        The first run of this collided with a config-apply job writing to
        the same console, and `got[-1]` cheerfully recorded that job's
        command as the accounting form of `show version`. A corpus that
        is the GROUND TRUTH cannot contain a guess, so an ambiguous
        capture is recorded as ambiguous and excluded from grading.
        """
        before = max_seq()
        c.run(typed, 3.0)
        time.sleep(1.8)
        got = receipts_since(before)
        if len(got) == 1:
            accounted, note = got[0]["accounted_cmd"], None
        elif not got:
            accounted, note = None, "no accounting record"
        elif len({g["accounted_cmd"] for g in got}) == 1:
            # Several receipts, all carrying the SAME string: a slow
            # command's record can land inside the next command's window.
            # Content-identical is not ambiguous, and refusing it loses a
            # real row (`sh run` was dropped this way).
            accounted = got[0]["accounted_cmd"]
            note = "%d receipts, all identical" % len(got)
        else:
            accounted = None
            note = ("AMBIGUOUS: %d receipts arrived in this window (%r) -- "
                    "another session was active; not recorded as truth"
                    % (len(got), [g["accounted_cmd"] for g in got][:4]))
        entries.append({"typed": typed, "mode": mode,
                        "accounted_cmd": accounted,
                        "receipts": len(got), "note": note})
        print("  %-42s -> %r%s" % (typed, accounted,
                                   "  [" + note + "]" if note else ""),
              flush=True)

    for cmd in EXEC_CMDS:
        capture(cmd, "exec")
    # `configure terminal` and `end` are captured as the transitions they
    # are: the compiler mints a `configure terminal` grant as the
    # config-mode prerequisite, so its canonical form has to come from
    # the router like every other.
    capture("configure terminal", "exec")
    for cmd in CONFIG_CMDS:
        capture(cmd, "config")
    capture("end", "config")
    c.run("no interface %s" % CORPUS_IF, 2)
    c.close()

    corpus = {
        "ios_version": "15.2(4)M7",
        "platform": "Cisco 7206VXR (NPE400), C7200-ADVENTERPRISEK9-M",
        "device": "R1",
        "captured_on_port": CONSOLE_PORT,
        "captured_utc_ns": time.time_ns(),
        "note": ("`accounted_cmd` is what IOS put in the accounting cmd= "
                 "field for the typed string. Ground truth; the "
                 "canonicalizer targets this, never the other way round."),
        "entries": entries,
    }
    out = "/home/nhoward/virp/tests/fixtures/ios_respelling_corpus.json"
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(corpus, f, indent=1, sort_keys=True)
        f.write("\n")
    print("corpus: %d entries -> %s" % (len(entries), out))
    print("CORPUS DONE", flush=True)


if __name__ == "__main__":
    main()
