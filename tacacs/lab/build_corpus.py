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
]
CONFIG_CMDS = [
    "interface Loopback301", "interface Loopback 301", "int lo301",
    "interface GigabitEthernet0/0", "int gi0/0",
    "description CORPUS-TEST", "no description",
    "no shutdown", "shutdown",
    "ip address 10.30.1.1 255.255.255.255", "no ip address",
    "do show clock", "do sh ver",
    "logging buffered 16384",
    "no logging console",
]


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
    c.run("configure terminal", 2.5)
    for cmd in CONFIG_CMDS:
        capture(cmd, "config")
    c.run("end", 2)
    c.run("no interface Loopback301", 2)
    c.close()

    corpus = {
        "ios_version": "15.2(4)M7",
        "platform": "Cisco 7206VXR (NPE400), C7200-ADVENTERPRISEK9-M",
        "device": "R1",
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
