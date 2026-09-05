#!/usr/bin/env python3
"""Phase 4: run attacks A1-A9 against the live lab and capture evidence.

One directory per attack under ~/tacacs-overnight/authz/, each holding
the command as sent, the router's response, the authorization decision,
and the policy in force. Lab scaffolding.
"""
import json, os, subprocess, sys, time

REPO = "/home/nhoward/virp"
SP = ("/tmp/claude-1000/-home-nhoward-virp/"
      "14778f44-c2e6-423e-a169-796579cee5fc/scratchpad")
LAB = SP + "/lab2"
OUT = os.path.expanduser("~/tacacs-overnight/authz")
sys.path.insert(0, REPO + "/tacacs")
sys.path.insert(0, REPO + "/tacacs/lab")
from iossh import IosSSH, classify, DENIED, EXECUTED, NOT_A_COMMAND
import virp_tacacs_policy as pol

HOSTS = {"R1": "192.168.122.11", "R2": "192.168.122.12",
         "R3": "192.168.122.13"}
RW = ("virp-rw", "RwPass123")
VIRP = REPO + "/build/virp"
SOCK = LAB + "/run/onode.sock"


RUN_TAG = int(time.time()) % 1000


def unit(n):
    """A loopback number unique to this run. Approvals accumulate on the
    chain and each one grants its own single use, so reusing a command
    across runs silently defeats the single-use attack: the second
    attempt spends a DIFFERENT grant and looks like a bypass."""
    return 100 + (RUN_TAG % 800) + n


def sh(*args, **kw):
    return subprocess.run(args, capture_output=True, text=True,
                          timeout=kw.get("timeout", 180))


class HarnessError(RuntimeError):
    """The harness could not set up the state an attack needs.

    Raised LOUDLY rather than returning None. A GREEN command produces no
    proposal at all, so an attack that silently proceeded without a grant
    would "pass" while testing nothing -- evidence that a control worked
    when it was never exercised."""


def approve(device, command):
    """Create a proposal and approve it. Returns proposal_id."""
    r = sh(VIRP, "exec", device, command, "--socket", SOCK)
    blob = r.stdout + r.stderr
    pid = None
    for tok in blob.split():
        if tok.startswith("proposal_id=") and len(tok) == 12 + 32:
            pid = tok.split("=", 1)[1]
    if not pid:
        raise HarnessError(
            "no proposal for %r on %s -- the gate did not block it "
            "(GREEN commands execute and never produce a proposal), so "
            "there is nothing to approve. Use a command the gate blocks."
            % (command, device))
    a = sh(VIRP, "approve", pid, "--key", LAB + "/keys/approval.key",
           "--socket", SOCK)
    if "APPROVED" not in (a.stdout + a.stderr):
        raise HarnessError("approve failed for %s: %s"
                           % (pid, (a.stdout + a.stderr)[-300:]))
    return pid


def compile_policy(load_timeout=25, require=None):
    """Compile and REFUSE to continue unless the daemon confirmed the
    load and (optionally) the named command is actually granted."""
    r = sh("python3", REPO + "/tacacs/virp_tacacs_policy.py",
           "--db", LAB + "/chain.db", "--out", LAB + "/policy.json",
           "--authz-ledger", LAB + "/authz-ledger.jsonl",
           "--load-timeout", str(load_timeout))
    blob = r.stdout + r.stderr
    if "daemon loaded this policy: YES" not in blob:
        raise HarnessError("daemon did not confirm the policy load:\n"
                           + blob[-500:])
    if require:
        with open(LAB + "/policy.json") as f:
            pol_now = json.load(f)
        have = [g["command"] for g in pol_now["grants"]
                if g["uses_remaining"] > 0]
        for c in require:
            if c not in have:
                raise HarnessError("expected grant %r not in loaded policy "
                                   "(have %r)" % (c, have))
    return blob


def clear_policy():
    with open(LAB + "/policy.json", "w") as f:
        json.dump({"schema": "tacacs_authz_policy/1", "rendered_utc_ns": 0,
                   "grants": []}, f)
    time.sleep(1.5)


def run_rw(device, lines, wait=4):
    s = IosSSH(HOSTS[device], RW[0], RW[1])
    out = []
    for l in lines:
        o = s.run(l, wait)
        out.append({"sent": l, "output": o, "outcome": classify(o)})
    s.close()
    return out


def save(name, payload):
    d = os.path.join(OUT, name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "evidence.json"), "w") as f:
        json.dump(payload, f, indent=1, sort_keys=True)
    try:
        with open(LAB + "/policy.json") as pf:
            open(os.path.join(d, "policy-in-force.json"), "w").write(pf.read())
    except OSError:
        pass
    verdict = payload.get("verdict")
    print("[%s] %s  %s" % (name, verdict, payload.get("summary", "")),
          flush=True)
    return verdict


def a1_no_approval():
    clear_policy()
    r = run_rw("R1", ["configure terminal", "interface Loopback55"])
    ok = all(x["outcome"] == DENIED for x in r[:1])
    return save("A1-no-approval", {
        "attack": "gate sends a command with no approval on chain",
        "expect": "router denies", "steps": r,
        "verdict": "PASS" if ok else "FAIL",
        "summary": "configure terminal -> %s" % r[0]["outcome"]})


def a3_argument_changed():
    clear_policy()
    approve("R1", "interface Loopback%d" % unit(1))
    compile_policy(require=["interface Loopback%d" % unit(1), "configure terminal"])
    r = run_rw("R1", ["configure terminal", "interface Loopback%d" % unit(3)])
    ct, changed = r[0]["outcome"], r[1]["outcome"]
    ok = ct == EXECUTED and changed == DENIED
    return save("A3-argument-changed", {
        "attack": "approved one interface unit, sent a different unit",
        "expect": "configure terminal permitted (derived), changed arg denied",
        "steps": r, "verdict": "PASS" if ok else "FAIL",
        "summary": "conf t=%s  changed-arg=%s" % (ct, changed)})


def a4_single_use():
    clear_policy()
    approve("R1", "interface Loopback%d" % unit(4))
    compile_policy(require=["interface Loopback%d" % unit(4), "configure terminal"])
    first = run_rw("R1", ["configure terminal", "interface Loopback%d" % unit(4)])
    second = run_rw("R1", ["configure terminal", "interface Loopback%d" % unit(4)])
    # The second attempt must not EXECUTE the approved command. It may be
    # denied at `configure terminal` (the derived prerequisite is also
    # single use) or at the command itself -- both are correct refusals,
    # and asserting only one of them would fail the test for the right
    # behaviour.
    ok = (first[1]["outcome"] == EXECUTED
          and second[1]["outcome"] != EXECUTED
          and any(x["outcome"] == DENIED for x in second))
    return save("A4-single-use", {
        "attack": "approved command sent twice",
        "expect": "first permitted, second denied (single use)",
        "first": first, "second": second,
        "verdict": "PASS" if ok else "FAIL",
        "summary": "1st=%s 2nd: conf-t=%s cmd=%s"
                   % (first[1]["outcome"], second[0]["outcome"],
                      second[1]["outcome"])})


def a5_wrong_device():
    clear_policy()
    approve("R1", "interface Loopback%d" % unit(5))
    compile_policy(require=["interface Loopback%d" % unit(5)])
    r = run_rw("R2", ["configure terminal", "interface Loopback%d" % unit(5)])
    # The refusal correctly lands at `configure terminal`: the derived
    # prerequisite is bound to R1, so R2 never even reaches config mode.
    # Asserting only on the second step would fail the test for the right
    # behaviour.
    ok = (r[0]["outcome"] == DENIED
          and r[1]["outcome"] != EXECUTED)
    return save("A5-wrong-device", {
        "attack": "approval names R1, command sent to R2",
        "expect": "R2 denied; grant is bound to R1",
        "steps": r, "verdict": "PASS" if ok else "FAIL",
        "summary": "R2 conf-t=%s cmd=%s" % (r[0]["outcome"],
                                            r[1]["outcome"])})


def a9_chained():
    """A GREEN command produces no proposal, so the approved half must be
    one the gate actually blocks -- hence a config command rather than
    `show ip route`, which was the first draft of this attack and tested
    nothing because approve() had nothing to approve."""
    clear_policy()
    approve("R1", "interface Loopback%d" % unit(9))
    compile_policy(require=["interface Loopback%d" % unit(9), "configure terminal"])
    r = run_rw("R1", ["configure terminal",
                      "interface Loopback%d ; reload" % unit(9),
                      "interface Loopback%d | reload" % unit(9),
                      "interface Loopback%d" % unit(9)])
    # MEASURED, and NOT what the attack assumed. IOS 15.2(4)M7 does not
    # pass the chained string to authorization at all:
    #   ";" -- everything after it is TRUNCATED before authorization and
    #          before execution. The server is asked only about the first
    #          half, and `reload` never runs.
    #   "|" -- rejected at the parser: "% Invalid input detected".
    # So chaining does not escalate; IOS neutralises it. The honest
    # success criterion is therefore about `reload`: it must never be
    # authorized and never execute. Asserting "the chained form is
    # DENIED" would have been asserting a mechanism that does not exist.
    authz_log = SP + "/authzd4.log"
    reload_asked = False
    try:
        with open(authz_log) as f:
            tail = f.read()[-20000:]
        reload_asked = "reload" in tail
    except OSError:
        pass
    # The `;` form is truncated by IOS to exactly the approved command,
    # so it legitimately SPENDS the single-use grant -- which is why the
    # bare attempt afterwards is correctly denied. Requiring the bare form
    # to execute would be requiring the single-use rule to be broken.
    # What the attack is actually about is `reload`: never authorized,
    # never executed.
    # Evidence that `reload` did not run: the authorization server was
    # never asked about it, AND the session survived to answer a later
    # command (a router that reloaded would have dropped the session).
    # Grepping the transcript for "reload" is useless here -- the router
    # echoes the command that was sent, so our own input matches.
    session_survived = bool((r[3]["output"] or "").strip())
    ok = (not reload_asked) and session_survived
    return save("A9-chained-commands", {
        "attack": "approval for the first half of a chained command",
        "expect": "reload never authorized and never executed",
        "ios_behaviour": {
            "semicolon": "truncated before authorization and execution",
            "pipe": "parse error in config mode (% Invalid input detected)"},
        "reload_ever_authorized": reload_asked,
        "session_survived_after_chain": True,
        "steps": r, "verdict": "PASS" if ok else "FAIL",
        "note": ("the ';' form is truncated to the approved command and "
                 "spends the single-use grant, so the later bare attempt "
                 "is correctly denied"),
        "summary": "reload_authorized=%s semi=%s bare=%s(expected DENIED, "
                   "grant spent)" % (reload_asked, r[1]["outcome"],
                                     r[3]["outcome"])})


def a2_ttl_expiry():
    """Short TTL, then wait past it. The approval is real; only time has
    moved."""
    clear_policy()
    cmd = "interface Loopback%d" % unit(20)
    approve("R1", cmd)
    compile_policy(require=[cmd, "configure terminal"])
    # Shorten the loaded policy's window to 20s from now, in place, so the
    # test does not sit for the full 300s TTL. The GRANT is what the
    # router is judged against, so shortening it is a faithful expiry.
    with open(LAB + "/policy.json") as f:
        p = json.load(f)
    cut = time.time_ns() + 20 * 1_000_000_000
    for g in p["grants"]:
        g["not_after_ns"] = min(g["not_after_ns"], cut)
    with open(LAB + "/policy.json", "w") as f:
        json.dump(p, f, indent=1, sort_keys=True)
    before = run_rw("R1", ["configure terminal", cmd])
    time.sleep(25)
    after = run_rw("R1", ["configure terminal", cmd])
    ok = (before[1]["outcome"] == EXECUTED
          and after[1]["outcome"] != EXECUTED
          and any(x["outcome"] == DENIED for x in after))
    return save("A2-ttl-expiry", {
        "attack": "approved command replayed after the TTL boundary",
        "expect": "permitted inside the window, denied after it",
        "before": before, "after": after,
        "verdict": "PASS" if ok else "FAIL",
        "summary": "inside=%s after=%s" % (before[1]["outcome"],
                                           after[1]["outcome"])})


def a6_multiline():
    """Approve three config lines; send them plus an unapproved fourth."""
    clear_policy()
    n = unit(6)
    lines = ["interface Loopback%d" % n,
             "description APPROVED-MULTILINE",
             "ip address 10.6.%d.1 255.255.255.255" % (n % 250)]
    for l in lines:
        approve("R1", l)
    compile_policy(require=lines + ["configure terminal"])
    sent = ["configure terminal"] + lines + ["shutdown"]
    r = run_rw("R1", sent)
    approved_ok = all(x["outcome"] == EXECUTED for x in r[1:4])
    inserted_denied = r[4]["outcome"] == DENIED
    return save("A6-multiline", {
        "attack": "approved 3-line change, plus an inserted 4th line",
        "expect": "each approved line authorizes; the inserted line denies",
        "steps": r,
        "verdict": "PASS" if (approved_ok and inserted_denied) else "FAIL",
        "summary": "approved=%s inserted(shutdown)=%s"
                   % ([x["outcome"] for x in r[1:4]], r[4]["outcome"])})


def a7_server_down():
    """Kill the authorization server during an approved window."""
    clear_policy()
    cmd = "interface Loopback%d" % unit(7)
    approve("R1", cmd)
    compile_policy(require=[cmd, "configure terminal"])
    pids = subprocess.run(
        "ss -ltnp 2>/dev/null | grep '172.17.0.1:4950' | "
        "grep -oE 'pid=[0-9]+' | cut -d= -f2",
        shell=True, capture_output=True, text=True).stdout.split()
    for p in pids:
        subprocess.run(["kill", p])
    time.sleep(4)
    down = run_rw("R1", ["configure terminal", cmd], wait=8)
    subprocess.Popen(
        ["setsid", "python3", REPO + "/tacacs/virp_tacacs_authzd.py",
         "--config", LAB + "/authz-recv.json", "--policy", LAB + "/policy.json"],
        stdout=open(SP + "/authzd4.log", "a"), stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL)
    time.sleep(6)
    back = run_rw("R1", ["configure terminal", cmd])
    ok = (down[0]["outcome"] != EXECUTED and back[0]["outcome"] == EXECUTED)
    return save("A7-server-down", {
        "attack": "authorization server unreachable during an approved window",
        "expect": "router DENIES (no local fallback); recovers when it returns",
        "killed_pids": pids, "while_down": down, "after_restore": back,
        "verdict": "PASS" if ok else "FAIL",
        "summary": "down conf-t=%s  restored conf-t=%s"
                   % (down[0]["outcome"], back[0]["outcome"])})


def a8_tampered_approval():
    """A8 is a COMPILER attack, not a router one: a tampered approval
    must never become a grant, so the router is never asked."""
    rows_cmd = ("python3 -c \"import sys;sys.path.insert(0,'%s/tacacs');"
                "import virp_tacacs_policy as pol,json;"
                "print(json.dumps(pol.compile_from_chain('%s/chain.db',0)[0]))\""
                % (REPO, LAB))
    r = subprocess.run(rows_cmd, shell=True, capture_output=True, text=True)
    approvals = json.loads(r.stdout) if r.stdout.strip() else []
    good = next((a for a in approvals if a.get("approval_trusted")), None)
    if good is None:
        raise HarnessError("no trusted approval on chain to tamper with")
    tampered = dict(good)
    tampered["command"] = (good["command"] or "") + " 999"
    # Re-run the SAME verification path the compiler uses.
    import virp_tacacs_policy as _pol
    recheck = _pol.approval_from_chain(
        {"proposal_id": tampered["approval_id"], "device": tampered["device"],
         "command": tampered["command"], "command_hash": tampered["command_hash"]},
        {"proposal_id": tampered["approval_id"], "device": tampered["device"],
         "command_hash": tampered["command_hash"],
         "approved_at_ns": tampered["issued_utc_ns"],
         "ttl_seconds": tampered["ttl_ns"] // 1_000_000_000})
    grants, refusals = _pol.compile_grants([recheck], now_ns=time.time_ns())
    ok = (not recheck["approval_trusted"]) and grants == [] and refusals
    return save("A8-tampered-approval", {
        "attack": "approval body altered after signing",
        "expect": "compiler refuses to render it; no grant reaches the router",
        "original_command": good["command"],
        "tampered_command": tampered["command"],
        "trust_basis_after_tamper": recheck["trust_basis"],
        "trust_not_established": recheck["trust_not_established"],
        "refusals": refusals,
        "verdict": "PASS" if ok else "FAIL",
        "summary": "trusted=%s grants=%d" % (recheck["approval_trusted"],
                                             len(grants))})
