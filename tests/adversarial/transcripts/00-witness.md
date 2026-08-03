# Build #0 — Target-side witness

**Date:** 2026-08-03 · **Host:** virp-lab · **Branch:** `test/adversarial-2026-08-03`
**Purpose:** establish an independent record of what the *target* actually did, so
that every later transcript can fill column 1 of the results table without asking
VIRP. Nothing in builds #1–#6 is trustworthy until this exists and is proven.

---

## 1. Mechanism

The VIRP linux driver opens **one SSH exec channel per command** over a persistent
SSH session (`src/drivers/driver_linux.c`: *"Uses exec channels, not interactive
shell… Each execute() opens a new channel"*). That makes sshd's `ForceCommand` the
true chokepoint: nothing reaches the device without passing through it first.

Installed on the four sacrificial containers `clab-frr-ospf-frr1..frr4`:

| Path (inside container) | What |
|---|---|
| `/usr/local/bin/virp-witness` | the witness script |
| `/etc/ssh/sshd_config.d/99-virp-witness.conf` | `ForceCommand /usr/local/bin/virp-witness` |
| `/var/log/virp-witness/{witness.log,counter,lock}` | append-only log, atomic counter, flock |

Repo artifacts (this branch): `tests/adversarial/witness/{virp-witness,install-witness.sh,witness-count.sh}`
and `tests/adversarial/virp-evidence-header.sh`.

Log format — one line per event, tab-separated, fixed `VIRPWITNESS` marker:

```
VIRPWITNESS v1 RECV seq= nonce= host= epoch= mono= utc= pid= client= user= cmdsha= cmd=
VIRPWITNESS v1 DONE seq= nonce= epoch= mono= rc=
```

`nonce` joins the RECV/DONE pair. `seq` is a per-container flock-serialised counter
and is the authoritative ordering under concurrency. `mono` is `/proc/uptime`
(10 ms) — busybox `date` has no `%N`, so wall clock is second-resolution only and
must not be used to order concurrent events.

### Three deliberate fidelity properties

1. **Fail-open.** Every logging step is guarded. If the witness cannot write, the
   operation still runs. A witness that could block operations would be measuring
   itself rather than the system under test.
2. **No pipes around the command.** The command runs via `eval` in the witness's own
   process, so its stdout/stderr are the raw SSH channel descriptors and its bytes
   reach VIRP unaltered; exit status passes through. **Consequence, stated plainly:
   this witness does not independently hash the response body.** Byte-level response
   attestation requires capture mode, which inserts a `tee` and therefore perturbs
   the system; it is **off by default** and will be enabled only for the
   oversized-response transcript, where that is the whole point.
3. **RECV is written before the command runs.** So a crash or kill mid-operation
   still leaves proof the operation was *delivered*. **RECV = delivered and entered.
   DONE = ran to completion with this rc.** The gap between them is precisely the
   ambiguity window test #2 hunts for.

**Counting rule for all later transcripts:** executions at the target = **RECV**
lines matching the command digest. Never count DONE for this — an operation that
took effect and then died writes RECV and no DONE.

---

## 2. Two things found while building it — both matter for later tests

### 2.1 The witness has a coverage boundary, and it bit immediately

`ForceCommand` is applied from the config the sshd **listener** held when the
connection was accepted. The VIRP daemon keeps a **persistent** SSH session and only
opens new *channels* per command. So a session established *before* the install keeps
running without the witness, and reloading sshd does not fix it.

Observed directly. With `ForceCommand` installed and sshd HUP'd, a GREEN read through
VIRP returned:

```
device=clab-frr-ospf-frr1 command="vtysh -c "show ip ospf neighbor""
trust_tier=GREEN (0x01)  seq=15568  obs_type=0x07 (signed observation)
signature=VALID
gate_decision=allowed
payload:
  Neighbor ID  Pri State   Up Time   Dead Time  Address      Interface
  2.2.2.2        1 Full/-  4d06h19m    39.191s  10.10.12.2   eth1:10.10.12.1
  4.4.4.4        1 Full/-  4d07h20m    39.192s  10.10.41.1   eth2:10.10.41.2
```

…while the witness log was **empty** and the counter read **0**.

A real operation, really executed, really signed — and completely invisible to the
witness. Fixed by restarting the daemon (PID 556324 → 778602) to force reconnection.
**Operational rule for every subsequent test: any daemon restart or SSH reconnect
re-opens this hole. Re-prove capture after each one.** `install-witness.sh` does not
do this for you and says so in its usage text.

### 2.2 The containers carry constant background traffic that is not the test

The witness immediately exposed traffic no VIRP-side view shows:

```
2026-08-03T01:43:54Z  cmdsha=dd291cd6294bafef  uptime
2026-08-03T01:43:55Z  cmdsha=a3fb7dd1b851dac1  vtysh -c "show ip ospf database"   <- the test
2026-08-03T01:44:00Z  cmdsha=dd291cd6294bafef  uptime
2026-08-03T01:44:05Z  cmdsha=dd291cd6294bafef  uptime
                       ... every ~5s, indefinitely ...
```

A **daemon watchdog probe (`uptime`) every ~5 seconds per container**, plus autopilot
reads every minute. The watchdog probe is a real command executed on a real device and
it is **not** signed, chained, or otherwise represented in VIRP's evidence. It is
benign, but it is a standing reminder that *VIRP's artifacts are not a complete record
of what VIRP did to a device.* All counting is therefore scoped to an exact command
digest, never to raw line counts.

---

## 3. Proof the counting is sound under concurrency

Test #1 fires ~50 concurrent contenders, so the counter had to be proven at that level
*before* being relied on. 50 concurrent witness invocations on frr1:

```
=== RECV lines: 50 ===
=== DONE lines: 50 ===
=== counter: 50 ===
=== distinct seq values: 50 ===
=== duplicate seq values (should be empty) ===
=== distinct nonces: 50 ===
```

No duplicate or lost sequence numbers. The flock-serialised counter is safe at the
concurrency test #1 needs.

---

## 4. Sanity transcript — one GREEN read appears exactly once

### Header

```
utc                : 2026-08-03T01:43:50Z
hostname           : virp-lab
daemon pid         : 778602
daemon binary      : /usr/local/lib/virp/virp-onode-prod
daemon sha256      : db8f3fabbfc6cc8ee838a5f38ed972f710ed8e098b7c0f91f463379d889d5154
client binary      : /opt/virp/build/virp
client sha256      : 56d215702cfe2a558d8f5d1bd642c0488a8e0df9a1e7e149d3deb9ce15c57e50
client version     : virp-tool b6e9602c
git commit         : feeb1d04   branch: test/adversarial-2026-08-03
gate (from daemon) : default=ENFORCE max_tier=YELLOW overrides=0
devices.json sha256: af448c352e0077e6fe28cdfe9ef9e39fc0752ee2329c265788842493c9fd146c
devices loaded     : Loaded 7/7 devices from /run/virp/devices.json
chain db           : /var/lib/virp/chain.db (45051904 bytes)
chain head         : autopilot-comparator:2026-08-03 seq=43 comparator:1785721332861280124
                     entry=fa11267e0dd5f90e prev=0c82be59eae76f76
spool proposals    : 202
spool approvals    : 2
spool challenges   : 3
witness             frr1 counter=1 fc=on   frr2 counter=33 fc=on
                    frr3 counter=33 fc=on  frr4 counter=33 fc=on
```

Operation: `vtysh -c "show ip ospf database"` · cmdsha `a3fb7dd1b851dac1`
(chosen because neither the watchdog nor autopilot ever issues it, so attribution is
unambiguous). Target: `clab-frr-ospf-frr1`. Invoked **once**, at 01:43:55.883Z.

### Client-visible result

```
trust_tier=GREEN (0x01)  seq=50  obs_type=0x07 (signed observation)
signature=VALID
gate_decision=allowed
chain_registered=yes
artifact_hash=32b22de1a56150a89e3a74a4bdd9786e60877cf2c061accf543e312f4cbd1dbe
payload: OSPF Router with ID (1.1.1.1) / Router Link States (Area 0.0.0.0)
         1.1.1.1  2.2.2.2  3.3.3.3  4.4.4.4  (5 links each)
```

### Target-side independent result (witness only, VIRP not consulted)

```
cmdsha         : a3fb7dd1b851dac1
delivered(RECV): 1
completed(DONE): 1
exit codes     : rc=0 x1
witness seqs   : 2
```

Raw line:

```
VIRPWITNESS v1 RECV seq=2 nonce=748f8c00-80b9-4ee6-8146-df38e3fe5b0f host=frr1
  epoch=1785721435 mono=373094.51 utc=2026-08-03T01:43:55Z pid=74974
  client=172.20.20.1,42212,22 user=root cmdsha=a3fb7dd1b851dac1
  cmd=vtysh -c "show ip ospf database"
```

### Durable evidence + journal

```
SESSION                      SEQ  TYPE         ARTIFACT_ID                                ENTRY_HASH        PREV_HASH
virp-cli:clab-frr-ospf-frr1  0    observation  obs:clab-frr-ospf-frr1:1785721435953084742 15e1fbb0f4092a82  80200bcd744fb428

Aug 03 01:43:55 virp-onode-prod[778602]: [GATE] mode=ENFORCE device=clab-frr-ospf-frr1
  driver=linux tier=GREEN threshold=YELLOW decision=allow command="vtysh -c "show ip ospf database""
```

Chain entry re-read **after a full daemon restart** — still present, same entry hash
`15e1fbb0f4092a82`. Durable.

### Results table

| Actual target event | VIRP response | Durable evidence | Auditor conclusion |
|---|---|---|---|
| `show ip ospf database` delivered **once** to frr1 at 01:43:55Z (witness seq=2, nonce 748f8c00…), completed rc=0 | GREEN, `signature=VALID`, `gate_decision=allowed`, chain_registered | chain entry `15e1fbb0f4092a82`, artifact `32b22de1…`, survives daemon restart | one authorized read executed once on frr1 and was recorded |

Column 1 and column 4 **agree**. The witness is trustworthy for execution counting.

---

## 5. Mistakes preserved

Left in deliberately, per the evidence contract.

- **`install-witness.sh reset` before `install`** — three "can't create
  `/var/log/virp-witness/witness.log`: nonexistent directory" errors on frr2–frr4.
  Harmless ordering error on my part; the directory is created by `install`.
- **First evidence header reported `spool proposals/approvals/challenges = 0/0/0`.**
  Wrong. `/var/lib/virp/approvals` is mode `700 virp:virp`, so an unprivileged
  `ls | wc -l` got *Permission denied* on stderr and counted **0** on stdout. True
  counts were 202/2/3. This is the nastiest kind of evidence bug — **a silent zero
  that looks like a clean baseline** — and it would have made any spool-delta claim in
  test #1 meaningless. `virp-evidence-header.sh` now reads the spool via `sudo`.
- **First witness recount reported `DONE count: 1` from a wrong grep.** DONE lines
  carry only `seq=` and `nonce=`, never `cmdsha=`, so grepping the command digest
  matches RECV lines only and reports the RECV count twice — which looks exactly like
  RECV/DONE agreement. `witness-count.sh` now joins RECV→DONE on the nonce.
- **`exit codes : 1 1 0`** — a leading space produced a phantom empty entry in the
  `uniq -c` output. Cosmetic, but `rc` becomes load-bearing in test #2, so it was
  fixed to `rc=0 x1`.

## 6. Incidental observations (not findings, but noted for later builds)

- `vtysh -c "show ip ospf interface brief"` returned the body text
  `No such interface name` **with rc=0**, and VIRP signed it as GREEN /
  `gate_decision=allowed`. VIRP faithfully carried the bytes — no complaint — but an
  auditor reading only the VIRP status fields (`signature=VALID`, `allowed`) without
  parsing the payload would conclude the command did what was asked. Relevant to #6's
  `signature valid ≠ executed-as-intended` distinction.
- Each `virp exec --chain-register` creates a **fresh session** `virp-cli:<device>`
  starting at **seq=0**. Session/seq semantics are directly relevant to #5 (rollback)
  and #6 (replay across sessions).

## 7. Known limits of this witness — stated so no later transcript overclaims

1. **It does not attest response bytes** in default mode (fidelity rule 2). Claims
   about what the device *returned* still rest on VIRP's artifact unless capture mode
   is explicitly enabled and declared.
2. **It only sees SSH.** It witnesses the four `linux`/FRR containers. It says nothing
   about the `wazuh`, `librenms`, or `pbs` API drivers.
3. **It can be bypassed by a pre-existing SSH session** (§2.1). Re-prove capture after
   every daemon restart.
4. **It is inside the target.** Anything with root on the container could edit the log.
   That is acceptable here — the container is sacrificial and the adversary under test
   is VIRP's accounting, not a compromised device — but it is not a tamper-proof oracle
   and must not be described as one.
