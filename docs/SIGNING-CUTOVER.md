# Runbook — turning on detached chain signing (D-1, `-S`)

**Status of the rule this runbook implements: NOT RULED.** The Sep 1
Docket run graded 18 organic sessions on 313 FAILED because `-S` was
enabled on a database that already had open per-device sessions: every
session that straddled the cutover carries an unsigned `seq 0` under a
signed head, which is the `stripped signature in a signed session` hard
FAIL. Three candidate rules were put to Nate (V39 item 2, options A / B /
C). None was ticked before this was written, so this runbook documents
**option A — signing is enabled only on an empty database** — as the
provisional procedure, and the daemon has **no** code change enforcing it.
Until a rule is ruled and implemented, nothing but this procedure prevents
a repeat.

**Nothing in this runbook has been executed.** It was written on the
laptop against the source tree; no host was contacted, no database was
opened, no unit was edited, and `-S` was not added anywhere.

---

## 0. What is and is not being changed

- `-S <path>` gives the daemon a **dedicated Ed25519 chain-signing secret**.
  It is already a different key from `K_chain` (`-C`): `K_chain` is the
  32-byte symmetric key that HMACs every entry and head; the `-S` key is an
  Ed25519 secret whose only job is the detached signature. The reviewer's
  "use a dedicated key" point is therefore **already satisfied** — say so,
  and do not introduce a third key to satisfy it again.
- Signing is **pure addition**. The canonical bytes, `chain_entry_hash`,
  `chain_hmac`, `head_canonical` and the genesis rule are byte-identical
  with and without it; the signature lands in four columns no pre-D-1
  reader touches (`SECURITY.md`, "Detached Ed25519 Chain Signing").
- Everything written **before** the cutover is covered by the D-0 seal
  (`tools/seal/`, `seal-2026-08.json` + `.minisig` + `.ots`), not by `-S`.
  The cutover does not retro-sign anything and must not be described as if
  it did.

## 1. Why a straddled session fails

A chain session is signed or unsigned as a whole. The verifier grades a
session by its head: in a session whose head carries a signature, an entry
with an empty `chain_sig` is a **stripped signature — hard FAIL**
(`tests/test_chain_signing.c: test_stripped_signature_rejected`), and an
entry whose `chain_sig_key_id` differs from the head's is likewise a hard
FAIL (`test_keyid_mismatch_within_session_rejected`). An entirely unsigned
(pre-D-1) session read with a public key is **not** a failure — it is
counted as `entries_unsigned` and reported.

The daemon's per-device chain sessions (`gate-enforce:<device>`,
`approval:<device>`, `camera:<id>:<date>`) are long-lived: they are keyed by
device, not by process lifetime, so they survive restarts and simply
continue at the next sequence number. Enabling `-S` on a live database
therefore appends signed entries into sessions whose earlier entries are
unsigned, and rewrites each session head as signed. That is precisely the
18-session verdict.

**So: the safe cutover is never "add `-S` to the unit and restart".**

The shape is reproduced, from an empty database, by
`tests/test_signing_activation.c` (`make test-signing-activation`) — two
unsigned appends, then activation, then two signed appends. The verifier's
verdict on the result is, verbatim:

    first_broken=0
    Missing Ed25519 signature at sequence 0 in a signed session
    (stripped signature)

That is the 313 verdict, eighteen times over.

## 2. Procedure (option A — fresh database)

Everything below runs **as the daemon user, on the O-Node host**. There is
no `sqlite3` CLI on 313; use the Python standard library, which has the
online-backup API built in.

### 2.1 Pre-flight

    systemctl status virp-onode        # note the unit name on this host
    # confirm the current -c / -C / -S arguments, verbatim:
    systemctl cat virp-onode | grep -n ExecStart

Record the current chain path (`-c`) and key path (`-C`). If `-S` is
already present, STOP: this host has already cut over, and this runbook is
not for it.

### 2.2 Snapshot the live database, online, as the daemon user

`sqlite3.Connection.backup()` takes a consistent snapshot of a database
that is being written to. Do **not** `cp` a live WAL-mode database.

    python3 - <<'PY'
    import sqlite3, time
    SRC = "/var/lib/virp/chain.db"
    DST = "/var/lib/virp/chain.sealed-%s.db" % time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    src = sqlite3.connect("file:%s?mode=ro" % SRC, uri=True)
    dst = sqlite3.connect(DST)
    with dst:
        src.backup(dst)
    dst.close(); src.close()
    print(DST)
    PY

Then hash it and record the digest somewhere outside the host:

    sha256sum /var/lib/virp/chain.sealed-*.db

### 2.3 Seal the snapshot

Follow the D-0 ceremony in `tools/seal/README.md`: as the K_chain holder,
verify every entry hash, link, genesis value and HMAC over the snapshot,
then sign the full session-head set with the seal key (which never touches
the O-Node) and anchor the result. The existing seal
(`tools/seal/seal-2026-08.json`) is the worked example of the output shape.
Verify the previous seal still checks out before adding to it:

    minisign -V -p tools/seal/virp-seal-2026.pub -m tools/seal/seal-2026-08.json

The snapshot plus its seal is what preserves the pre-cutover history. The
old database file itself is then evidence, not a live chain.

### 2.4 Move the old database aside — do not delete it

    systemctl stop virp-onode
    mv /var/lib/virp/chain.db      /var/lib/virp/chain.pre-cutover.db
    mv /var/lib/virp/chain.db-wal  /var/lib/virp/chain.pre-cutover.db-wal  2>/dev/null || true
    mv /var/lib/virp/chain.db-shm  /var/lib/virp/chain.pre-cutover.db-shm  2>/dev/null || true

Nothing recreates `chain.db`; the daemon will create a fresh one on start.

### 2.5 Mint the signing key (if it does not exist)

    virp-tool keygen chainsign /etc/virp/chain-sign
    # secret: /etc/virp/chain-sign.sk   public: /etc/virp/chain-sign.pub
    chmod 600 /etc/virp/chain-sign.sk
    chown <daemon-user> /etc/virp/chain-sign.sk

Distribute **only** the `.pub` to verifiers. Record its `key_id`: every
session created from here on will carry it, and a later restart with a
*different* secret is the failure mode section 4 covers.

### 2.6 Start with `-S`, on the fresh database

Add `-S /etc/virp/chain-sign.sk` to `ExecStart` alongside the existing
`-c` and `-C`, then:

    systemctl daemon-reload
    systemctl start virp-onode
    journalctl -u virp-onode -n 40 --no-pager

Expect `[Chain] Initialized:` for the new path and no `chain signing … could
not be enabled` line. `-S` without `-c`/`-C` is a FATAL refusal, as is an
unloadable key; both name themselves.

### 2.7 Verify the first entries

Drive one GREEN read at a device, then verify its session with the **public
key only** — the point of D-1 is that a verifier without `K_chain` can do
this:

    virp chain-verify --db /var/lib/virp/chain.db \
                      --session gate-enforce:<device> \
                      --pubkey /etc/virp/chain-sign.pub

Expected verdict: `VALID`, every entry signed, `entries_unsigned=0`,
`OPEN_EXECUTIONS=0` once the read completes, and one signing `key_id`
across entries and head.

### 2.8 Verify through the Docket bundle path

Export the new session and run it through Docket exactly as the Sep 1 run
did, so the cutover is graded by the same tool that found the problem:

    # export the fresh session(s) with the chain-signing public key pinned
    <export the bundle for the new chain.db, --keys /etc/virp/chain-sign.pub>
    docket verify <bundle-dir> --pin <key_id>

**Expected first verdict: PASS / CRYPTOGRAPHICALLY-VERIFIED**, with zero
FAILED sessions. The 18 straddled sessions in the *old* database stay
FAILED under every option — A, B or C — and that is correct: they record a
real inconsistency, and rewriting them would be worse than reporting them.
Verify the sealed snapshot as a separate bundle and expect the pre-D-1
verdict for an unsigned chain (verified under `K_chain`, `entries_unsigned`
equal to the entry count) — not a failure.

## 3. Rollback

Remove `-S` from `ExecStart`, `daemon-reload`, restart. The daemon reverts
to unsigned appends. The sessions created while `-S` was on keep their
signatures, and appending unsigned entries into them creates exactly the
straddle this runbook exists to avoid — so a rollback must also move the
signed database aside and start a third, fresh one, or accept FAILED
verdicts on every session that spans the rollback. **Rollback is not free.
That asymmetry is the strongest argument for cutting over onto a fresh
database in the first place.**

## 4. The failure modes this procedure does not yet prevent

Recorded here because the daemon does not enforce them today (option C —
no code change):

- **`-S` on a nonempty database.** Nothing refuses it.
  `virp_chain_enable_signing()` loads the key, `ALTER TABLE`s the four
  signature columns onto the live database, and returns `VIRP_OK`. Note
  that this means the database is **mutated** by the attempt: the columns
  are added even though no rule was violated in the caller's view. Under
  option A the refusal must come *before* those ALTERs for the database to
  be byte-identical after a refused start.
- **Restart with a different signing key.** Nothing refuses it either. The
  daemon signs new entries with the new `key_id` and the verifier reports
  `Signature key_id mismatch at sequence N` — after the fact, at read time,
  on somebody else's screen.

Both are pinned as PENDING (known-failing by design) in
`tests/test_signing_activation.c`, each naming its acceptance criterion. They
are counted in their own bucket, never as passes, and the suite refuses to
print a clean line while they exist. When a rule is ruled and implemented,
remove each marker **in the same commit that makes it pass** — a pending
marker that silently becomes correct is how stale markers accumulate. The
suite treats an unexpected PASS as a hard failure for exactly that reason.

## 5. Hard rules for whoever runs this

- Never add `-S` to an installed unit as a first step. The database work
  comes first.
- Never point `-S` at a key the O-Node host is not the sole holder of.
- Never delete the pre-cutover database. It is the evidence the seal
  attests.
- One `key_id` per database, for the life of that database.
