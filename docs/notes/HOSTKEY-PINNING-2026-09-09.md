# Follow-up: host-key pinning must cover the algorithm libssh2 negotiates

**Filed 2026-09-09. Not fixed tonight — documentation of a diagnosis.**
**Do not merge `fix/fortigate-hostkey-rsa-pref` (ffaa452) as-is: its stated
root cause is wrong. See "What was wrong in the workaround" below.**

## Symptom

After the FortiGate 200G (10.0.10.1) was added to virp-lab's template, every
watchdog attempt failed at host-key verification:

    [virp-fg] handshake OK, verifying host key
    [SSH-HK] Unknown host key for 10.0.10.1:22 — not in /var/lib/virp/.virp/known_hosts

…while `known_hosts` held **two** pinned lines for 10.0.10.1 (`ssh-rsa`,
`ssh-ed25519`), unhashed, `virp:virp 0600`, present before the daemon
started, whose fingerprints matched the live device exactly. The cat3850
(10.0.10.2) verified from the same file in the same daemon.

## Root cause

**The daemon negotiated an ECDSA host key, and no ECDSA key was pinned.**

A handshake-only libssh2 probe against 10.0.10.1 (no auth) showed:

    libssh2 negotiated HOSTKEY method = ecdsa-sha2-nistp256
    libssh2_session_hostkey type     = 3 (ECDSA_256)
    SHA256 = 3953df92… (= OVPfkiFx46WeyXUgXzWupvweTW6Vl0bICR/AH5JOblU, the FGT's ECDSA key)

libssh2 1.11's default `LIBSSH2_METHOD_HOSTKEY` preference lands on ECDSA
when the server offers it. FortiOS 7.6 advertises
`ecdsa-sha2-nistp521,-384,-256, rsa-sha2-256, rsa-sha2-512, ssh-ed25519`.
So the verifier — correctly — mapped the negotiated key to
`LIBSSH2_KNOWNHOST_KEY_ECDSA_256` and looked for an ECDSA pin. There was
none. NOTFOUND was the right answer.

The pin was incomplete because it was produced with
`ssh-keyscan -t rsa,ed25519`. The ECDSA key was never fetched.

## Why the diagnosis went wrong twice

1. `ssh -vv` from virp-lab reported `kex: host key algorithm: ssh-ed25519`.
   That is **OpenSSH's client preference**, not libssh2's. It was read as
   "the daemon negotiates ed25519." It does not.
2. From that false premise, the failure was attributed to libssh2's ed25519
   known-host lookup. An offline harness disproved it:
   `libssh2_knownhost_readfile` tags an `ssh-ed25519` line as
   `LIBSSH2_KNOWNHOST_KEY_ED25519` (bits=7) and
   `libssh2_knownhost_checkp` with the ED25519 mask returns **MATCH**.

The lesson: **measure what libssh2 negotiates; never infer it from OpenSSH.**

## Verified NOT broken (the question this follow-up was asked to answer)

- `src/virp_ssh_hostkey.c` obtains the negotiated type from
  `libssh2_session_hostkey(session, &key_len, &key_type)` (line 78) and maps
  `LIBSSH2_HOSTKEY_TYPE_ED25519` → `LIBSSH2_KNOWNHOST_KEY_ED25519` (line
  131). It handles RSA, DSS, ECDSA 256/384/521 and ED25519.
- libssh2 1.11.0 (both nodes) reads and matches ed25519 pins correctly.
- **An ed25519-only device (modern Linux with RSA host keys disabled) will
  verify fine**, provided its ed25519 key is pinned.

## Resolution applied

The ECDSA key was pinned (`ssh-keyscan -t ecdsa 10.0.10.1`), 00:50:44 UTC.
The verifier re-reads `known_hosts` on every connect, so no restart was
needed. Next attempt: `[SSH-HK] Host key verified: 10.0.10.1:22`.

Host-key verification is solved. The 200G still does not connect: the very
next step, `libssh2_userauth_password()`, fails with `rc=-18 Authentication
failed (username/password)` on every attempt, while the rendered credential
(`virp-gate`, 15 chars, substituted) is intact. That is a FortiGate-side
account / password / `trusthost` question and is **separate from pinning**.

## What was wrong in the workaround

`fix/fortigate-hostkey-rsa-pref` (ffaa452) adds an RSA-first
`LIBSSH2_METHOD_HOSTKEY` preference to the FortiGate driver. It would have
"worked" — by steering negotiation onto the one algorithm that happened to
be pinned — but its commit message asserts a libssh2 ed25519 bug that does
not exist. Merging it would encode a false explanation into the tree and
mask the real rule (pin every algorithm). Leave it unmerged; delete or
rewrite it.

## Follow-ups (not tonight)

1. **Make the NOTFOUND log self-diagnosing.** `[SSH-HK] Unknown host key
   for %s:%u` should also print the negotiated algorithm and which key
   types ARE pinned for that host. With that line this would have been a
   ten-second read instead of an hour of inference.
2. **Pinning procedure.** Wherever the runbook says to pin a host key, it
   must say `ssh-keyscan -t rsa,ecdsa,ed25519` — all of them. The ASA-Lab
   pin (rsa only, in its `_comment`) works only because that ASA offers
   nothing but rsa. Any device that adds an ECDSA or ed25519 key later
   fails in exactly this way.
3. **Policy question, not a bug:** should drivers set an explicit
   `LIBSSH2_METHOD_HOSTKEY` preference so negotiation is deterministic
   across libssh2 upgrades? panos and juniper already do. Deterministic
   negotiation is a legitimate goal; it is not a substitute for pinning
   every offered key.
