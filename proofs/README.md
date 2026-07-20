# VIRP formal verification artifacts

## Contents

| File | What it is |
|---|---|
| `virp_obs_v2.pv` | ProVerif model of v2 observation signing/verification (`virp_sign_observation_v2` / `virp_verify_observation_v2` in `src/virp_crypto.c`) |
| `virp_obs_v2.out` | Checked-in ProVerif 2.05 output for the model — reproduce with `make proofs` |

## Verified properties (ProVerif 2.05, Dolev-Yao attacker)

1. **Master O-Key secrecy** — `not attacker(mk)` is true.
2. **Session key secrecy** — a probe encrypted under every HKDF-derived
   session key stays secret even though the attacker chooses the client
   nonce and sees all handshake values.
3. **Injective agreement** —
   `inj-event(accepted(sid, dev, cmdhash, seq, payload)) ==>
   inj-event(signed(sid, dev, cmdhash, seq, payload))`:
   every accepted observation corresponds to exactly one distinct signing
   by the O-Node with the same session, device, command hash, sequence
   and payload. This covers forgery, cross-session replay, and
   device/command substitution.

## Stated limits — read before citing

- The injective-agreement result holds **modulo a restriction** that
  encodes the replay high-water store (`virp_seqstore_accept`): each
  (session, seq) is accepted at most once. ProVerif's Horn-clause
  abstraction cannot represent that mutable state directly. The
  restriction is exactly the store's contract, and the store's behavior
  is demonstrated by negative tests
  (`tests/test_obs_v2.c`: replay, non-monotonic, cross-restart cases).
- **Freshness is not modeled** — symbolic models have no clock. The
  300 s staleness window is enforced in `virp_verify_observation_v2`
  and demonstrated by `test_stale_observation_rejected` with an
  injected verifier clock.
- The model covers the **v2 observation path only**. v1 messages
  (master-key signed, no session/device/command binding, no replay
  protection at verify time) are NOT covered by these proofs.
- There is **no Tamarin model** in this repository. Any claim of
  Tamarin verification is unsubstantiated and has been removed from the
  docs; draft-howard-virp-05 §16.1 still carries the old claim and
  needs the same correction in its next revision.

## Reproducing

ProVerif is not packaged in Ubuntu 22.04 (jammy). Build from source:

```sh
apt-get install -y ocaml-nox ocaml-findlib
curl -LO https://bblanche.gitlabpages.inria.fr/proverif/proverif2.05.tar.gz
tar xzf proverif2.05.tar.gz && cd proverif2.05 && ./build
# GUI (lablgtk2) failure is fine — the CLI binary is what we need
cp proverif /usr/local/bin/
```

Then from the repo root:

```sh
make proofs
```

which runs `proverif proofs/virp_obs_v2.pv` and fails if any query
stops proving.
