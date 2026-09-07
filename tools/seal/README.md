# Chain seal — 2026-08-23

One-time seal over the production VIRP chain: 350 sessions, 165,954
entries, snapshot taken 2026-08-23T03:44:46Z UTC. As the chain key
holder, the operator verified every entry hash, chain link, genesis
value, and HMAC (165,954/165,954 passed, zero mismatches), then signed
the full session head set with a dedicated Ed25519 key that never
touches the O-Node.

What this proves: from the seal date forward, any alteration of the
sealed history is detectable by anyone holding these files, including
alteration by the operator. What it does not prove: the absence of
alteration prior to the seal date. That residual is stated inside the
seal itself, and sessions created after detached chain signing lands
(draft-07 work) will not rely on this attestation at all.

## Verify

    minisign -V -p virp-seal-2026.pub -m seal-2026-08.json

The sha256 of seal-2026-08.json is independently anchored via
OpenTimestamps (seal-2026-08.json.ots) and this repository's commit
history. To check a chain excerpt against the seal, recompute its
session head and compare against the sessions list or the embedded
Merkle rules.
