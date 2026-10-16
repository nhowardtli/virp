# Bounded Kestrel witness publisher

`publisher.py --config /etc/virp-kestrel/publisher.json [--dry-run]`

This is a separate oneshot, never part of an execute transaction. The root-owned
configuration names exact sessions in submission order; there is no all-sessions
mode. Disabled configuration makes no database or network calls. Missing sessions,
unsigned heads and wrong node keys fail before any submission. A read transaction
captures all selected heads consistently. Newer heads can be submitted on the next
explicit run; old immutable head files and receipts remain.

The publisher verifies native detached head signatures using the public sidecar.
The existing witness client reads the daemon-owned raw64 signing key on the node;
no private key is copied to the cage or transported to the witness. Submission goes
to a loopback SSH forward only. The remote authorized key must allow only forwarding
to 127.0.0.1:8081 and refuse shell/PTY/agent forwarding. Pin the remote host key.

Every accepted receipt must bind the exact session-derived chain ID, sequence,
head hash and submitter key ID, and pass the existing client's public-only signature
and inclusion checks. A successful submit process without a verified receipt is a
failure. Invalid receipts are preserved before retry. The witness deduplicates an
identical submission, so repairing a truncated receipt does not grow the tree.

Configuration exact fields:

```json
{
  "format": "virp-kestrel-publisher/1",
  "enabled": false,
  "sessions": [],
  "chain_db": "/var/lib/virp-kestrel/chain.db",
  "chain_public_key": "/etc/virp-kestrel/chain-sign.pub",
  "chain_signing_key": "/etc/virp-kestrel/chain-sign.key",
  "heads": "/var/lib/virp-kestrel/witness/heads",
  "client": "/usr/local/lib/virp-kestrel-v3/witness-client",
  "witness_url": "http://127.0.0.1:18791",
  "witness_public_key": "/etc/virp-kestrel/witness.pub"
}
```

Keep the production publisher disabled until the designated first RW evidence
session exists. Do not substitute a legacy head or a test submission. Session
allowlisting controls which evidence is published; it grants no device authority.

Tests: `python3 -m unittest discover -s tools/witness -p 'test_*.py' -v`.
The phase-three audit additionally records a real local witness/client roundtrip,
second-run deduplication, and corrupted-receipt repair with the tree staying at1.
No Rust source, compiler version or chain format change is needed.
