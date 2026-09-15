# Verify a demo receipt — Phase B completion pending

The current console download is an operational JSON receipt. It is **not**
the docket bundle described below and cannot earn a cryptographic verdict.

Once Nate has provisioned the isolated witness lane and the builder has
enabled signed demo chains and completed the docket export, the visitor will
download a bundle directory and obtain public keys independently of that bundle:

```sh
virp-verify --pin demo-chain.hex --witness-key demo-witness.hex ./demo-bundle
```

The demo chain public key prepared on VM219 is:

```text
caa74561a6fdf29f8570ac5ec3eb2e478fa3a045d070d4173a3619cdfe031393
```

Its private half remains only on VM219. It is not yet enabled in the daemon
or registered with a witness. No witness endpoint or key is currently configured.

CRYPTOGRAPHICALLY-VERIFIED means the supported hashes, links and signatures
the verifier examines match. Read its coverage and witness findings too;
a headline does not establish properties the report calls unknown or unsupported.
SIGNER TRUST PINNED means those signatures match the public key you supplied
out of band. It does not establish the truth of a router's output or trust in
the signer beyond your decision to trust that public key.

Required final acceptance is still open: independently download and verify on
a laptop that has never seen VM219, then copy the bundle, alter one byte in a
covered artifact, and confirm a FAILED verdict. Preserve the untouched original.
Do not claim this acceptance from manifest hash consistency alone.

The witness producer registration and any separate capture producer key are
distinct concepts. The key above is specifically the O-Node Ed25519 chain key.
Nate must confirm the demo lane registration contract before witness wiring.
