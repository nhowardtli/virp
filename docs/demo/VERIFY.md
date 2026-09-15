# Verify your demo receipts

## Download and verify

In the console, choose **Download your receipts** for a proposal from a fresh
SSH login. The tar contains one signed visitor shell session, its artifact
bodies, and a report in **docket-report/0.11** format.

This is **UN-WITNESSED**: no witness countersign, witness public key, or delivery
proof is carried. Nothing in this path contacts or configures a witness.

Obtain the demo chain public key independently of the download. Nate's VM219
demo key is the following 64-character hex value. Save it as demo-chain.hex:

```text
caa74561a6fdf29f8570ac5ec3eb2e478fa3a045d070d4173a3619cdfe031393
```

Extract the downloaded tar in an empty directory, then run exactly:

```sh
virp-verify --pin demo-chain.hex ./bundle
virp-verify --json --pin demo-chain.hex ./bundle > checked-report.json
```

The standalone verifier can be built from the Rust workspace:

```sh
cargo build --locked --release -p virp-verify
```

Use target/release/virp-verify in place of virp-verify if it is not on PATH.
The verifier needs no VM credentials, SSH access, private key or network access.

The demonstrated native headline was:

```text
CRYPTOGRAPHICALLY-VERIFIED — native witness delivery missing (0/6 verified; metadata missing)
```

The entry count depends on your session. Keep the entire headline and witness
findings when sharing results. CRYPTOGRAPHICALLY-VERIFIED means the supported
chain properties and Ed25519 signatures matched the independently supplied key.
SIGNER TRUST PINNED means that the matching key came from your --pin file.
These do not prove device truth, witness delivery, completeness outside the
exported session, or an independent witness timestamp.

The bundled keys.json alone is not an independent trust anchor. The bundled
docket-report.json is a derived report, not itself a signed artifact; rerun the
verifier yourself. Its file-coverage section distinguishes authenticated
artifact bytes from unsigned manifests, envelopes and supporting metadata.

## What the bundle covers

Only the named visitor shell chain: login, request/reply correlation records,
and chain-view records. Reply records commit the received observation digest;
they are not a copy of all raw device output. The daemon's separate proposal,
approval and outcome chains are not included. The console's separate
operational receipt remains available, but is not a cryptographic docket.

Sessions begun before demo chain signing was enabled cannot meet this signed
download contract. Start a fresh SSH login and file a new proposal. Old history
is preserved as originally recorded, never retroactively signed or relabelled.

## One-byte tamper check

Preserve the original. Make a separate copy and change one byte of a covered
artifact:

```sh
cp -a bundle bundle-tampered
python3 - <<'PY'
from pathlib import Path
p = next(p for p in sorted(Path('bundle-tampered/artifacts').iterdir())
         if p.is_file() and p.stat().st_size)
data = bytearray(p.read_bytes())
data[0] ^= 1
p.write_bytes(data)
print('Changed one byte in', p)
PY
virp-verify --pin demo-chain.hex ./bundle-tampered
```

The expected verdict is FAILED and a nonzero exit status. Editing only unsigned
README/report metadata is a different test; the verifier identifies those files
as uncovered rather than claiming they are signed.

## Witnessed first-submission proof (B3)

On 2026-09-15, the complete one-entry visitor login session
`demo-9dc771c4060d43b791d58bd8e2d43047` was exported with its real witness receipt:
leaf index0, tree size1. This session contains no device command or proposal.
The artifact is `b3/visitor-witnessed.tar` in Nate's Phase A/B audit directory.
The console download described above still exports un-witnessed sessions.

Save the independently supplied demo witness public key as `witness-demo.hex`:

```text
b7c71bde39f35896a0ebe7f5458d21da901103563e2d7adf0bfc913465f67fe2
```

With both public pin files obtained independently, verify the extracted bundle:

```sh
virp-verify --pin demo-chain.hex --witness-key witness-demo.hex --require-witness ./bundle
virp-verify --json --pin demo-chain.hex --witness-key witness-demo.hex --require-witness ./bundle > checked-report.json
```

Observed: `CRYPTOGRAPHICALLY-VERIFIED — native witness delivery verified (1/1 verified; metadata missing)`, exit0.
Artifact tamper yields FAILED/exit1. Witness-signature tamper is rejected by
`--require-witness` with exit7; the unchanged chain's integrity remains separate.

The C export retains its original signed bytes and HMAC fields. It is not the
Rust native-chain profile. `delivery.json` carries the actual submission and
receipt, including its signed tree head and inclusion proof. There is no
`native-export.json`: that filename asserts a different producer profile in the
current verifier. Scope is described separately in unsigned README/metadata.
The missing native metadata is explicit in the report and is not a crypto pass.
No signature was reconstructed or reissued to manufacture prefix coverage.

## Remaining Phase B acceptance

The demo witness is live and VM219's restricted tunnel and submission timer are
enabled. Claude independently verified un-witnessed B4 (CLAUDE-VERIFY-B4-89cceb9.md).
The B3 checks above were builder-run; independent Claude reproduction remains open.
Capturing every historical signed prefix of longer sessions and adding that
coverage to the console download remain open. Current-head receipts alone do
not establish complete delivery for a multi-entry session.
