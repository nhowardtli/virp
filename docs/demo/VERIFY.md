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

## Remaining Phase B acceptance

Nate must provision the separate witness demo submitter/producer registration,
heads path and public witness key. STOP before witness configuration.
Witness-backed delivery and independent Claude verification of this B4 commit
remain open. Claude independently verified B1/B2 at C9b6595a / Rustdee60a3;
CLAUDE-VERIFY-B-9b6595a.md in the audit directory records that separate run.
