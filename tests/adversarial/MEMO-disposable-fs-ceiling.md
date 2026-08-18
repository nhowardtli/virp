# Test #3 sizing — the disposable-filesystem ceiling (power-loss fidelity)

**Base commit:** `d17f5643` (merged main; per CONVENTIONS.md §1).
**Status:** SIZING ONLY — no destructive run performed. Held for review before
any device-mapper / loop / mount action, the same discipline the FI daemon
itself is gated by (`include/virp_fault_inject.h`).

## Why this test exists

`SECURITY.md` and `docs/VIRP-CLAIMS.md` now carry the honest caveat that the
crash coverage is **SIGKILL, not power loss**. Test #2's harness
(`fi-run.sh`) SIGKILLs the daemon with its chain at `/run/virp-fi/chain.db`.
`/run` is **tmpfs** (confirmed on virp-lab). That combination measures exactly
one thing: SQLite's crash recovery of an *uncommitted transaction whose
storage is still intact* — the process died, the RAM did not. It cannot
measure the failure mode the caveat is about: **writes the application
believed were durable that never reached the platter** (power loss, a lying
disk, `fsync` that returned before the barrier). tmpfs has no platter to lose
from and its `fsync` is a formality.

Test #3 closes that gap on a filesystem we can actually cut. This memo sizes
the ceiling — mechanism, fidelity, resources, and safety — so the reviewer
approves an envelope, not a blank cheque.

## Fidelity ladder (what each rung actually proves) + host availability

| Rung | Mechanism | Failure it models | On virp-lab? |
|---|---|---|---|
| L0 | SIGKILL, chain on **tmpfs** (today's `fi-run.sh`) | process crash, storage intact | in tree |
| L1 | SIGKILL, chain on **disk-backed loop ext4**, then `echo 3 > drop_caches` | unsynced page-cache loss, coarse | yes |
| L2 | **dm-error** flip mid-run | total device failure (every I/O errors) → fail-**closed** detection | `error v1.7.0` loaded |
| L3 | **dm-flakey `drop_writes`** then reload to a clean table | **silent write-loss** — writes ack at the syscall, never hit the image → the true power-loss case | loadable (`modprobe dm-flakey`, `.ko` present) |
| L4 | `LD_PRELOAD` making `fsync`/`fdatasync` a no-op + SIGKILL | "the disk lied about durability", no root/dm | yes |

L3 is the headline: it is the only rung that reproduces *committed-looking but
not-durable*, which is precisely what the caveat concedes is untested. L2 is
its companion — a chain writer that meets a hard I/O error must fail closed,
not ack. L0 stays as the process-crash baseline (test #2, unchanged).

## The ceiling (resource envelope requested)

The loop image MUST live on a **disk-backed** fs for `fsync` to mean anything.
`/tmp` and the session scratchpad are `/dev/sda1 ext4` — real fsync. Sizing:

| Dimension | Ceiling | Basis |
|---|---|---|
| Loop image size | **256 MB** (min 64 MB) | a test chain.db with a few thousand entries is single-digit MB; 190 GB free on `/`, 29 GB RAM — headroom is a non-constraint, so cap for tidiness, not need |
| Loop devices | **1** (`/dev/loop0` free) | one image is enough; the dm target stacks on it |
| dm devices | **1**, uniquely named (`virp-adv3-flakey-$$`) | never a generic name that could alias another mapping |
| Chain corpus | ≤ ~5,000 appends per run | enough to have a WAL + a fsync boundary to straddle; bounded runtime |
| Wall-clock | a few minutes per rung | not the 39-min live-chain suite; this is self-contained |
| Kernel side-effect | `dm-flakey` module left loaded | benign; note it in the transcript per CONVENTIONS.md |

## Safety envelope (rule 3, extended to the block layer)

The FI contract's rule 3 ("isolated socket, chain and spool; never
`/var/lib/virp`") extends downward to the device:

1. **Dedicated scratch only.** Image, mountpoint, socket, keys all under a
   run-unique dir in the session scratchpad. The production chain
   (`/var/lib/virp/chain.db`), `/run/virp`, and the production socket are
   never named.
2. **Unique device names.** `losetup --find --show` for the loop;
   `virp-adv3-flakey-$$` for the dm node. No fixed `/dev/mapper` name that
   could collide with a real mapping.
3. **Guaranteed teardown.** A single `trap` unwinds in order on ANY exit:
   `umount` → `dmsetup remove` → `losetup -d` → `rm -rf` the scratch dir.
   Re-entrant and idempotent; a half-built stack still tears down.
4. **Privilege ceiling.** `losetup`/`dmsetup`/`mount`/`modprobe` need root
   (passwordless sudo is available). Each sudo call is a single, named,
   auditable command — no `sudo bash`. The test refuses to run if the target
   image path resolves anywhere under `/var` or `/run`.
5. **One session.** Same as the audit rule — not run concurrently with the
   autopilot's 5-minute cycle touching the production chain (different fs, but
   the discipline stands).

## What test #3 measures once approved

Arm L3 (`drop_writes`) after N appends, with an explicit `fsync` boundary in
the middle:

- entries appended **before** the fsync boundary must survive the cut;
- entries appended **after** it (written, not yet synced) vanish on reload to
  a clean table — the power-loss event;
- on reopen from the underlying image, does `virp_chain_verify_session` **catch
  the lost tail** (the signed per-session head asserts a length the entries no
  longer reach → verification fails, which is the *correct* detection), or does
  it silently report VALID on the shortened chain?

The pass condition is not "no data lost" — power loss loses data. It is **"loss
is detected, never silently accepted"**: the head-record completeness check
(the same one that closed the truncated-tail gap for a keyless attacker) must
also catch an *honest* truncation from a storage cut. L2 asserts the writer
fails closed on hard error rather than acking a write it could not persist.

## Recommendation

Build test #3 at **L3 (dm-flakey drop_writes)** as the headline with **L2
(dm-error)** as the fail-closed companion, inside the envelope above, as a new
`tests/adversarial/fi-powerloss.sh` plus a transcript that pins `d17f5643` per
CONVENTIONS.md. Hold the first destructive run for review. Keep L0 as the
process-crash baseline. L4 is a no-root fallback if a future host lacks
dm-flakey — not needed here.
