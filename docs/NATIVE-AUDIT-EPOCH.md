# Separate new signed audit sessions from legacy history

A live migration exposed a compatibility boundary with released virp-verify0.1.3:
`approval:<device>` and `gate-enforce:<device>` already contained unsigned entries.
Enabling signing appended valid signatures, but left a signed head over an unsigned
prefix. Native verification recognizes this transition; 0.1.3 instead rejects the
mixed session. Both observations are retained in the private rollout report.

Do not backfill signatures, delete history, relax the verifier, or reset a database
under the same session IDs. The opt-in production flag `-E v3-20261016` starts new
native audit sessions with a suffix, e.g. `approval:SW-3850@v3-20261016`. This is an
ordinary new session ID in the existing format, not a new signature domain or wire
format. The native node configuration record commits to the selected epoch.

The flag requires Ed25519 signing and 1–16 ASCII letters, digits or hyphens. It is
set before worker startup and cannot change within the process. Append paths for
approval, gate-enforce and node-config sessions receive the suffix; explicit cage
observation session IDs and all read/verification lookups remain unchanged. Names
that would exceed the existing session field are refused, never truncated. An
existing unsigned or differently signed destination is refused inside the append
transaction. The default without -E retains existing behavior.

Original entry bytes, signatures, heads, proposal IDs and consumed approval state
stay in the same database/store. No approval is granted by choosing an epoch.
Export the explicit new suffixed sessions and the matching cage observation
session for a new run. Keep older mixed sessions separately, with their actual
verification status. Never call the historic packet retroactively verified.

Rollout: regression suite, canary full approval/apply/replay/restore through the
shared helper, offline verifier0.1.3 with public-only pins, then paired binary/helper
pin update on .211 after snapshot. Add -E to the candidate unit only. Preserve the
old binary and unit; rollback code/config without rewinding the chain. The v3
production run must use fresh proposals and actual operator approval for applies.
