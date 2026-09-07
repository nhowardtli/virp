# Verifier semantics

Two verifiers read the same chain database and must reach the same
conclusion about it:

- the C verifier, `src/virp_chain.c` (`virp_chain_verify_session`,
  `chain_verify_locked`), used by `virp-tool` and by the daemon;
- the Python standalone verifier, `report/verify.py`
  (`verify_chain_signatures`), used by `virp-report` and by the public
  `virp-verify`.

Where a rule is shared it is written down HERE, once, and both code paths
point at this file. A rule that lives only in one implementation is a
rule the two can drift apart on, which is how the migration defect below
survived.

## Is a session signed?

Optional Ed25519 chain signing (D-1) is enabled per NODE. Enabling it
adds `chain_sig` / `chain_sig_key_id` to `chain_entries` and `head_sig` /
`head_sig_key_id` to `chain_heads`, and those columns then exist for the
whole DATABASE, including for every session written before signing was
switched on.

**Signed-ness is a property of the SESSION, not of the database and not
of which keys the operator happens to hold.**

```
head_signed      = head exists and head_sig is non-empty
any_entry_signed = some entry in the session has a non-empty chain_sig

session is SIGNED    <=>  head_signed or any_entry_signed
session key_id       =    head_sig_key_id      if head_signed
                          first entry's chain_sig_key_id otherwise
```

- An UNSIGNED session is graded `unsigned`. The asymmetric tier does not
  apply to it. This is never a failure and is never a pass of a check
  that did not run: `sig_checked` is false and the entries are counted
  `entries_unsigned`.
- A SIGNED session whose key_id is not the one the verifier holds is
  `key_unavailable`: a soft, whole-session outcome. Never a failure. The
  keyless and symmetric tiers still apply.
- Inside a SIGNED session the verifier holds the key for, every entry
  must carry a signature whose key_id equals the session's, and every
  signature must verify. A missing signature there is a STRIPPED
  signature and is a FAILURE at the same severity as a bad one: the
  signature columns sit outside the canonical bytes, so the signature is
  their only integrity protection.

### The defect this rule replaces

HAM review, 2026-09-06, item 7. The C verifier computed

```c
check_sigs = verify_sig_enabled && entry_sig_cols && !sig_key_unavailable_session;
```

`entry_sig_cols` says the COLUMNS exist, which after enabling signing is
true for every session in the database. So a legitimate pre-signing
session, verified with the pubkey supplied, took the signed-session path,
found no signature at sequence 0, and reported:

```
Missing Ed25519 signature at sequence 0 in a signed session (stripped signature)
```

The Python verifier asked the per-session question and got it right. No
test covered the migration sequence in either implementation, so the
disagreement was invisible. `tests/test_chain_signing_migration.c` covers
it now, in both directions: the pre-signing session must PASS, and
stripping a signature out of a session whose head is still signed must
still FAIL.

## Where a verdict may and may not be diluted

A verdict describes the EVIDENCE. An operational failure of the verifier
itself describes the VERIFIER, and the two must never be rendered on the
same axis. See `VERIFIER_ERROR` in `report/verify.py`: a storage or IO
error while verifying is not "unverifiable evidence", it is "this run did
not complete", and it exits with its own code.
