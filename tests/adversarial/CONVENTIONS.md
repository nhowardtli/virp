# Adversarial test program — conventions

These are binding conventions for the adversarial program (builds/tests under
`tests/adversarial/`). They exist because an adversarial finding is only
meaningful against a *known* base, and a finding against a stale base can read
as open when it is already fixed (as happened when a session tested an older
base and reported the `chain_append`/`artifact_store` non-atomicity as open
after it had already been fixed in-transaction on merged main).

## 1. Every transcript pins the commit it tested

Each transcript's header MUST record the exact commit the run was executed
against, not just the branch. The header block becomes:

```
**Date:** YYYY-MM-DD · **Host:** <host> · **Branch:** `<branch>`
**Commit:** `<short-sha>`   (git rev-parse --short HEAD at run time)
```

Rationale: a crash/atomicity/verifier finding is a statement about a specific
tree. Without the commit, a reader cannot tell whether a later fix already
closed it. The commit is the difference between "this is open" and "this was
open at `<sha>`; check whether it still is."

Transcript conclusions that assert a defect SHOULD say "at `<sha>`" so the
claim carries its own base.

## 2. The adversarial tree rebases onto merged main before a new test

Before starting a new test (e.g. test #3), the adversarial branch MUST be
rebased onto the current merged `main`, so the run exercises the shipped code,
not a diverged snapshot. Record the resulting base commit per convention 1.

Rationale: the audit batches land fixes on `main` continuously. An adversarial
run on a pre-fix base re-discovers closed findings and wastes the reviewer's
time reconciling them. Rebase first; then what survives is genuinely open.

## Corollary — reconciling a stale finding

If a run reports a finding that the current `main` shows fixed, the finding is
reconciled to "already closed at `<merged-sha>`", NOT re-implemented. Re-fixing
shipped code to manufacture a red is forbidden; a red proof against a shipped
fix is produced in a **harness-only** build (e.g. reverting the body store to a
post-`COMMIT` autocommit only inside the fault-injection build), never by
touching the shipped path.
