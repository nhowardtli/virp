# What you just watched: the demo, step by step

*A plain-language companion to `./demo/run.sh`. No programming knowledge
needed. For the precise technical claims, see [`README.md`](README.md); for
what has and has not been established, see the
[security page](https://thirdlevel.ai/virp/security.html).*

The demo tells one short story. A requester (in real deployments, an AI agent
or a script) asks a collector — the O-Node — to run commands against a device.
The collector decides what kind of request each one is (GREEN for safe reads,
RED for changes that need a human), does it or refuses it, and seals a record
of what happened so it can't be quietly altered afterward. The nine steps walk
that story end to end.

**1. A GREEN operation executes.** The requester asks for a harmless read
("show version"), and the collector's gate classifies it GREEN — safe to run —
and runs it. Why it matters: the decision about what is safe is made by the
collector, not by the requester asking.

**2. Its record verifies.** The record of that read carries an authentication
tag the collector computed with a secret key, and the verifier checks it. Why
it matters: a record with a valid tag is one the collector actually produced —
the requester can't manufacture one, because it never holds the key.

**3. Modifying the record causes verification failure.** The demo changes one
detail in a copy of the record and checks it again; the altered copy is
rejected while the original still passes. Why it matters: you just watched
tampering get caught — edits after the fact don't survive verification.

**4. A RED operation is blocked.** The requester asks for a configuration
change; the gate classifies it RED — requires a human — refuses to run it, and
files a proposal describing exactly what was requested. Why it matters:
wanting to make a change and being allowed to make it are separated, and the
refusal itself becomes part of the record.

**5. An Ed25519 approval is created.** A human approver signs that specific
proposal with a separate signing key the collector never holds. Why it
matters: approval comes from outside the system being approved — the collector
can't approve its own work, and the signature covers this exact command on
this exact device.

**6. The exact approved operation executes.** With the signed approval
presented, the collector runs the change — and only that change. Why it
matters: the approval isn't a general "go ahead"; it is bound to one command
on one device.

**7. Reusing the approval fails.** The demo presents the same approval a
second time; the collector refuses. Why it matters: an approval works once.
Yesterday's yes can't be replayed to authorize today's change.

**8. An unknown operation fails closed.** The requester asks for something the
gate has no rule for; instead of guessing, the collector refuses. Why it
matters: the safe default is no — anything unrecognized is refused, not waved
through.

**9. The evidence chain verifies.** Every record from this run is a link in a
chain: each entry commits to the one before it, so removing or reordering
entries breaks the chain, and the verifier walks it end to end. Why it
matters: the history reads as one tamper-evident sequence, not a loose pile of
logs.

The demo's closing line is the honest boundary, and it is worth repeating
here: **the target was simulated. This shows protocol behavior, not that any
real device was reached or told the truth.** The demo establishes what the
collector does with requests, records, and approvals — not what any real
network is doing.
