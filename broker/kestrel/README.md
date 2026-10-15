# Kestrel bounded Duo coordinator — candidate

Not installed or reachable from the cage. approval_plan.py is an internal
trusted-service API, not an authenticated public endpoint. It accepts no
caller-supplied approval boolean. DuoAuth performs explicit push and polls the
same transaction; the protected ledger binds it to an immutable digest.

Current scope: SW-3850 10.0.10.2 serial FCW2305C0EP, description on
GigabitEthernet1/0/22 only. Forward and exact restore have separate native C
VAP1 challenge bytes and single-use issuance. One owner push displays both.
No write memory, reload, arbitrary commands, retry after uncertain dispatch,
expiry extension or operator credential disclosure. GREEN show interfaces is
the verification read; show running-config remains YELLOW.

The production service must authenticate the primary owner, pin device node
ID and host key, verify C observation authentication before supplying challenge
or current description, own the SQLite directory mode0700, enforce its active
lease/STOP on every step, and provide a private signing dependency. These are
not provided by this library alone. Native C signatures authenticate individual
proposals; the plan ledger must be exported and bound into the evidence chain
to attest that both signatures came from one approved workflow. Duo success is
not the owner's Ed25519 signature. No compliance or independent witness claim.

Expiry/reboot fail closed. A crash after issuance intent refuses reissuance;
recovery needs fresh observed state and an explicitly authorized path. The
local events table is a hash-linked ledger, not an independently signed chain.
Verified Push currently refuses before sending when number display is needed;
it does not downgrade to a simpler policy. No real push occurs in tests.

Run: python3 -m unittest discover -v -s broker/kestrel
