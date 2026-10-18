# Production two-port qualification

Explicit owner-delegated standing scope for SW-3850 Gi1/0/22–23, October18.
This endpoint has no work expiry and no per-command approval. Existing leased
canary/production routes are not silently migrated. Native deadline enforcement,
UNKNOWN reconciliation and comprehensive BLACK alias coverage are not closed.

VM227 root runner `twoport_cage.py` uses GPT-6 Astra and the existing root-held
transport key. The model gets a CLI-shaped tool, not credentials. The forced
router on .211 selects `twoport_helper.py`; a dedicated no-login requester has
native RED ceiling. BLACK remains refused. The helper restricts reads and renders
one exact port configuration line as configure/interface/line/end. It never
accepts global configuration, another port, interface ranges, save or reload.

Root-pinned authorization, binary, config, modules and target are checked before
each exchange. STOP and unresolved outcomes still block. The standing scope is
explicit schema `kestrel-standing-scope/1`; absence of deadlines in a legacy
policy is an error, not an implicit migration. A root-only reviewed baseline
record enables writes and selects active VLANs. This is a helper-side baseline
check, not a native transaction/precondition proof. Per-request serialization,
intent and individual signed v3 exchanges are retained; the combined tool reply
is an unsigned presentation of those individual records.

The existing forced `stop` operation writes the new scope STOP without requiring
an unexpired old lease. No caller can clear it. Transport timeout does not retry
or kill the original request. Failed exchanges stop the run and retain evidence.
There is no generic automatic rollback. Restore uses the captured exact baseline
through the same governed path after resolving any outstanding outcome.

Deployment must preserve credential isolation: production devices.json is
root-owned with a read ACL for the daemon UID only. Do not use group-read mode
with the socket group, which also contains unprivileged requesters. Never place
keys, device credentials or private deployment profiles in this repository.

Qualification grammar permits access/trunk mode, selected active VLANs,
descriptions, edge protections, bounded port-security settings, auto speed/duplex
and administrative enable/disable. It does not establish end-to-end forwarding
when no device is attached, nor establish production-wide autonomous management.

The endpoint also holds the legacy production helper lock for the whole request,
so future use of the legacy read route cannot interleave a config-mode sequence.
This is process serialization, not a claim of native transaction isolation.
