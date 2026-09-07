# Backlog

Items that are agreed to be real but are not scheduled yet. Each entry
states the defect, the evidence that it is real, and what "done" means.
Delete an entry when it lands, in the commit that lands it.

## TACACS receiver: spool when the O-Node is unreachable

**Defect.** `virp_tacacs_recv.py` appends each accounting record to the
chain synchronously. If the O-Node socket is unavailable at that moment
the record is lost: the receiver writes an honest `APPEND_FAILED` ledger
entry naming the record it could not append, and then drops it. The
switch has already sent it and will not send it again, so the accounting
record simply does not exist on the chain.

**Evidence it is real.** 2026-09-07 16:42:18Z on VM 313, during a
`virp-onode` restart:

    {"event": "APPEND_FAILED",
     "artifact_id": "tacacs:10.0.0.10:4195317974:1:fbb595a29f213926",
     "body_sha256": "3db1ba038eaf3837d47aa7a7a0cdb340619ca2ce5b095d1598f43562e9d96489",
     "detail": "O-Node unreachable: [Errno 2] No such file or directory",
     "source_addr": "10.0.0.10"}

One real record from LAB-SWITCH-1, gone. Any O-Node restart loses every
record that arrives inside its window.

**The camera path already solves this.** Segments captured during the
same restart were held and replayed in capture order the moment the
socket returned. Chain sequence numbers across the outage are unbroken
(`camera:axis-m3085v-b8a44fdd572c:2026-09-07` seq 10017 to 10018, no
skip), and the append lag shows the replay: five segments captured
between 16:41:52Z and 16:42:16Z were all appended at 16:42:20Z, oldest
first, after which lag returned to its normal 4 seconds.

**Done means.** The receiver spools an unappendable record to durable
local storage instead of dropping it, replays the spool in arrival order
when the O-Node returns, and appends an outage marker record naming the
window and the number of records replayed. The marker matters: today
continuity across an outage can only be inferred from unbroken sequence
numbers, and nothing on the chain says an outage happened at all.
Ordering is part of the contract, not an implementation detail, because
an accounting session's STOP record is only meaningful after its START.
