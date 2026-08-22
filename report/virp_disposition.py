"""
Auto-generated from include/virp_disposition.h by scripts/gen_disposition.py.
Do not edit by hand. `make check-disposition` fails on drift.

Execution disposition vocabulary shared by the C core and the
report layer. See the header for the meaning of each state and
for the legacy-record rule this module's helpers implement.
"""

UNSET = 0
NOT_DISPATCHED = 1
EXECUTED_CONFIRMED = 2
EXECUTED_FAILED = 3
EXECUTED_UNKNOWN = 4

NAME_NOT_DISPATCHED = 'NOT_DISPATCHED'
NAME_EXECUTED_CONFIRMED = 'EXECUTED_CONFIRMED'
NAME_EXECUTED_FAILED = 'EXECUTED_FAILED'
NAME_EXECUTED_UNKNOWN = 'EXECUTED_UNKNOWN'

# The four persistable states, by canonical name. UNSET is not one.
PERSISTABLE = (NAME_NOT_DISPATCHED, NAME_EXECUTED_CONFIRMED, NAME_EXECUTED_FAILED, NAME_EXECUTED_UNKNOWN)

# Reader-side labels for records written before this vocabulary
# existed. Never written by the daemon; never mapped onto PERSISTABLE.
LEGACY_CONFIRMED = 'LEGACY_CONFIRMED'
LEGACY_FAILED = 'LEGACY_FAILED'

# Body schema tags. A reader keys on these to tell new from legacy.
GATE_EXECUTION_SCHEMA_V1 = 'gate_execution/1'
GATE_EXECUTION_SCHEMA_V2 = 'gate_execution/2'
OUTCOME_SCHEMA_V2 = 'outcome/2'


def success_of(disposition):
    """The DERIVED boolean the C side writes alongside a disposition:
    True only for EXECUTED_CONFIRMED, False only for EXECUTED_FAILED,
    None for EXECUTED_UNKNOWN and NOT_DISPATCHED (the yes/no question
    has no honest answer there)."""
    if disposition == NAME_EXECUTED_CONFIRMED:
        return True
    if disposition == NAME_EXECUTED_FAILED:
        return False
    return None

