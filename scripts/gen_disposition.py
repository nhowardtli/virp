#!/usr/bin/env python3
"""
Generate report/virp_disposition.py from include/virp_disposition.h.

include/virp_disposition.h is the single definition of the execution
disposition vocabulary shared by the C core (which writes records) and
the report layer (which grades them). This script mirrors it into a
stdlib-only Python module so report/ never hand-codes a name that can
drift from the header.

    python3 scripts/gen_disposition.py > report/virp_disposition.py
    make gen-disposition        # same
    make check-disposition      # fails if the committed module is stale

Parsed from the header, nothing else:
  - every `VIRP_DISPOSITION_<STATE> = <n>,` enum line
  - every `#define VIRP_DISPOSITION_NAME_<STATE> "<name>"`
  - every `#define VIRP_DISPOSITION_LEGACY_<X> "<label>"`
  - every `#define VIRP_<...>_SCHEMA_V<n> "<tag>"`
"""

import re
import sys
from pathlib import Path

HEADER = Path(__file__).resolve().parent.parent / "include" / "virp_disposition.h"

ENUM_RE = re.compile(r"^\s*VIRP_DISPOSITION_(\w+)\s*=\s*(\d+)\s*,?\s*$")
NAME_RE = re.compile(r'^#define\s+VIRP_DISPOSITION_NAME_(\w+)\s+"([^"]+)"')
LEGACY_RE = re.compile(r'^#define\s+VIRP_DISPOSITION_(LEGACY_\w+)\s+"([^"]+)"')
SCHEMA_RE = re.compile(r'^#define\s+(VIRP_\w+_SCHEMA_V\d+)\s+"([^"]+)"')


def parse(header_path):
    enum, names, legacy, schemas = {}, {}, {}, {}
    for line in header_path.read_text().splitlines():
        m = ENUM_RE.match(line)
        if m:
            enum[m.group(1)] = int(m.group(2))
            continue
        m = NAME_RE.match(line)
        if m:
            names[m.group(1)] = m.group(2)
            continue
        m = LEGACY_RE.match(line)
        if m:
            legacy[m.group(1)] = m.group(2)
            continue
        m = SCHEMA_RE.match(line)
        if m:
            schemas[m.group(1)] = m.group(2)
    return enum, names, legacy, schemas


def main():
    if not HEADER.exists():
        print("ERROR: %s not found" % HEADER, file=sys.stderr)
        return 1
    enum, names, legacy, schemas = parse(HEADER)
    persistable = [k for k in enum if k != "UNSET"]
    if len(persistable) != 4 or set(persistable) != set(names):
        print("ERROR: header must define exactly four named persistable "
              "states; enum=%s names=%s" % (persistable, sorted(names)),
              file=sys.stderr)
        return 1

    out = []
    out.append('"""')
    out.append("Auto-generated from include/virp_disposition.h by "
               "scripts/gen_disposition.py.")
    out.append("Do not edit by hand. `make check-disposition` fails on drift.")
    out.append("")
    out.append("Execution disposition vocabulary shared by the C core and the")
    out.append("report layer. See the header for the meaning of each state and")
    out.append("for the legacy-record rule this module's helpers implement.")
    out.append('"""')
    out.append("")
    for state in sorted(enum, key=enum.get):
        out.append("%s = %d" % (state, enum[state]))
    out.append("")
    for state in sorted(names, key=enum.get):
        out.append("NAME_%s = %r" % (state, names[state]))
    out.append("")
    out.append("# The four persistable states, by canonical name. UNSET is not one.")
    out.append("PERSISTABLE = (%s)" % ", ".join(
        "NAME_%s" % s for s in sorted(names, key=enum.get)))
    out.append("")
    out.append("# Reader-side labels for records written before this vocabulary")
    out.append("# existed. Never written by the daemon; never mapped onto PERSISTABLE.")
    for k in sorted(legacy):
        out.append("%s = %r" % (k, legacy[k]))
    out.append("")
    out.append("# Body schema tags. A reader keys on these to tell new from legacy.")
    for k in sorted(schemas):
        out.append("%s = %r" % (k.replace("VIRP_", "", 1), schemas[k]))
    out.append("")
    out.append("")
    out.append("def success_of(disposition):")
    out.append('    """The DERIVED boolean the C side writes alongside a disposition:')
    out.append("    True only for EXECUTED_CONFIRMED, False only for EXECUTED_FAILED,")
    out.append("    None for EXECUTED_UNKNOWN and NOT_DISPATCHED (the yes/no question")
    out.append('    has no honest answer there)."""')
    out.append("    if disposition == NAME_EXECUTED_CONFIRMED:")
    out.append("        return True")
    out.append("    if disposition == NAME_EXECUTED_FAILED:")
    out.append("        return False")
    out.append("    return None")
    out.append("")
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
