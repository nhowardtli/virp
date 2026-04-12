#!/usr/bin/env python3
"""
Generate api/_virp_constants.py from include/virp.h.

Extracts #define constants matching known VIRP protocol prefixes so
Python never hand-codes values that can drift from the C header.

Usage:
    python3 scripts/gen_constants.py > api/_virp_constants.py
    # or via Makefile: make gen-constants
"""

import re
import sys
from pathlib import Path

HEADER = Path(__file__).resolve().parent.parent / "include" / "virp.h"

# Prefixes to extract
PREFIXES = (
    "VIRP_VERSION",
    "VIRP_HEADER_SIZE",
    "VIRP_HMAC_SIZE",
    "VIRP_KEY_SIZE",
    "VIRP_MAX_MESSAGE_SIZE",
    "VIRP_MAX_PAYLOAD_SIZE",
    "VIRP_CHANNEL_",
    "VIRP_MSG_",
    "VIRP_TIER_",
    "VIRP_OBS_",
    "VIRP_SCOPE_",
    "VIRP_APPROVAL_",
)

# Regex for simple #define NAME value lines (handles hex, decimal, and
# simple expressions like (VIRP_MAX_MESSAGE_SIZE - VIRP_HEADER_SIZE))
DEFINE_RE = re.compile(
    r"^#define\s+(VIRP_\w+)\s+(.+?)(?:\s*/\*.*\*/)?$"
)


def parse_defines(header_path: Path) -> list[tuple[str, str]]:
    results = []
    for line in header_path.read_text().splitlines():
        line = line.strip()
        m = DEFINE_RE.match(line)
        if not m:
            continue
        name, value = m.group(1), m.group(2).strip()
        if not any(name.startswith(p) for p in PREFIXES):
            continue
        results.append((name, value))
    return results


def main():
    if not HEADER.exists():
        print(f"ERROR: {HEADER} not found", file=sys.stderr)
        sys.exit(1)

    defines = parse_defines(HEADER)
    if not defines:
        print("ERROR: no matching #defines found", file=sys.stderr)
        sys.exit(1)

    print('"""')
    print("Auto-generated from include/virp.h by scripts/gen_constants.py.")
    print("Do not edit by hand.")
    print('"""')
    print()

    for name, value in defines:
        # Convert C-style expressions to Python
        # Replace (A - B) style with Python equivalent
        py_value = value
        print(f"{name} = {py_value}")


if __name__ == "__main__":
    main()
