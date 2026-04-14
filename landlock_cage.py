#!/usr/bin/env python3
"""
Wall 4 — Landlock enforcement for IronClaw AI process.
Applies kernel-level filesystem restrictions BEFORE starting server.py.
Once applied, irreversible — even root cannot undo.
"""
import ctypes
import ctypes.util
import os
import sys
import struct

# Landlock syscall numbers (x86_64)
SYS_landlock_create_ruleset = 444
SYS_landlock_add_rule = 445
SYS_landlock_restrict_self = 446

# Landlock access flags for filesystem (ABI v1+)
LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12
LANDLOCK_ACCESS_FS_REFER = 1 << 13
LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14

# Rule type
LANDLOCK_RULE_PATH_BENEATH = 1

# All filesystem access flags
ALL_FS_ACCESS = (
    LANDLOCK_ACCESS_FS_EXECUTE |
    LANDLOCK_ACCESS_FS_WRITE_FILE |
    LANDLOCK_ACCESS_FS_READ_FILE |
    LANDLOCK_ACCESS_FS_READ_DIR |
    LANDLOCK_ACCESS_FS_REMOVE_DIR |
    LANDLOCK_ACCESS_FS_REMOVE_FILE |
    LANDLOCK_ACCESS_FS_MAKE_CHAR |
    LANDLOCK_ACCESS_FS_MAKE_DIR |
    LANDLOCK_ACCESS_FS_MAKE_REG |
    LANDLOCK_ACCESS_FS_MAKE_SOCK |
    LANDLOCK_ACCESS_FS_MAKE_FIFO |
    LANDLOCK_ACCESS_FS_MAKE_BLOCK |
    LANDLOCK_ACCESS_FS_MAKE_SYM |
    LANDLOCK_ACCESS_FS_REFER |
    LANDLOCK_ACCESS_FS_TRUNCATE
)

READ_ONLY = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE
READ_WRITE = READ_ONLY | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_TRUNCATE

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

def syscall(num, *args):
    libc.syscall.restype = ctypes.c_long
    libc.syscall.argtypes = [ctypes.c_long] + [ctypes.c_long] * len(args)
    ret = libc.syscall(num, *args)
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"syscall {num} failed: {os.strerror(err)}")
    return ret

def create_ruleset(fs_access):
    """Create a Landlock ruleset handling all filesystem access."""
    # struct landlock_ruleset_attr { __u64 handled_access_fs; }
    attr = struct.pack("Q", fs_access)
    buf = ctypes.create_string_buffer(attr)
    return syscall(SYS_landlock_create_ruleset, ctypes.addressof(buf), len(attr), 0)

def add_path_rule(ruleset_fd, path, access):
    """Allow specific access to a filesystem path."""
    fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
    try:
        # struct landlock_path_beneath_attr { __u64 allowed_access; __s32 parent_fd; }
        attr = struct.pack("Qi", access, fd)
        buf = ctypes.create_string_buffer(attr)
        syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                ctypes.addressof(buf), 0)
    finally:
        os.close(fd)

def enforce():
    """Apply Landlock restrictions. IRREVERSIBLE."""
    print("[WALL 4] Creating Landlock ruleset...")
    ruleset_fd = create_ruleset(ALL_FS_ACCESS)

    # === ALLOWED PATHS ===
    rules = [
        # IronClaw dashboard — READ ONLY. AI cannot modify its own code.
        ("/opt/virp-dashboard",           READ_ONLY),
        # Python runtime
        ("/usr/lib/python3",              READ_ONLY),
        ("/usr/lib/python3.10",           READ_ONLY),
        ("/usr/bin",                      READ_ONLY),
        ("/usr/lib",                      READ_ONLY),
        ("/lib",                          READ_ONLY),
        ("/lib64",                        READ_ONLY),
        ("/usr/share",                      READ_ONLY),
        # System necessities
        ("/etc",                          READ_ONLY),
        ("/proc",                         READ_ONLY),
        ("/sys",                          READ_ONLY),
        ("/dev",                          READ_ONLY),
        # Temp — read-write for runtime needs
        ("/tmp",                          READ_WRITE),
        ("/run",                          READ_WRITE),
        # OpenClaw config — read only
        ("/home/ironclaw/.openclaw",      READ_ONLY),
    ]

    for path, access in rules:
        if os.path.exists(path):
            add_path_rule(ruleset_fd, path, access)
            mode = "RO" if access == READ_ONLY else "RW"
            print(f"[WALL 4]   {mode}: {path}")
        else:
            print(f"[WALL 4]   SKIP (missing): {path}")

    # Everything not listed is DENIED. No /root, no /home/ironclaw/ironclaw,
    # no /usr/local/bin, no virp source code.

    # Apply — IRREVERSIBLE
    # First drop "no new privs" so Landlock takes effect
    PR_SET_NO_NEW_PRIVS = 38
    libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)

    syscall(SYS_landlock_restrict_self, ruleset_fd, 0)
    os.close(ruleset_fd)

    print("[WALL 4] === LANDLOCK ENFORCED — IRREVERSIBLE ===")
    print("[WALL 4] Denied: /root, /home/ironclaw/ironclaw, /usr/local/bin, VIRP source")
    print("[WALL 4] AI process cannot modify its own code or access keys")

if __name__ == "__main__":
    try:
        enforce()
    except OSError as e:
        print(f"[WALL 4] Landlock enforcement FAILED: {e}")
        print("[WALL 4] Continuing WITHOUT Landlock — Wall 4 inactive")
        sys.exit(1)

    # Launch the dashboard server
    print("[WALL 4] Starting server.py under Landlock...")
    os.execvp("python3", ["python3", "/opt/virp-dashboard/server.py"])
