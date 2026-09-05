#!/usr/bin/env python3
"""
virp_tacacs_codec.py — RFC 8907 TACACS+ codec. LAB ONLY.

Pure functions, no sockets, no chain, no keys beyond the shared secret
passed in. Split out from the receiver so the wire format can be tested
without a lab: every test in tests/test_tacacs_accounting.py builds
packets with the same code the receiver decodes with, and the
round-trip vectors are checked against the RFC's own construction
rather than against this module's opinion of it.

WHAT THE OBFUSCATION IS (RFC 8907 §4.5, §10.1): an MD5-derived
pseudo-pad XORed over the body. It is NOT encryption. RFC 8907 §10.1
says so directly. It authenticates possession of the shared secret and
hides the body from a passive reader who lacks it; it provides no
integrity guarantee, no replay protection, and no proof of origin.
Nothing in this module or above it may claim otherwise.

Copyright 2026 Third Level IT LLC — Apache 2.0
"""

import hashlib
import struct

HEADER_LEN = 12

# Session types (header byte 1).
TAC_PLUS_AUTHEN = 0x01
TAC_PLUS_AUTHOR = 0x02
TAC_PLUS_ACCT = 0x03

# Header flags (header byte 3).
TAC_PLUS_UNENCRYPTED_FLAG = 0x01
TAC_PLUS_SINGLE_CONNECT_FLAG = 0x04

# Accounting request flags (body byte 0).
TAC_PLUS_ACCT_FLAG_START = 0x02
TAC_PLUS_ACCT_FLAG_STOP = 0x04
TAC_PLUS_ACCT_FLAG_WATCHDOG = 0x08

# Accounting reply status.
TAC_PLUS_ACCT_STATUS_SUCCESS = 0x01
TAC_PLUS_ACCT_STATUS_ERROR = 0x02
TAC_PLUS_ACCT_STATUS_FOLLOW = 0x21

# Name tables. Every lookup keeps the raw value alongside the name, so a
# value this table does not know is recorded as the number it was and
# never silently becomes "unknown" with the number dropped.
AUTHEN_METHOD_NAMES = {
    0x00: "NOT_SET", 0x01: "NONE", 0x02: "KRB5", 0x03: "LINE",
    0x04: "ENABLE", 0x05: "LOCAL", 0x06: "TACACSPLUS", 0x08: "GUEST",
    0x10: "RADIUS", 0x11: "KRB4", 0x20: "RCMD",
}
AUTHEN_TYPE_NAMES = {
    0x01: "ASCII", 0x02: "PAP", 0x03: "CHAP", 0x04: "ARAP",
    0x05: "MSCHAP", 0x06: "MSCHAPV2",
}
AUTHEN_SERVICE_NAMES = {
    0x00: "NONE", 0x01: "LOGIN", 0x02: "ENABLE", 0x03: "PPP",
    0x04: "ARAP", 0x05: "PT", 0x06: "RCMD", 0x07: "X25",
    0x08: "NASI", 0x09: "FWPROXY",
}
SESSION_TYPE_NAMES = {
    TAC_PLUS_AUTHEN: "AUTHEN",
    TAC_PLUS_AUTHOR: "AUTHOR",
    TAC_PLUS_ACCT: "ACCT",
}


class TacacsMalformed(Exception):
    """Raised only by strict callers. The receiver does NOT use this to
    drop packets: a malformed packet is still recorded, with parse
    MALFORMED and whatever fields did decode. See tacacs/README.md."""


def name_of(table, value):
    """(name, raw). An unknown value yields a name of None — never a
    string that looks like a decode."""
    return table.get(value), value


def pseudo_pad(session_id, secret, version, seq_no, length):
    """RFC 8907 §4.5.

        MD5_1 = MD5(session_id || key || version || seq_no)
        MD5_n = MD5(session_id || key || version || seq_no || MD5_{n-1})
        pad   = (MD5_1 || MD5_2 || ...)[:length]

    session_id is the 4 header bytes in network order, version and
    seq_no one byte each — the same bytes the header carries, not a
    re-encoding of them.
    """
    sid = struct.pack("!I", session_id)
    base = sid + secret + bytes([version, seq_no])
    pad = b""
    prev = b""
    while len(pad) < length:
        prev = hashlib.md5(base + prev).digest()
        pad += prev
    return pad[:length]


def xor_body(body, session_id, secret, version, seq_no):
    """Apply the pad. XOR is its own inverse, so this both obfuscates
    and deobfuscates — deliberately one function, because two would
    invite them to drift apart."""
    pad = pseudo_pad(session_id, secret, version, seq_no, len(body))
    return bytes(b ^ p for b, p in zip(body, pad))


def parse_header(raw):
    """12-byte header -> dict. Raises TacacsMalformed if short."""
    if len(raw) < HEADER_LEN:
        raise TacacsMalformed("header is %d bytes, need %d"
                              % (len(raw), HEADER_LEN))
    version, typ, seq_no, flags, session_id, length = struct.unpack(
        "!BBBBII", raw[:HEADER_LEN])
    return {
        "version": version,
        "version_major": (version >> 4) & 0x0F,
        "version_minor": version & 0x0F,
        "type": typ,
        "type_name": SESSION_TYPE_NAMES.get(typ),
        "seq_no": seq_no,
        "flags": flags,
        "unencrypted": bool(flags & TAC_PLUS_UNENCRYPTED_FLAG),
        "single_connect": bool(flags & TAC_PLUS_SINGLE_CONNECT_FLAG),
        "session_id": session_id,
        "length": length,
    }


def build_header(version, typ, seq_no, flags, session_id, length):
    return struct.pack("!BBBBII", version, typ, seq_no, flags,
                       session_id, length)


def acct_flag_names(flags):
    """Ordered list of set accounting flags. WATCHDOG|START is a legal
    combination (an update carrying new data) and is reported as BOTH
    names, never collapsed to one — the combination is the fact."""
    out = []
    if flags & TAC_PLUS_ACCT_FLAG_START:
        out.append("START")
    if flags & TAC_PLUS_ACCT_FLAG_STOP:
        out.append("STOP")
    if flags & TAC_PLUS_ACCT_FLAG_WATCHDOG:
        out.append("WATCHDOG")
    return out


def parse_acct_request(body):
    """RFC 8907 §6.1 accounting REQUEST body -> (fields, parse_state).

    parse_state is "COMPLETE" or "MALFORMED". A MALFORMED body returns
    every field that DID decode rather than raising: the receiver
    records it either way, and a partially-decoded packet is more
    evidence than a dropped one.

    Layout:
      flags, authen_method, priv_lvl, authen_type, authen_service,
      user_len, port_len, rem_addr_len, arg_cnt,
      arg_1_len .. arg_N_len,
      user, port, rem_addr, arg_1 .. arg_N
    """
    f = {
        "acct_flags_raw": None, "acct_flags": [],
        "authen_method_raw": None, "authen_method": None,
        "priv_lvl": None,
        "authen_type_raw": None, "authen_type": None,
        "authen_service_raw": None, "authen_service": None,
        "user": None, "port": None, "rem_addr": None,
        "arg_cnt": None, "args": [],
    }
    if len(body) < 9:
        return f, "MALFORMED"

    (flags, a_method, priv_lvl, a_type, a_service,
     user_len, port_len, rem_len, arg_cnt) = struct.unpack("!9B", body[:9])

    f["acct_flags_raw"] = flags
    f["acct_flags"] = acct_flag_names(flags)
    f["authen_method"], f["authen_method_raw"] = name_of(
        AUTHEN_METHOD_NAMES, a_method)
    f["priv_lvl"] = priv_lvl
    f["authen_type"], f["authen_type_raw"] = name_of(
        AUTHEN_TYPE_NAMES, a_type)
    f["authen_service"], f["authen_service_raw"] = name_of(
        AUTHEN_SERVICE_NAMES, a_service)
    f["arg_cnt"] = arg_cnt

    off = 9
    if len(body) < off + arg_cnt:
        return f, "MALFORMED"
    arg_lens = list(body[off:off + arg_cnt])
    off += arg_cnt

    need = user_len + port_len + rem_len + sum(arg_lens)
    state = "COMPLETE" if len(body) >= off + need else "MALFORMED"

    def take(n):
        nonlocal off
        chunk = body[off:off + n]
        off += n
        return chunk

    # latin-1 round-trips every byte 0x00-0xFF to a character and back,
    # so a non-UTF-8 argument is preserved rather than replaced with
    # U+FFFD. These are transcription fields; they must not lose bytes.
    f["user"] = take(user_len).decode("latin-1")
    f["port"] = take(port_len).decode("latin-1")
    f["rem_addr"] = take(rem_len).decode("latin-1")
    for n in arg_lens:
        if off >= len(body) and n:
            state = "MALFORMED"
            break
        f["args"].append(take(n).decode("latin-1"))

    return f, state


def build_acct_request(acct_flags, authen_method, priv_lvl, authen_type,
                       authen_service, user, port, rem_addr, args):
    """Inverse of parse_acct_request. Used by the tests to build the
    packets a router would send, and by `virp_tacacs_recv.py selftest`."""
    u = user.encode("latin-1")
    p = port.encode("latin-1")
    r = rem_addr.encode("latin-1")
    a = [x.encode("latin-1") for x in args]
    for blob in [u, p, r] + a:
        if len(blob) > 255:
            raise TacacsMalformed("field exceeds 255 bytes: %r" % blob[:32])
    out = struct.pack("!9B", acct_flags, authen_method, priv_lvl,
                      authen_type, authen_service, len(u), len(p),
                      len(r), len(a))
    out += bytes(len(x) for x in a)
    out += u + p + r + b"".join(a)
    return out


def build_acct_reply(status, server_msg=b"", data=b""):
    """RFC 8907 §6.2: server_msg_len(2), data_len(2), status(1),
    server_msg, data. Note the status byte follows both lengths."""
    return (struct.pack("!HHB", len(server_msg), len(data), status)
            + server_msg + data)


def parse_acct_reply(body):
    if len(body) < 5:
        raise TacacsMalformed("accounting reply is %d bytes" % len(body))
    msg_len, data_len, status = struct.unpack("!HHB", body[:5])
    off = 5
    return {
        "status": status,
        "server_msg": body[off:off + msg_len].decode("latin-1"),
        "data": body[off + msg_len:off + msg_len + data_len].decode("latin-1"),
    }


def args_index(args):
    """A lookup into `args`, NOT a second source of truth.

    Values are byte-identical to the argument they came from, selected
    by FIRST occurrence. RFC 8907 §5.5 allows both `=` (mandatory) and
    `*` (optional) as the name/value separator; both are honoured for
    finding the split point, and the separator is not recorded as part
    of either half.

    Any name appearing more than once is listed in `duplicates`, and a
    reader is expected to go to `args` itself. Nothing here normalizes
    case, unescapes, or reorders.
    """
    first = {}
    seen = {}
    for a in args:
        eq = a.find("=")
        st = a.find("*")
        if eq < 0 and st < 0:
            name, value = a, None
        else:
            cut = eq if (st < 0 or (0 <= eq < st)) else st
            name, value = a[:cut], a[cut + 1:]
        seen[name] = seen.get(name, 0) + 1
        if name not in first:
            first[name] = value
    return {
        "task_id": first.get("task_id"),
        "service": first.get("service"),
        "cmd": first.get("cmd"),
        "lookup_rule": "first_occurrence_verbatim",
        "duplicates": sorted(n for n, c in seen.items() if c > 1),
    }
