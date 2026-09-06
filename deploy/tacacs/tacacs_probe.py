#!/usr/bin/env python3
"""tacacs_probe.py -- a dependency-free TACACS+ client, for proving policy.

Stdlib only, single file, no install. That is deliberate: this has to run
on 313, which is the gate, and the standing rule is that nothing is
installed there. Copy it to /tmp, run it, delete it.

Implements exactly the two exchanges the proof needs, per RFC 8907:
  - AUTHENTICATION, PAP  (single round trip)
  - AUTHORIZATION, per-command

It is not a general-purpose library. It does not do ASCII login
continuations, CHAP, accounting, or single-connect. It does not need to.

The body obfuscation is the RFC 8907 MD5 pseudo-pad. That is not
encryption and is not claimed to be -- it is what TACACS+ specifies, and
the proof is about policy decisions, not transport secrecy.
"""

import argparse
import hashlib
import os
import socket
import struct
import sys

TAC_PLUS_MAJOR = 0xC
TYPE_AUTHEN, TYPE_AUTHOR = 0x01, 0x02

AUTHEN_STATUS = {1: "PASS", 2: "FAIL", 3: "GETDATA", 4: "GETUSER",
                 5: "GETPASS", 6: "RESTART", 7: "ERROR", 0x21: "FOLLOW"}
AUTHOR_STATUS = {1: "PASS_ADD", 2: "PASS_REPL", 0x10: "FAIL",
                 0x11: "ERROR", 0x21: "FOLLOW"}


def pseudo_pad(session_id, key, version, seq_no, length):
    """RFC 8907 5.4.1 MD5 pad. Repeated MD5 over the previous digest."""
    key = key.encode() if isinstance(key, str) else key
    pad, prev = b"", b""
    while len(pad) < length:
        h = hashlib.md5()
        h.update(struct.pack("!I", session_id) + key +
                 bytes([version]) + bytes([seq_no]) + prev)
        prev = h.digest()
        pad += prev
    return pad[:length]


def obfuscate(body, session_id, key, version, seq_no):
    if not key:
        return body
    pad = pseudo_pad(session_id, key, version, seq_no, len(body))
    return bytes(a ^ b for a, b in zip(body, pad))


class TacacsError(Exception):
    pass


class Client:
    def __init__(self, host, port, key, timeout=10):
        self.host, self.port, self.key, self.timeout = host, port, key, timeout

    def _exchange(self, pkt_type, version, body):
        session_id = struct.unpack("!I", os.urandom(4))[0]
        seq = 1
        enc = obfuscate(body, session_id, self.key, version, seq)
        # flags=0: body IS obfuscated. Setting bit 0 would send cleartext.
        hdr = struct.pack("!BBBBII", version, pkt_type, seq, 0,
                          session_id, len(enc))
        with socket.create_connection((self.host, self.port),
                                      self.timeout) as s:
            s.sendall(hdr + enc)
            rhdr = self._recv_exact(s, 12)
            rver, rtype, rseq, rflags, rsid, rlen = struct.unpack("!BBBBII",
                                                                  rhdr)
            if rlen > 65535:
                raise TacacsError("implausible body length %d" % rlen)
            rbody = self._recv_exact(s, rlen)
        if not (rflags & 0x01):
            rbody = obfuscate(rbody, rsid, self.key, rver, rseq)
        return rbody

    @staticmethod
    def _recv_exact(s, n):
        buf = b""
        while len(buf) < n:
            chunk = s.recv(n - len(buf))
            if not chunk:
                raise TacacsError("connection closed after %d/%d bytes "
                                  "(wrong shared key is the usual cause)"
                                  % (len(buf), n))
            buf += chunk
        return buf

    def authenticate(self, user, password, port="tty0", rem_addr="127.0.0.1"):
        """PAP authentication. minor version 1, as RFC 8907 requires."""
        version = (TAC_PLUS_MAJOR << 4) | 1
        u, p, r, d = (user.encode(), port.encode(),
                      rem_addr.encode(), password.encode())
        body = struct.pack("!BBBBBBBB",
                           0x01,        # action  = LOGIN
                           1,           # priv_lvl (advisory on the request)
                           0x02,        # authen_type = PAP
                           0x01,        # authen_service = LOGIN
                           len(u), len(p), len(r), len(d)) + u + p + r + d
        rb = self._exchange(TYPE_AUTHEN, version, body)
        status, flags, smsg_len, data_len = struct.unpack("!BBHH", rb[:6])
        smsg = rb[6:6 + smsg_len].decode(errors="replace")
        return AUTHEN_STATUS.get(status, "UNKNOWN(0x%02x)" % status), smsg

    def authorize(self, user, command, priv_lvl=1, port="tty0",
                  rem_addr="127.0.0.1", add_cr=True):
        """Per-command authorization, shaped the way IOS shapes it.

        IOS does NOT send the command as one string. It sends
        cmd=<verb> plus one cmd-arg= per remaining token, and terminates
        with cmd-arg=<cr>. tac_plus-ng reassembles those into a single
        space-joined line (author.c:eval_args). Sending the whole command
        as cmd= would produce a DIFFERENT string on the server and would
        prove nothing about what a real router gets.
        """
        version = TAC_PLUS_MAJOR << 4
        toks = command.split()
        args = ["service=shell"]
        if toks:
            args.append("cmd=" + toks[0])
            for t in toks[1:]:
                args.append("cmd-arg=" + t)
            if add_cr:
                args.append("cmd-arg=<cr>")
        else:
            args.append("cmd=")           # EXEC / shell login authorization
        argb = [a.encode() for a in args]
        u, p, r = user.encode(), port.encode(), rem_addr.encode()
        body = struct.pack("!BBBBBBBB",
                           0x06,        # authen_method = TACACSPLUS
                           priv_lvl,
                           0x02,        # authen_type = PAP
                           0x01,        # authen_service = LOGIN
                           len(u), len(p), len(r), len(argb))
        body += bytes(len(a) for a in argb)
        body += u + p + r + b"".join(argb)
        rb = self._exchange(TYPE_AUTHOR, version, body)
        status, arg_cnt, smsg_len, data_len = struct.unpack("!BBHH", rb[:6])
        off = 6 + arg_cnt
        smsg = rb[off:off + smsg_len].decode(errors="replace")
        return AUTHOR_STATUS.get(status, "UNKNOWN(0x%02x)" % status), smsg


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=49)
    ap.add_argument("--key", required=True,
                    help="TACACS+ shared key. Pass via a file/env in real "
                         "use; it lands in argv here.")
    ap.add_argument("--user", required=True)
    ap.add_argument("--password")
    ap.add_argument("--priv-lvl", type=int, default=1)
    ap.add_argument("--rem-addr", default="127.0.0.1")
    ap.add_argument("--authenticate", action="store_true")
    ap.add_argument("--command", action="append", default=[],
                    help="command to authorize; repeatable")
    ap.add_argument("--no-cr", action="store_true",
                    help="omit the IOS <cr> terminator")
    args = ap.parse_args()

    c = Client(args.host, args.port, args.key)
    rc = 0

    if args.authenticate:
        if args.password is None:
            sys.exit("--authenticate needs --password")
        try:
            status, msg = c.authenticate(args.user, args.password,
                                         rem_addr=args.rem_addr)
        except Exception as e:
            print("AUTHEN %-10s ERROR %s" % (args.user, e))
            sys.exit(2)
        print("AUTHEN %-8s %-6s %s" % (args.user, status, msg))
        if status != "PASS":
            rc = 1

    for cmd in args.command:
        try:
            status, msg = c.authorize(args.user, cmd,
                                      priv_lvl=args.priv_lvl,
                                      rem_addr=args.rem_addr,
                                      add_cr=not args.no_cr)
        except Exception as e:
            print("AUTHOR %-8s %-40r ERROR %s" % (args.user, cmd, e))
            rc = 2
            continue
        permitted = status in ("PASS_ADD", "PASS_REPL")
        print("AUTHOR %-8s %-40r %-9s %s"
              % (args.user, cmd, status,
                 "PERMIT" if permitted else "DENY"))
        if not permitted:
            rc = max(rc, 1)

    sys.exit(rc)


if __name__ == "__main__":
    main()
