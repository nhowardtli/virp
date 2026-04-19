# Security Policy

## Reporting Vulnerabilities

VIRP is a security-critical protocol. If you discover a vulnerability in the cryptographic verification path, chain integrity, HMAC signing, or trust tier enforcement:

**Do NOT open a public issue.**

Email: nhoward@thirdlevelit.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if you have one)

We will acknowledge receipt within 48 hours and provide a timeline for remediation.

## Scope

The following are in scope for security reports:

- HMAC-SHA256 signing bypass or forgery
- Trust tier escalation (e.g., RED command executing as GREEN)
- Chain database tampering without detection
- O-Node socket authentication bypass
- Device credential exposure through the API layer
- Session handshake state machine violations

## Out of Scope

- Denial of service against the O-Node (known limitation — single-process architecture)
- Issues requiring physical access to the host machine
- Social engineering

## Socket Peer Authentication

The O-Node Unix domain socket is gated by `SO_PEERCRED` (Linux). VIRP
currently supports Linux only; the BSD `getpeereid` equivalent is not
implemented. Every `accept()` reads the connecting process's UID and
compares it against a startup-loaded allowlist:

- `VIRP_ALLOWED_UIDS` — comma-separated UID list (e.g. `VIRP_ALLOWED_UIDS=0,1001`)
- Prod builds also honor `socket_allowed_uids` in the JSON config
- If neither is set, the allowlist defaults to the daemon's own
  effective UID — closed to every other local user

Rejected connections are closed immediately without reading any bytes
and produce a single `REJECTED connection: peer uid=...` log line.

The socket itself is created mode 0660 atomically via `umask(0117)` set
around `bind()` (with a belt-and-suspenders `chmod(0660)` after), so
there is no window in which a world-accessible node exists on disk.

## Supported Versions

| Version | Supported |
|---------|-----------|
| main branch | ✅ |
| Older commits | Best-effort |

## Recognition

Security researchers who report valid vulnerabilities will be credited in the CHANGELOG (unless they prefer anonymity).
