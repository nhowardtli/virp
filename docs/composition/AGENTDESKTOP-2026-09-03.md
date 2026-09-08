# Agentdesktop and VIRP, composed: 2026-09-03

We put a third-party agent harness in front of VIRP and found two bugs in our seam and one in theirs.

Written 2026-09-03. Inputs are frozen alongside this file under
`docs/composition/agentdesktop-2026-09-03/`: `FINDINGS.md` (the Agentdesktop
review) and `CHAIN-GROUND-TRUTH-20260903.md` (a read-only dump of
`/var/lib/virp/chain.db` on 10.0.10.211). Chain sequence numbers below are
citations into that dump.

## 1. What was composed, and how

Agentdesktop v0.1.0, standalone install (no controller), on netclaw
(Ubuntu 24.04.4, kernel 6.8). Dex OIDC and Agentgateway both on loopback via
docker compose. Claude Code as the agent. Two VIRP MCP bridges registered in
`~/.claude.json`: `virp-bridge-remote` (to the colo O-Node at 10.0.10.211) and
`virp-bridge-local` (to netclaw's own O-Node). Later in the day Agentgateway
was repointed at Ollama on the Spark and the Anthropic provider was removed,
so the same path ran on local models.

```
  operator
     |
     v
  Claude Code ----------------> Agentgateway (127.0.0.1:4001) --> Anthropic
     |     (model path)              |                            or Ollama
     |                               +-- Dex OIDC (127.0.0.1:5557)
     |
     | (device path, MCP stdio)
     v
  sudo -n -u virp-bridge python3 virp-bridge-mcp.py
     |
     +--> virp-bridge-local  --> netclaw O-Node --> FRR testbed
     +--> virp-bridge-remote --> 10.0.10.211 O-Node --> clab-frr-ospf-frr1..4
                                     |
                                     v
                                 chain.db (append-only, signed)
```

Agentdesktop governs the model path: which endpoint the agent talks to, what
the Bash tool may touch, what telemetry is emitted. VIRP governs the device
path: which command reaches which device, at what trust tier, and what gets
signed into the chain. **Today they share a host and nothing else.** No
identity, token, or policy decision crosses between them. That is the single
most important fact in this document, and section 6 says what follows from it.

## 2. Agentdesktop findings

Five findings, against the `/home/nhoward/agentdesktop-main` checkout. Severity
is my call, not the vendor's.

**2.1 `--user` scopes reconcile but not discovery. Medium.**
`discovery/metadata.rs:189-232` (`user_home_dirs`) unions the invoking user's
home, every `is_dir()` field-6 path in `/etc/passwd`, and every directory under
`/home`. Nothing consults `--user`. `discovery/metadata.rs:16-25`
(`find_executable`) then takes the first existing candidate from a `BTreeSet`,
which iterates lexicographically. On netclaw that selected
`/home/claudecode/.local/bin/claude` (2.1.222) over nhoward's
`.npm-global` install (2.1.259), while reconcile correctly wrote
`/home/nhoward/.claude/settings.json`. The daemon therefore reports on one
install and manages another. Cross-user MCP disclosure was prevented only by
file permissions (`/home/claudecode/.claude.json` is mode-restricted and the
read failed), not by any scoping in the code.

**2.2 The sandbox is written with no enforcement signal on this host. High, host-specific.**
`reconcile/claude_code.rs:166-215` writes a `sandbox` block with
`failIfUnavailable: true`. On Ubuntu 24.04 with
`kernel.apparmor_restrict_unprivileged_userns=1`, `bwrap --unshare-net` fails
with `loopback: Failed RTM_NEWADDR: Operation not permitted`, reproducible with
no Claude Code involved. So the settings assert a sandbox that cannot start.
The two filesystem and network assertions could not be exercised at all. The
severity is in the gap between what the file says and what the kernel will do.

**2.3 The sandbox does not cover MCP at all. High, and by design.**
Same source range. The `sandbox` object never references `mcpServers`, and
`core/src/config.rs:27,39-46` shows the schema has no MCP key. The VIRP bridges
run as their own `sudo -u virp-bridge` process tree, outside it. This was
confirmed the clean way: with the sandbox enabled, the MCP GREEN read succeeded
while Bash sandbox init failed. Tightening `sandbox.filesystem.denied` does
nothing to the bridges. VIRP's own tier gate is what governs device access, and
that is the correct division, but it should be stated rather than assumed.

**2.4 MCP inventory disclosure is allowlist-limited. Clean, no action.**
`discovery/claude_code.rs:107-140` reads only `command`, `url`, `transport`,
`enabled`, `name`, `source`. `core/src/model.rs:43-60` has nowhere to put
`args`, `env`, or `headers`, with inline comments saying the omission is
deliberate. The raw entries it parses do carry `VIRP_ONODE_SOCKET`, the
`-u virp-bridge` identity, and the bridge path; none survive extraction. This
is an allowlist, not a denylist, so a future secret-bearing field is dropped by
default. Worth recording as a thing done right.

**2.5 Telemetry needs a controller. Low, informational.**
`reconcile/mod.rs:243-250` writes the `PreToolUse` and `SessionStart` hooks only
when telemetry events are configured; the standalone `config.yaml` sets none.
Even if forced, `daemon.rs:335` makes the telemetry sender `Some` only when a
controller exists, and `api.rs:56-76` returns 424 FAILED_DEPENDENCY otherwise.
Standalone Agentdesktop cannot emit tool-use telemetry. Anyone assuming the
harness provides an audit trail in this configuration is wrong.

**2.6 Agentgateway management listeners, in the example. Medium.**
Under `network_mode: host`, `stats` binds `[::]:15020` and `readiness` binds
`[::]:15021`; `admin` is loopback already, which corrects the premise as
originally filed. The stock example hides this by running on a bridge network
and publishing only `127.0.0.1:4001:4001`, so the safety comes from the Docker
port list and not from the defaults. `adminAddr`, `statsAddr`, `readinessAddr`
pin all three. The data plane on 4001 has no bind option
(`schema/config.json`: `LocalGateway` exposes `port` only), so an interface
filter is unavoidable there. On netclaw, with `ufw inactive` and
`iptables -P INPUT ACCEPT`, this was live LAN exposure of the metrics endpoint.

## 3. VIRP findings and fixes

Two bugs in our seam. Both are visible in the chain, and both fixes are visible
in the chain too.

### 3.1 Session identity was model-writable

`virp-bridge-mcp.py` declared `peer` and `request_id` as MCP tool arguments and
built the chain `session_id` from them. When gpt-oss:120b filled them in, the
.211 chain recorded a session called **`ncfed-user-session-req-001`**: a name
the model invented, signed into evidence as if it were identity. When qwen left
them empty, the same code produced `ncfed-unknown-unknown`.

The entry is `ncfed-user-session-req-001` seq 0 to 2. It is not a corrupt
record. It is a complete, correct, fully verified exchange (request, signed
GREEN observation, outcome `executed`) filed under a fictional name, with
`provenance_source: claimed`. The command really ran. The identity attached to
it was fabricated. Its `previous_entry_hash` (`aff745b96ddc176e...`) ties it
into the global chain, so it cannot be excised without breaking everything
after it, and it should not be: it is the only first-hand evidence that the
defect reached production evidence.

The file's own mitigation had been to label argument-supplied values `claimed`
and prefer `clientInfo` values labelled `verified`. That branch was dead in
production, because netclaw's `invocation.py:553` sends
`clientInfo {"name": "n2n", "version": "1.0"}` and no peer identity, so every
real call fell through to the claimed path. An honest label on a fabricated
value still puts the fabrication in the session id.

Fix, bridge commit `31ffbd05`: identity is derived from channels the model
cannot reach. User from `SUDO_USER`/`SUDO_UID`, set by sudo before exec. Host
from `socket.gethostname()`. Request id minted per invocation and never
accepted from the caller. The `peer` and `request_id` arguments were removed
from the tool schema. Commit `d6ba605f` then added `bridge_instance`
(`b-<pid>-<uuid4[:16]>`, minted once per process) as a body field, so the
per-invocation boundary survives without fragmenting the chain into short
per-process chains that nothing references.

The authenticated triple that followed is `ncfed-nhoward-netclaw` seq 9 to 11:
a GREEN read continuing the same chain across a separate bridge process, body
carrying `bridge_instance: b-3926283-1722a4815b7f4a68` and
`provenance_source: authenticated`, with `sha256(stored body)` equal to the
entry's `artifact_hash`. The before-and-after is readable straight off the
chain: `claimed` on one side of Sep 3, `authenticated` on the other.

### 3.2 Error paths left request/outcome pairs open

GATE 4 refuses a `fed_outcome` that cites nothing, which is correct. The
consequence was that an exchange dying before an observation existed could not
be closed at all: the `fed_request` landed and no outcome ever could.

**`ncfed-nhoward-netclaw` seq 21** is that, on a live chain, on purpose. A probe
asked for `obs_version 2` over the remote socket; uid 993's allowlist has no
`session_hello`, so the handshake was refused `-50` and the session-less v2
execute refused `-30`. Nothing reached a device. The bridge then tried to close
the pair with a `fed_error` body and was refused `-50`, because that node's
type policy did not carry the type yet. The chain is append-only, so **seq 21
can never be closed retroactively.**

Fix, bridge commit `04575219` and daemon commit `dc49b748`: `fed_error` is a
commitment type carrying no signature and claiming none, so GATE 3 does not
apply to it and it cannot be mistaken for signed evidence. GATE 4 now reads
either `observation_sha256` or `error_sha256`, exactly one, never both, and an
error-backed outcome may not claim `executed`. **Seq 22 to 24** is the
identical probe after the deploy, closed: `error_sha256` equal to
`sha256(fed_error body)` = `9854ef79...`, `observation_sha256` absent, outcome
`failed`. Seq 21 next to seq 22 to 24 is the before-and-after.

Two things were found while fixing this and not fixed.

The first is a real gap: **GATE 3 runs only when `artifact_content` is
non-empty.** A commitment-only `fed_observation` therefore skips GATE 2 and
GATE 3 and still satisfies GATE 4, so a client can cite any 64-hex string as an
unsigned observation. Ticketed, not fixed.

The second is drift, now reconciled. The bridge running on netclaw at
`/usr/local/lib/virp/virp-bridge-mcp.py` (installed 2026-08-16) was 59 lines
ahead of `origin/main` and existed in no repository. Commit `6451e3d4` imported
it verbatim, explicitly vouching only for "this is what is running", not for
correctness. Review of those 59 lines is a separate ticket. Three uncommitted
GATE 4/5 corrections were inside them, including per-invocation correlation
salting: the old unsalted hash keyed on `(peer, request_id, device, command)`,
and since peer and request_id were "unknown" on every call, every repeat of the
same read reused one artifact id forever.

## 4. The harness refused before VIRP ever saw the request

At 2026-09-03T21:27:49Z the agent emitted a correct tool call for a YELLOW read:

```
[tool_use] mcp__virp-bridge-remote__exec_device_command
           input= {"command": "vtysh -c \"show running-config\"",
                   "device": "clab-frr-ospf-frr1"}
```

At 21:28:45Z it came back refused, by the harness, not by us:

```
Permission for this action was denied by the Claude Code auto mode classifier.
Reason: No reason provided. If you have other tasks that don't depend on this
action, continue working on those. [...] To allow this type of action in the
future, the user can add a Bash permission rule to their settings.
```

At 21:28:54Z the model told the operator to loosen permissions:

```
The request to run `vtysh -c "show running-config"` on clab-frr-ospf-frr1 was
blocked by the permission system. [...] If you'd like to proceed, you can:
1. Adjust your settings to allow this command (e.g., add a Bash permission
   rule that permits `vtysh` on the FRR devices), or
2. Provide an alternative method you have access to for obtaining the
   configuration [...]
```

**No chain entry exists for this request.** Compare `ncfed-unknown-unknown`
seq 335 to 337, where the same command on the same device reached the gate and
produced a `fed_request`, a signed `OBS_ERROR` observation, and a `refused`
outcome: three signed entries saying a YELLOW read was declined. The classifier
block produced none of that. From the chain's point of view the request never
happened.

That is the argument for **every request producing an entry at the gate**, not
only every request that reaches it. A refusal upstream of the gate is
indistinguishable from an operator who never asked. Worse, the harness advised
widening permissions, and the mechanism it named (a Bash permission rule) is
not even the one that governs the MCP path, so following the advice would have
loosened the wrong control. The gate is the only component positioned to record
that a thing was asked for and declined, and today it never learns.

## 5. Local models on the same path

Measured from the session transcripts on netclaw, so treat the sample as small.
gpt-oss:120b: median 14.5 s per turn, p90 23.3 s, max 30.4 s (n=12).
qwen3.8:27b: median 42.7 s, p90 45.7 s, max 45.7 s (n=5). Roughly a threefold
difference, both usable for interactive reads and neither pleasant.

The reported roughly one-in-three failure to emit a `tool_use` block, where the
model narrates the action instead of calling the tool, is carried over from the
operator's session notes. I did not re-derive it here: the transcripts do not
distinguish "should have called a tool and did not" from "correctly answered
without one".

Claim fidelity is the more interesting failure. Reading a healthy GREEN
`show ip ospf neighbor` result (chain seq 377 to 379), qwen3.8:27b wrote:

```
both entries show Pri = 1 yet are in Full state, which is unusual — normally
point-to-point or priority-0 (passive) interfaces can't form adjacencies
```

(That quote is verbatim, em dash included; this document otherwise avoids them.)
That is wrong. Priority 1 with Full state is ordinary on a broadcast segment.
The signed observation was correct; the narration of it was not. VIRP
guarantees the bytes, and nothing in the design guarantees the sentence the
model writes about them.

## 6. What this is not

Not an integration. Agentdesktop's identity never reaches the chain. The
`session_id` comes from `SUDO_USER` on the bridge, not from the Dex token the
operator authenticated with, so the two systems currently share a host and a
day, nothing more.

Not external validation of VIRP. We wrote both sides, we chose the test cases,
and the harness was configured by us.

Not a benchmark. Latencies come from a handful of interactive turns on one
host, not from a controlled run.

Provenance: written from the two frozen input files named at the top, the
commit messages of `nhowardtli/netclaw-virp-bridge` `6451e3d4`, `31ffbd05`,
`d6ba605f`, `04575219` and `virp` `dc49b748`, and the `.211` chain ranges cited
inline. The chain dump verified body hashes and entry links structurally; it
did not check the chain HMAC, whose key it deliberately cannot read.

## 7. Follow-ups

- Identity passthrough from the Agentdesktop credential into the bridge session id; the receiver already exists.
- `SO_PEERCRED` on the daemon, so session owner is derived and signed by the daemon rather than asserted by uid 993.
- GATE 3 does not run on commitment-only bodies; any 64-hex string can be cited as an unsigned observation.
- Daemon does not drain on SIGTERM with device connections open; every stop is a 90 s timeout then SIGKILL.
- netclaw's local O-Node is 183 commits behind and needs a scheduled sync with a Nexus-safe restart window.
- Decide whether .211 fast-forwards off the `dc49b748` cherry-pick onto mainline, then deploy per the release-flow ruling.
