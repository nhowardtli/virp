# Agentdesktop + VIRP: Security Findings

Host: netclaw (Ubuntu 24.04.4, kernel 6.8). Agentdesktop 0.1.0, standalone install (no controller).
Stack: Dex OIDC (127.0.0.1:5557) + Agentgateway LLM proxy (127.0.0.1:4001) via docker compose.
Two VIRP MCP bridges registered in `~/.claude.json`: `virp-bridge-remote` and `virp-bridge-local`.
Source tree: `/home/nhoward/agentdesktop-main`. Line numbers are against that checkout.

Each finding is split into VERIFIED (observed at runtime and/or read directly in source) and
ASSUMED (inference not exercised on this host). Every source claim carries a `file:line` citation.

---

## Finding 1: MCP inventory disclosure is allowlist-limited; sensitive args and env never leave the daemon

### VERIFIED

Agentdesktop's discovery of MCP servers extracts only a fixed allowlist of fields and drops
everything else, including the command arguments and environment that carry the VIRP secrets.

- `crates/agent/src/discovery/claude_code.rs:107-140` (`mcp_servers_from_value`): the parser reads
  only `command`, `url`, `transport` (from `type`), `enabled` (from `disabled`), `name`, and
  `source`. It never reads `args`, `env`, or `headers`.
- `crates/agent/src/discovery/claude_code.rs:42-52` (`discover_mcp_servers`): the source of the data
  is `managed-mcp.json` plus each home `~/.claude.json`. So the raw entries it parses DO contain the
  sensitive `args`/`env`, but the parser discards them at extraction time.
- `crates/core/src/model.rs:43-60` (`McpServer`): the model has no field for arguments or
  environment. Inline comments state the omission is deliberate: "Arguments and environment are
  intentionally omitted" (~line 50) and "Headers are intentionally omitted" (~line 53).
- `crates/agent/src/api.rs:178-180` (`discover` handler): returns `state.discovery`, a snapshot
  built from the allowlisted model above. What a discovery client can see is bounded by that model.

Concretely, the raw `~/.claude.json` entries that Agentdesktop reads include:
- `virp-bridge-remote`: `sudo -n -u virp-bridge env VIRP_ONODE_SOCKET=/run/virp-remote/onode.sock
  VIRP_OBS_VERSION=1 python3 -u /usr/local/lib/virp/virp-bridge-mcp.py`
- `virp-bridge-local`: `sudo -n -u virp-bridge python3 -u /usr/local/lib/virp/virp-bridge-mcp.py`

The `VIRP_ONODE_SOCKET` path, the `-u virp-bridge` privilege-drop identity, and the python bridge
path all live in `args`/`env`. Because the parser is an allowlist that stops at `command`, none of
these reach the discovery snapshot. Only the bare `command` value (`sudo`) survives.

This is an allowlist (name the fields you keep), not a denylist (name the fields you strip). An
allowlist fails closed: a future field carrying a secret is dropped by default rather than leaked by
omission. That is the safer design and it is the one in use.

### ASSUMED

- The exact JSON a live discovery client receives was not dumped in this run (the discovery endpoint
  requires the daemon socket and a client call). The conclusion rests on the source path above, which
  is deterministic: the model has nowhere to put args/env, so they cannot appear regardless of input.

### Net

Discovery does NOT leak `VIRP_ONODE_SOCKET`, the `-u virp-bridge` identity, or the python bridge
path. The mechanism is a field allowlist in `mcp_servers_from_value`, backed by a model
(`McpServer`) that structurally cannot carry arguments, environment, or headers.

---

## Finding 2: The sandbox block governs Claude Code's Bash tool only; MCP servers run outside it

### VERIFIED

The `sandbox` block Agentdesktop reconciles into `~/.claude/settings.json` is Claude Code's
command-sandbox configuration. It wraps Bash tool invocations. It does not wrap, gate, or reference
MCP servers, so the VIRP bridges execute outside the sandbox entirely.

Source:
- `crates/agent/src/reconcile/claude_code.rs:166-215` (`managed_settings`): builds a
  `json!({"sandbox": {"enabled": true, "failIfUnavailable": true,
  "allowUnsandboxedCommands": false, "filesystem": {"allowWrite": writable, "denyRead": denied,
  "denyWrite": denied}, "network": {"allowedDomains": allowed_domains}}})` and deep-merges it into
  settings. Nothing in this object references `mcpServers`; the reconciler never modifies the MCP
  server list.
- `crates/core/src/config.rs:27` and `:39-46`: `sandbox` is a root `DaemonConfig` field
  (`Option<SandboxConfig>`); `SandboxConfig` is camelCase with `deny_unknown_fields`. Its only
  children are `filesystem` (`:66` writable, `:69` denied) and `network` (`:56` allowed_domains).
  There is no MCP-related key anywhere in the sandbox schema.

Runtime behavior on this host, with the sandbox block active in settings:
- The GREEN read path through the MCP bridge continued to work with the sandbox enabled. MCP calls
  are not bwrap-wrapped; they run as their own `sudo -u virp-bridge` process tree, unaffected by the
  Claude Code sandbox settings.
- All Bash tool commands are wrapped by `bwrap` (bubblewrap) + `socat`. On this host that wrapper
  cannot initialize (see host-limitation note below), which is itself the proof that Bash goes
  through the sandbox and MCP does not: the MCP read succeeded while Bash sandbox init failed.

Host limitation (documented, not worked around):
- `bwrap --unshare-net` fails with `loopback: Failed RTM_NEWADDR: Operation not permitted`. Root
  cause is `kernel.apparmor_restrict_unprivileged_userns=1` on Ubuntu 24.04. A raw
  `bwrap --unshare-net --dev-bind / / true` reproduces the identical failure with no Claude Code
  involved. This kernel hardening was left in place (changing it is out of scope). Because of it,
  the two filesystem/network sandbox assertions below could not be exercised end to end.

### ASSUMED (could not be exercised on this host)

- That `ls /var/lib/virp-remote` is denied to the Bash tool by the `filesystem.denied` entry. The
  path is present in the reconciled deny list, and `denyRead` maps it into the sandbox object
  (`reconcile/claude_code.rs:166-215`), but the deny could not be observed because the sandbox
  wrapper will not start on this host.
- That `curl 127.0.0.1:4001` is or is not reachable from inside the sandbox under
  `network.allowedDomains: ["api.anthropic.com"]`. Same reason: the network namespace never
  initializes, so reachability from inside the sandbox is unobservable here.

Both ASSUMED items concern only what the sandbox does to the Bash tool. Neither affects the VERIFIED
conclusion, because that conclusion is that MCP is outside the sandbox regardless of these settings.

### Net

The sandbox applies to Bash, not to MCP. VIRP bridges are reached over the MCP transport, which the
reconciler never sandboxes and never references. Tightening `sandbox.filesystem.denied` or
`sandbox.network.allowedDomains` constrains what shell commands can touch; it does nothing to the
VIRP bridge processes. VIRP's own trust-tier gate, not the Agentdesktop sandbox, is what governs
device access through the bridges.

---

## Finding 3: Telemetry hooks require a controller; standalone cannot emit them

### VERIFIED

Agentdesktop only writes the Claude Code `PreToolUse` / `SessionStart` hooks when the daemon's
telemetry config asks for those events, AND those events have nowhere to go unless a controller is
configured. In this standalone install there is no controller, so telemetry hooks cannot deliver
anything.

Hook construction is gated on telemetry event selection:
- `crates/agent/src/reconcile/mod.rs:243-246`: `tool_use_hook =
  telemetry.collects_tool_use().then(|| claude_hook_command(...))`.
- `crates/agent/src/reconcile/mod.rs:247-250`: `session_new_hook =
  telemetry.collects_session_new().then(|| claude_session_hook_command())`.
- `crates/agent/src/reconcile/mod.rs:328-338` (`claude_hook_command`): the hook runs
  `agentdesktop --socket <sock> hook claude-pre-tool-use [--include-input]`.
- `crates/agent/src/reconcile/mod.rs:341-351` (`claude_session_hook_command`): the hook runs
  `agentdesktop --socket <sock> hook claude-session-start`.
- `crates/core/src/config.rs:131-154` (`TelemetryConfig`): `collects_tool_use`,
  `includes_tool_input`, and `collects_session_new` are true only when the corresponding
  `TelemetryEventName` (`tool.use`, `tool.use.input`, `session.new`, `:159+`) is present in the
  configured `events` set. The standalone `config.yaml` sets no `telemetry.events`, so all three are
  false and NO hooks are written.

Even if telemetry events were configured, the emitted hook posts to the daemon, and the daemon has
no telemetry sink without a controller:
- `crates/agent/src/daemon.rs:334`: `let (telemetry_sender, telemetry_receiver) = mpsc::channel(256);`
- `crates/agent/src/daemon.rs:335`: `let telemetry = config.controller.as_ref().map(|_|
  telemetry_sender.clone());` so the AppState telemetry sender is `Some` ONLY when a controller is
  configured; otherwise it is `None`.
- `crates/agent/src/daemon.rs:338-359`: the `telemetry_receiver` is consumed exclusively inside
  `if let Some(controller) = config.controller.clone()`, where it is passed to `remote::run(...)` at
  `:352`. With no controller, the receiver is never read; there is no file, stdout, or local socket
  sink.
- `crates/agent/src/remote.rs:413` (`telemetry_to_proto`): telemetry events are converted to
  protobuf only to be shipped over the controller (gRPC) integration. That is the sole consumer.
- `crates/agent/src/api.rs:56-76` (telemetry handler): the endpoint does
  `state.telemetry.as_ref().ok_or_else(|| (StatusCode::FAILED_DEPENDENCY, "daemon has no controller
  configured"))?`. Without a controller a hook's POST to `/v1/telemetry` is rejected 424
  FAILED_DEPENDENCY and the event is dropped.

### Per the prompt: they require a controller, so stopping here

No hook event was enabled or fabricated. In standalone mode (`config.yaml` has no `controller`
section) there is no configuration that makes the daemon emit or persist a PreToolUse/SessionStart
telemetry event: the hooks are not written (no events configured), and even if forced, the events
would 424 at `/v1/telemetry` because the telemetry sender is `None` without a controller. Enabling
real telemetry requires enrolling the daemon against a controller endpoint, which is out of scope
for this standalone evaluation.

### ASSUMED

- That with a controller configured and `telemetry.events` populated, hooks would be written and
  events would flow to the controller over gRPC. This is the straight reading of the source above
  but was not exercised (no controller available).

---

## Prompt 4 observations (recorded as requested)

These are behavioral observations from the VIRP bridge runs, kept here for the record.

1. Empty session id on remote entries. Executed entries returned by `virp-bridge-remote` carry a
   session identifier of the form `ncfed-unknown-unknown` with an empty session component. The remote
   trust domain is populating the tenant/site prefix but leaving the session portion unresolved, so
   the signed-chain entry is attributable to the federation but not to a specific session.

2. Withheld outcome on the local not-found request. A request against `virp-bridge-local` for a
   device that is not in the local inventory returned a withheld outcome rather than an executed or
   explicitly rejected one. The local bridge declines to act (and declines to classify) when the
   target is not present in `/run/virp/devices.json`, so there is no signed execution and no signed
   rejection for an unknown target, only a withhold.

---

## Pre-step result: the local trust domain cannot produce a GREEN/executed entry by design

Before Finding 1 the task was to run a GREEN read against a real device in `virp-bridge-local`'s
inventory so the local trust domain would hold a genuine executed entry.

Local inventory (`/run/virp/devices.json`, read via `sudo`): `gate_default_mode: enforce`,
`gate_max_tier: yellow`; devices `netclaw-edge1` (fd00:dc:12::1), `netclaw-core` (fd00:dc:12::2),
`netclaw-edge2` (fd00:dc:23::3); all `vendor: linux`, ssh `netops`/`netops123`. The inventory
`_comment` states this governs the NetClaw FRR testbed only and that no `approvers.json` exists on
this host by design, so RED terminates in a signed rejection that nothing here can approve.

Result: every command tried against `netclaw-edge1` (`ip -6 addr show`, `uptime`, `show version`)
classified as RED and was refused, because `gate_max_tier` is YELLOW and a general Linux shell
command is treated as RED (fail-closed). No GREEN/executed entry was produced, and none was faked.
Unlike an FRR `vtysh` "show" (which can classify GREEN as a read-only network query), a general
Linux shell target has no GREEN read path under this gate configuration. The local trust domain
therefore cannot, by design on this host, produce a GREEN/executed inventory entry.

---

## Finding 4: agentgateway's management listeners bind all interfaces; the example hides this behind Docker port publishing

### VERIFIED

Correction to the premise as filed: only two of the three default to all-interfaces. `admin`
defaults to loopback. On first recreate under `network_mode: host`, the gateway logged:

```
listener established  address=[::]:15021       component="readiness"
listener established  address=127.0.0.1:15000  component="admin"
listener established  address=[::1]:15000      component="admin"
listener established  address=[::]:15020       component="stats"
started bind          bind="bind/4001"
```

`ss -tlnp` agreed: `*:15021`, `*:15020`, `*:4001` wildcard; `127.0.0.1:15000` loopback. So the
exposure is `stats` (15020, metrics) and `readiness` (15021), plus the data plane on 4001. The
admin UI, which `app` advertises at `http://localhost:15000/ui`, was already loopback-bound.

The stock example never reveals this because the gateway runs on a bridge network and publishes a
single port (`ports: 127.0.0.1:4001:4001`). Docker publishes only what is listed, so 15000/15020/
15021 stay inside the container's netns and are unreachable regardless of what they bind. The
safety comes from the port list, not from agentgateway's defaults.

The data-plane listener cannot be pinned. In `schema/config.json`, `LocalGateway` exposes only
`port`, and `LocalGatewayListener.hostname` is HTTP Host matching ("Hostname defines what hostnames
are served under this listener"), not a bind address. The management listeners can be pinned:
`RawConfig` carries `adminAddr`, `statsAddr` and `readinessAddr`, each documented as
`"ip:port", "localhost:port", "unix:/path/to/socket", or "off"`.

Pinning them under the top-level `config` block moved all three to loopback:

```
listener established  address=127.0.0.1:15021  component="readiness"
listener established  address=127.0.0.1:15000  component="admin"
listener established  address=127.0.0.1:15020  component="stats"
```

Off-box probes from 10.0.0.15 and from the operator workstation: 15000/15020/15021 all refused
(`curl exit 7`), 4001 dropped by the nftables backstop (`curl exit 124`, timeout), while
`127.0.0.1:4001` on netclaw still answered `HTTP 401` (JWT strict, no token).

Note the loopback test trap: `curl http://10.0.30.30:4001/` run *on* netclaw returns `HTTP 401`,
not a drop, because traffic to a local address traverses `lo` and so does not match
`iif != "lo"`. The guard must be tested from a different host or the result is a false negative.

### ASSUMED

- That 15000/15020/15021 are the complete set of management listeners. They are the three named in
  `RawConfig` and the three observed at startup; a listener that only appears under some other
  feature flag would not have shown up here.
- Reboot persistence of the nftables guard unit. It is `enabled` for `multi-user.target` and
  `After=docker.service`, but only its running state was verified, not its boot path.

### Net

Any deployment that gives agentgateway the host network namespace, or otherwise stops relying on
Docker's port list, inherits two all-interface management listeners. On a host with no firewall
(netclaw: `ufw inactive`, `iptables -P INPUT ACCEPT`) that is immediate LAN exposure of the metrics
endpoint. `adminAddr`/`statsAddr`/`readinessAddr` are the fix; an interface filter is only a
backstop, and is unavoidable for 4001 alone.

---

## Finding 5: `--user` scopes reconcile but not discovery; discovery walks every home on the host

### VERIFIED

The daemon, started as `nhoward` with `--user`, reported a binary in another user's home:

```
discovered program kind=claude-code executable=/home/claudecode/.local/bin/claude
                   version="2.1.222" mcps=2 skills=0
```

nhoward's own Claude Code is `/home/nhoward/.npm-global/bin/claude` at 2.1.259. The versions
confirm the selection: `/home/claudecode/.local/bin/claude --version` returns exactly 2.1.222.

From source, the path is three hops:

1. `discover()` calls `metadata::find_executable("claude", executable_candidates())`
   (`discovery/claude_code.rs:13`).
2. `find_executable` tries `find_in_path(name)` first, and only on `None` falls back to
   `additional_candidates.into_iter().find(|candidate| candidate.is_file())`
   (`discovery/metadata.rs:16-25`). It takes the **first existing** candidate, not the best one.
3. `executable_candidates()` collects into a `BTreeSet<PathBuf>`, inserting both
   `home.join(".local/bin/claude")` and `home.join(".npm-global/bin/claude")` for **every** home
   returned by `user_home_dirs()` (`discovery/claude_code.rs:23-40`). A `BTreeSet` iterates in
   lexicographic path order.

`user_home_dirs()` (`discovery/metadata.rs:189-232`) is the reason "every home" is literal. It
unions three sources: the invoking user's `home_dir()`; every field-6 path in `/etc/passwd` that
`is_dir()`; and on Linux every directory entry under `/home`. Nothing consults the `--user` flag.

On netclaw that resolves deterministically. `claude` is not on the daemon's `PATH`
(`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin`),
so step 2's `find_in_path` returns `None`. `/home` holds `claudecode`, `nexus`, `nhoward`, giving
six candidates, of which two exist:

```
/home/claudecode/.local/bin/claude       <- first in lexicographic order, selected
/home/nhoward/.npm-global/bin/claude
```

`claudecode` sorts before `nhoward`, so the other user's binary wins. Within a single home
`.local/bin` also sorts before `.npm-global/bin`, so an unused `~/.local/bin/claude` would shadow
the real install even without a second user.

The same host-wide enumeration drives the rest of discovery. `discover_mcp_servers()` reads
`home.join(".claude.json")` for every home (`discovery/claude_code.rs:48-51`), and `skill_roots()`
adds every home's `.claude/skills` plus every path in that home's `installed_plugins.json`
(`:59-64`). Here the reported `mcps=2` came from nhoward's own file (`virp-bridge-remote`,
`virp-bridge-local`); `/home/claudecode/.claude.json` exists but is mode-restricted, so
`fs::read` failed and `mcp_servers_from_json` returned an empty vec (`:98-100`). Cross-user MCP
disclosure was prevented by file permissions, not by any scoping in the code.

Reconcile, by contrast, is correctly user-scoped. The same run logged
`merged user settings program="claude-code" path=/home/nhoward/.claude/settings.json`.

### ASSUMED

- That the daemon would have read `/home/claudecode/.claude.json` had the mode allowed it. The
  code path is unconditional, but it was never exercised successfully, only observed failing.
- Behaviour when the daemon runs as root, where `/etc/passwd` homes and other users' dotfiles are
  all readable. Not tested.

### Net

`--user` is a reconcile scope, not a discovery scope. The snapshot describes the host, while the
settings write targets the invoking user, so the daemon can report on and manage two different
Claude Code installations in the same run. On a multi-user box the version, MCP list and skill
inventory in the snapshot may belong to a user other than the one whose `settings.json` was
edited. Putting a `claude` on the invoking user's `PATH` makes step 2 short-circuit and is the
least invasive way to make discovery agree with reconcile.

---

## Summary: verified vs assumed

VERIFIED
- Discovery uses a field allowlist; VIRP socket, `-u virp-bridge` identity, and python path are
  dropped and cannot reach the discovery snapshot (`discovery/claude_code.rs:107-140`,
  `core/src/model.rs:43-60`, `api.rs:178-180`).
- The reconciled `sandbox` block is Claude Code's Bash command sandbox; it never references
  `mcpServers`, so VIRP bridges run outside it (`reconcile/claude_code.rs:166-215`,
  `core/src/config.rs:27,39-46`).
- MCP GREEN read worked with the sandbox enabled; Bash goes through bwrap, MCP does not.
- Telemetry hooks are written only when telemetry events are configured, and events have no sink
  without a controller; `/v1/telemetry` returns 424 FAILED_DEPENDENCY otherwise
  (`reconcile/mod.rs:243-250,328-351`, `core/src/config.rs:131-154`, `daemon.rs:334-359`,
  `api.rs:56-76`, `remote.rs:413`).
- Local trust domain cannot produce a GREEN/executed entry: all shell commands classify RED under
  `gate_max_tier: yellow`.
- Prompt 4: remote executed entries carry an empty session id (`ncfed-unknown-unknown`); local
  not-found request returns a withheld outcome.
- agentgateway `stats`/`readiness` default to all-interfaces (`[::]:15020`, `[::]:15021`);
  `admin` defaults to loopback. The example hides this by publishing only 4001 from a bridge
  network. Pinned via `config.adminAddr/statsAddr/readinessAddr`; 4001 has no bind option
  (`schema/config.json`: `LocalGateway` has `port` only).
- `--user` scopes reconcile but not discovery: `user_home_dirs()` unions `home_dir()`,
  `/etc/passwd` field 6, and every directory under `/home`, then `find_executable` takes the
  first `is_file()` hit in `BTreeSet` (lexicographic) order
  (`discovery/claude_code.rs:13,23-40,48-64`, `discovery/metadata.rs:16-25,189-232`).
  On netclaw that selected `/home/claudecode/.local/bin/claude` (2.1.222) over nhoward's
  `.npm-global` install (2.1.259), while reconcile still wrote `/home/nhoward/.claude/settings.json`.

ASSUMED (not exercised on this host)
- Exact discovery JSON a live client receives (endpoint not called; conclusion is structural).
- Sandbox denial of `ls /var/lib/virp-remote` and reachability of `curl 127.0.0.1:4001` from inside
  the sandbox (bwrap will not initialize under `apparmor_restrict_unprivileged_userns=1`).
- Controller-attached telemetry flow (no controller available to enroll against).
- That 15000/15020/15021 are the complete set of agentgateway management listeners, and that the
  nftables guard survives reboot (running state verified, boot path not).
- That discovery would have read `/home/claudecode/.claude.json` with a permissive mode; the read
  was only observed failing. Daemon-as-root behaviour untested.
