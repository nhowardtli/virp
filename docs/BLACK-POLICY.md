# Owner policy and non-overridable BLACK boundary

Status: initial implementation, source and synthetic tests only. No live policy
migration or device operation is part of this change.

Owner authorization: “I follow you, I gree lets build it that way”. The agreed
intent is autonomous routine operations, including scoped deletion and reboot,
with selectable operator profiles and a hard boundary against a compromised
agent. This document describes what this version actually enforces.

## Profiles

| Profile | Behavior within an explicit grant |
| --- | --- |
| `observe` | Reads only. Approval cannot authorize a mutation in this profile. |
| `supervised` | Reads and bounded changes run automatically. Disruptive operations require the existing independent approval flow. |
| `autonomous` | Reads, bounded changes, and disruptive operations run automatically within grants and budgets. |

The owner selects a profile per authenticated Unix peer UID. There is no socket
verb for changing it. All profiles still require an exact operation, device,
endpoint, resource, expiry, and available budget. An approval changes neither
scope nor protected resources. BLACK is a refusal, never an executable ceiling.
Legacy `black` ceiling configurations now fail startup; SHADOW cannot disable
owner policy. The deprecated `virp_exec_passthrough` ABI variable is never set
true by the daemon and no driver uses it to authorize execution.

## BLACK categories and concrete coverage

These are equal prohibitions, not increasing permission levels. An unsupported
command is refused as BLACK-13; a specific reason does not imply that VIRP has
inferred the attacker's intent.

| Category | Compromised-agent threat | Enforcement in this version |
| --- | --- | --- |
| BLACK-01 | Disable enforcement or stop the observer | No policy/daemon administration command; socket shutdown denied; owner STOP blocks new reservations. |
| BLACK-02 | Increase its own authority or enroll its own approver | Root-owned policy and approver registry; no agent administration verb; production forbids the daemon UID as an agent principal. |
| BLACK-03 | Destroy backups or recovery resources | Owner-declared protected resources override all mutation grants, including parent-host reboot. No filesystem wipe primitive. |
| BLACK-04 | Lock the owner out of management | Protected ports/hosts cannot be mutated; no AAA, credential, management ACL, or route-change primitive. Owner must identify management dependencies. |
| BLACK-05 | Destroy resources outside the assignment | Exact per-resource grants; no wildcard mutation grants or generic delete command. |
| BLACK-06 | Cause cascading outages | Global in-flight limit and lifetime disruptive budget; conflicting host/resource mutations excluded while pending. This is not a quorum or availability proof. |
| BLACK-07 | Steal secrets or export private data | Closed read vocabulary; no arbitrary file read, command expansion, network upload, packet capture, or secret export primitive. Allowed output still requires appropriate recipient access. |
| BLACK-08 | Install persistence or a backdoor | No scripts, scheduler, package install, account creation, or arbitrary shell primitive. |
| BLACK-09 | Cross containment boundaries | Exact endpoint/resource matching and explicit VLAN range; no trunk, DTP, tunnel, or security-disable primitive. |
| BLACK-10 | Forge evidence or erase the audit trail | Agent signing/chain-append/intent-execute paths disabled under policy; mandatory execution evidence and durable journal; journal failure refuses admission. Existing cryptographic verification limitations are not fixed by this change. |
| BLACK-11 | Replace trusted software or policy | No software update, file write, firmware, or policy-edit primitive. Installed binaries and dependencies must remain outside agent custody. |
| BLACK-12 | Exhaust resources or spend without bound | Persistent global call and disruptive-operation budgets; no cloud provisioning/spending primitive. No automatic budget reset. |
| BLACK-13 | Escape assigned scope, time, target, or supported grammar | Closed parser, Unix peer identity, exact grants, expiry, clock rollback checks; unknown syntax fails closed. |
| BLACK-14 | Repeat an operation after an uncertain dispatch | Reserve durably before connection/dispatch; no policy-path automatic retry; UNKNOWN blocks subsequent mutations until owner reconciliation. |

Protection applies only to paths enforced by this daemon. Agent root access,
direct device credentials, access to the daemon UID, or another unrestricted
executor bypass this boundary. Do not describe an installation as contained
until those paths are removed and verified independently.

## Initial operation catalog

Commands are normalized before both authorization and execution. Leading spaces
and tabs and repeated spaces are canonicalized. Cisco `do` is removed once.
Network CLI keywords are case-folded; description payload case is preserved.
Shell wrappers, quoting, expansion, separators, control bytes, and unknown
syntax are refused; they are not stripped into an executable fallback.

| Operation | Accepted forms | Resource | Effect |
| --- | --- | --- | --- |
| `system.read` | Network: exact `show version`, `show clock`, `show interfaces`, `show interfaces status`, `show ip route`; FortiGate also `get system status`. Linux/Proxmox: `uptime`, `hostname`, `uname -sr`. | `host` | Read |
| `host.reboot` | Cisco `reload`; ASA `reload noconfirm`; JunOS `request system reboot`; FortiGate `execute reboot`; Linux/Proxmox `reboot` or `systemctl reboot`. | `host` | Disruptive |
| `vm.read` | `qm status ID`, `pct status ID` | `vm:ID`, `ct:ID` | Read |
| `vm.reboot` | `qm reboot ID`, `pct reboot ID` | `vm:ID`, `ct:ID` | Disruptive |
| `vm.delete` | `qm destroy ID`, `pct destroy ID` | `vm:ID`, `ct:ID` | Disruptive |
| `vm.start` | `qm start ID`, `pct start ID` | `vm:ID`, `ct:ID` | Change |
| `port.description` | Cisco `interface PORT description TEXT` | `port:PORT` | Change |
| `port.vlan` | Cisco `interface PORT switchport access vlan N` | `port:PORT` | Change |
| `port.access` | Cisco `interface PORT switchport mode access` | `port:PORT` | Change |

VM forms are accepted only for Linux/Proxmox, with canonical decimal IDs >=100
and no extra options. Cisco physical ports currently accept full `Ethernet` and
`GigabitEthernet` names followed by digits/slashes; no logical interface, range,
subinterface, abbreviation, or dynamic mode. Unsupported platform commands may
fail at the driver/device; catalog membership does not prove device support or
successful application. Existing driver restrictions still apply except for an
exact, scoped `host.reboot` dispatch capability; it cannot authorize another
BLACK command.

This catalog does **not** yet provide general routing, firewall, NAT, DNS, DHCP,
cluster maintenance, firmware, or arbitrary configuration automation. Those
need typed operations and corresponding enforcement tests before admission.

## Policy format

Start with `deploy/owner-policy.example.json`, which deliberately grants nothing.
The schema is validated by `virp_policy_parse`; unknown fields and duplicate
keys are rejected. The following is a synthetic example, not a deployment grant:

```json
{
  "version": 1,
  "max_calls": 1000,
  "max_disruptive": 4,
  "max_inflight": 1,
  "principals": [{
    "uid": 1234,
    "profile": "autonomous",
    "expires": 1798761600,
    "rules": [{
      "device_id": "0000000000000011",
      "host": "192.0.2.17",
      "port": 22,
      "vendor": 7,
      "operation": "vm.delete",
      "resource": "vm:104"
    }]
  }],
  "protected": [{
    "device_id": "0000000000000011",
    "resource": "vm:105",
    "reason": "BLACK-03"
  }]
}
```

`expires` is an absolute Unix timestamp. Device IDs are 16 lowercase hex digits;
endpoint and vendor must match the daemon inventory. Vendor enum values are in
`include/virp_driver.h`. Resource comparisons are case-insensitive. `port.vlan`
rules additionally require `vlan_min` and `vlan_max` (inclusive, 1..4094).

A protected resource blocks all mutation to that resource. Protecting `host`
or `*` blocks every mutation on the device. Any protected child also blocks a
host-level disruptive operation. Reads still require an explicit grant. There
is no automatic discovery of backup dependencies, management paths, quorum,
VM identity reuse, or logical service dependencies across devices: the owner
must pin those assignments. Prefer literal IPs with independently verified SSH
host keys; hostname text equality alone does not pin DNS resolution.

Budgets are global across principals and persist across policy edits/restarts.
Reservations consume budget even if connection or execution later fails. There
is no elapsed-time reset. `max_inflight` counts pending attempts; UNKNOWN does
not prevent read-only diagnosis, but it blocks every new mutation. `done`
means dispatch uncertainty was settled, not that the application objective or
service recovery was verified. A completed reboot dispatch can precede actual
recovery, so a concurrency limit alone cannot protect cluster availability.

## Custody and migration

This is a deliberate startup compatibility break. Do not install/restart a live
daemon until its policy, journal, credentials, and protected inventory are ready.
No live assets were assigned by the source change.

1. Keep the existing dedicated daemon UID (`virp`); do not run the daemon as root
   to bypass file checks. Agents, API services, brokers, and approval signers
   must use distinct identities. In particular, older units suggesting the HTTP
   API share `virp` are incompatible with this security boundary.
2. Put the owner policy in `/etc/virp/owner-policy.json`, root-owned, mode 0644 or
   stricter but readable by the daemon. All its ancestors must be root-owned
   and not group/other writable; no symlink or hardlink aliases. An existing
   approver registry must meet the same root-custody check. Keep approval private
   keys separate from agent access.
3. Keep rendered device configuration in root/daemon custody with no writable
   group/other ancestors. The normal `/run/virp/devices.json` is supported.
   Protect credential sources, signing keys, SSH host keys, binary, unit, and
   Python/other dependencies from every agent identity.
4. Initialize `/var/lib/virp/policy.db` once using the owner tool below. It must
   be a single-link regular file, mode 0600, owned by root or the dedicated
   daemon, under root/daemon-owned non-group/other-writable ancestors. The
   production loader never creates it. Do not replace it to reset quotas.
5. Pass `-P /etc/virp/owner-policy.json -J /var/lib/virp/policy.db` together with
   the existing device and mandatory chain flags. The canonical service unit
   includes these arguments. Convert old `black` ceilings explicitly. Device
   `evidence_required: false` is overridden in production.
6. Validate on a disposable test node, then deploy separately with recovery
   access. The developer C entrypoint now requires explicit mock mode; the Go
   O-Node is demo-only, uses mode-0600 sockets, and refuses any external signing
   key path. Neither is an alternate production executor.

Owner administration, from a trusted installed copy of this checkout (never
expose this tool through agent sudo/tool access):

```sh
# OWNER ONLY; substitute the actual dedicated daemon UID.
python3 tools/policy/owner.py init --journal /var/lib/virp/policy.db --daemon-uid 986
python3 tools/policy/owner.py status --journal /var/lib/virp/policy.db
python3 tools/policy/owner.py stop --journal /var/lib/virp/policy.db \
  --evidence 'Owner incident reference and reason for stopping execution'
python3 tools/policy/owner.py profile --journal /var/lib/virp/policy.db \
  --policy /etc/virp/owner-policy.json --uid 1234 --profile supervised \
  --evidence 'Owner change reference and reason for supervised operations'
```

Profile updates apply after an owner-controlled restart. STOP prevents new
reservations; it does not cancel a dispatch already admitted. `resume` requires
an owner reason and does not reset budgets. On startup, exclusive journal
custody converts abandoned pending attempts to UNKNOWN. A second production
dispatcher cannot load the same journal concurrently.

For UNKNOWN, stop the dispatcher, independently inspect the actual target, and
record evidence with `reconcile --attempt ID --evidence 'specific evidence
reference'`. Reconciliation requires exclusive journal custody and changes only
that attempt's state. It neither repeats the command nor refunds budget. The
evidence reference is an owner attestation, not a machine-verified postcondition.
Autonomous reconciliation, service health/quorum checks, cross-node shared
budgets, and automated recovery verification are future work.

## Verification and remaining assessment findings

`make test-black-policy test-black-policy-daemon` exercises closed grammar,
normalization, exact scope, profiles, protected resources and parent-host
containment, VLAN limits, durable quotas, concurrent admissions, STOP, clock
rollback, storage failure, unknown-result quarantine, Unix peer requests,
batches, genuine approval application/replay, durable reservations across a
process crash, and refusal of signing/shutdown socket actions. The fixtures dispatch
only to a synthetic driver, never a real device.

The full C regression suite and Go tests are separate compatibility checks.
Root-custody production loading requires a provisioned disposable host; a
successful live custody/containment qualification is not claimed here. The
report CLI signature-verification findings, temporal chain checks, broker
caller authentication, and other Mythos findings are separate unresolved work.
