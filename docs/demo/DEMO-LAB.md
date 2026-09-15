# VIRP Demo Lab — Phase A

Status: local implementation started; NOT deployed, NOT visitor-verified.
Phase B/C must not start until Claude Code verifies the deployed Phase A
commit with a second visitor key.

## Scope and ownership

Owner: Nate. Builder: Astra. Verifier: Claude Code.
Repository: nhowardtli/virp. Branch: feat/demo-lab.
Base: feat/onode-list-sessions, cef8ace.
Authoritative field prompt: VIRP-Demo-Lab-Prompt-2026-09-15.md supplied by Nate.

No work in this phase may contact 10.0.10.211, 10.0.50.102, 10.0.0.211,
VM313, the colo switch, FortiGate, or any real fleet device. No merge,
install-prod, or restart outside the new demo VM. Stop and ask before
changing any repository template except deploy/devices.demo.template.json,
opening a route to the colo, or using a real approver/witness key.

## VM inventory — Nate supplies actual values

| Field | Required / observed |
|---|---|
| Hypervisor | pve1 (planned; not queried for this phase) |
| VM ID | 219 (planned; creation unconfirmed) |
| Name | virp-demo |
| OS | Ubuntu24.04 |
| Resources | 2vCPU /4GiB /32GiB |
| NIC1 | new vmbr9, no uplink; MAC pending |
| NIC2 | VLAN20 management; MAC and IP pending |
| Builder sudo user / SSH alias | pending |
| Guest DMI UUID | pending; record before installing anything |
| Original clab-frr-ospf topology | not found locally; offline copy needed |

The builder does not create the VM or change the hypervisor network.
No public FortiGate VIP until Phase A is verified internally; Nate owns
that later step. Inbound management must originate from an allowed VLAN20
address (or be translated upstream by Nate): a home/VLAN10 source would
conflict with the required prohibited return routes. Do not relax those
routes to make the first SSH connection work.

## Implemented locally

- WELCOME.txt contains the printed visitor command sequence.
- VIRP_SHELL_MOTD adds that file to the interactive shell intro. Missing,
  oversized, or terminal-control-bearing MOTDs refuse startup visibly.
- VIRP_SHELL_DEMO_SESSION=1 enables random per-login `demo-<uuid>` sessions.
  The demo seat records request/reply correlation as evidence_item bodies.
  Requests are recorded before execution; a refused record prevents the
  device request. Reply records contain a digest and proposal identifiers;
  they do not claim to carry the full signed observation or verify its HMAC.
  `show chain` explicitly checks the visitor's own session as well as the
  recent list, even when concurrent users move it out of the top five.
- Only devices.demo.template.json grants uid988 the additional chain_append
  action, narrowed to evidence_item. The normal shell vocabulary and
  production templates retain their original policy. The daemon remains
  the enforcement boundary; an environment variable is not authorization.
- Demo template: node ceiling YELLOW, uid988 GREEN, no visitor approval,
  apply, shutdown, or direct uid1500 socket access. Daemon uid is rendered
  from VIRP_UID. Four proposed FRR endpoints use isolated172.31.219.11–14
  and IOS-style SSH/vtysh so the exact printed `show ip route` can work.
  R5/R6 use the repository's in-process mock driver, not licensed IOS.
  Container SSH/vtysh compatibility remains to be tested on VM219.

## Decisions and missing inputs

1. Nate must provide VM219's management IP, sudo user, SSH key/alias, and
   confirm creation. Actual MACs/IPs must replace the pending inventory.
2. Literal /usr/sbin/nologin conflicts with ForceCommand: sshd invokes the
   account's shell with -c, and nologin exits before virp-shell can start.
   A restricted login wrapper which accepts only the exact forced command
   is proposed; Nate's answer is pending. Do not silently use /bin/bash.
3. Supply an offline copy/path for the existing four-router clab-frr-ospf
   topology. Do not fetch it from the excluded live O-Node.
4. Choose approved external DNS/NTP endpoints and provide offline Ubuntu,
   containerlab/Docker/FRR dependencies. Do not temporarily open general
   VM egress for package installation.

## Remaining Phase A implementation and validation

No deployment instructions below have been executed. These are acceptance
requirements, not assertions of a working installation.

- Stage the fake fleet and pin/record image digests; use FRR plus R5/R6
  mocks, with no IOS image and no production credential. Generate the
  demo FRR credential and approval private key ONLY on VM219. Enroll
  the demo approver with virp-tool; never export the private half.
- Install daemon/service using the demo template only, with approvals
  enabled and visitor seat uid988/group virp via install-virp-shell.
- Install the agreed restricted visitor login, exact sudoers grant,
  root-owned key file, ForceCommand, password/forwarding/SFTP restrictions,
  and MaxSessions8. MaxSessions limits channels per SSH connection; it
  does not impose a global eight-visitor cap.
- Apply nftables with SSH inbound and only explicitly allowed DNS/NTP
  outbound on the management interface; allow only necessary internal
  fake-fleet traffic. Add persistent prohibit routes for10.0.10.0/24,
  10.0.50.0/24 and10.0.0.0/24, including FORWARD/IPv6 escape prevention.
  Capture ip route and the kernel-refused nc test with no packet sent to
  the excluded address.
- Build reset service/timer at04:00, take a quiescent pristine snapshot,
  and reset all mutable stores (chain and WAL/SHM, approval proposals and
  other proposal state). Terminate old visitor sessions and deny new ones
  during reset so an old REPL cannot leak yesterday's in-memory proposals
  or write into the new chain. Preserve demo signing keys. Test crash and
  repeated reset behavior before enabling the timer.
- Fresh issued-key SSH login, exact WELCOME sequence, proposal never
  applied, own session visible, shell/exec/SFTP/forwarding escape refusals.
- Record nft ruleset, effective sshd Match settings, reset units, VM
  inventory, host/branch/commit and exact commands in the Phase A report.
- Claude Code independently repeats from a second issued key on that
  same commit. Phase A is not DONE before this succeeds.

## Local checks (no VM or live devices)

```sh
cd /home/nhoward/virp-demo-lab
python3 tests/test_virp_shell.py
python3 tests/test_demo_motd.py
python3 tests/test_demo_session.py
make -j2 CISCO=1 build/virp-tool build/virp-onode-prod
```

These prove local parser/record behavior and compilation only. They do not
prove container networking, forced SSH authentication, FRR command behavior,
reset isolation, or guest deployment.
