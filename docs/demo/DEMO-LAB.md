# VIRP Demo Lab — Phase A

Status: VM219 answers administrator SSH; demo deployment and visitor verification pending.
Phase B/C must not start until Claude Code verifies the deployed Phase A
commit with a second visitor key.

## Scope and ownership

Owner: Nate. Builder: Astra. Verifier: Claude Code.
Repository: nhowardtli/virp. Branch: feat/demo-lab.
Base: feat/onode-list-sessions, b7548fc (owner-pinned revision).
Authoritative field prompt: VIRP-Demo-Lab-Prompt-2026-09-15.md supplied by Nate.

No work in this phase may contact 10.0.10.211, 10.0.50.102, 10.0.0.211,
VM313, the colo switch, FortiGate, or any real fleet device. No merge,
install-prod, or restart outside the new demo VM. Stop and ask before
changing any repository template except deploy/devices.demo.template.json,
opening a route to the colo, or using a real approver/witness key.

## VM inventory — observed 2026-09-15

| Field | Observed |
|---|---|
| Hypervisor | pve1, 10.0.10.10 |
| VM ID / name | 219 / virp-demo |
| OS | Ubuntu 24.04 cloud image, SHA256 checked against Ubuntu manifest |
| Resources | 2 vCPU / 4 GiB / 32 GiB |
| net0 / eth0 | vmbr0, VLAN20, BC:24:11:CF:51:36, 10.0.20.219/24 |
| net1 / eth1 | vmbr9, BC:24:11:FE:AC:C4, 172.31.219.1/24 |
| Management gateway | 10.0.20.1 (owner supplied; VM110 confirms VLAN20) |
| Builder sudo user | demo-admin |
| Guest DMI UUID | c88c6f10-aafb-44ca-ba27-95a5ae95da67 |
| Offline assets | ~/virp-demo-assets/frr-ssh-10.2.1.tar.gz and frr-ospf-lab.tgz |

Nate authorized VM creation and specific PVE startup settings on 2026-09-15.
The builder created vmbr9 without ports or an address using `ifup vmbr9`,
avoiding a reload of existing bridges. VMs104/212 were already running;
no restart was needed. Onboot was set for103/104/110/211/212/219 and startup
orders for211 (1) and103 (2), exactly as authorized. No guest connections
to excluded nodes were made.

Administrator SSH works before final isolation. A management source inside
VLAN20 is needed for final SSH acceptance: prohibited home/VLAN10 return
routes must not be relaxed. An additional pve1 VLAN20 relay is awaiting
owner approval. No public FortiGate VIP is part of Phase A.

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

## Owner rulings and bootstrap findings

- Visitor uid1500 uses `/bin/sh`, with sshd ForceCommand and forwarding
  disabled. `restrict,pty` retains key restrictions while allowing the
  explicitly required terminal; `restrict` alone disables PTY allocation.
- Dependencies may be installed during bootstrap, then egress closes.
  Initial cloud-init package installation failed DNS resolution using
  10.0.20.1. A temporary public resolver was used during bootstrap only.
  Ubuntu repositories required HTTPS (HTTP returned403). The final
  firewall admits DNS/NTP only to10.0.20.1; its availability needs checking.
- Review fixes: renderer recognizes VIRP_DEMO_FRR_PASSWORD; records reject
  bodies of8191 bytes or more; reply-record errors warn after signed output;
  DEMO_ACTIONS is separate from production shell actions. Home-template
  commit06848ba is excluded from this branch.

## Remaining Phase A implementation and validation

These acceptance requirements remain open until evidence is recorded below.

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
