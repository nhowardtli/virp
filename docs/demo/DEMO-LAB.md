# VIRP Demo Lab — Phase A

Status: VM219 deployed; six devices connected; two manual resets passed.
Final network isolation and independent visitor acceptance remain open.
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
  Container SSH/vtysh compatibility is verified on VM219: all four FRR
  endpoints connect through the Cisco driver; R5/R6 connect through mock.

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

## VM deployment evidence — 2026-09-15

- containerlab0.79.0; offline image frr-ssh:10.2.1, local image ID prefix
  8e500662b906. No Docker image pull. Ring retains supplied OSPF link
  addresses (10.10.12/23/34/41), which are distinct from forbidden10.0.10/24.
  Management addresses are172.31.219.11–14. `br-demo` inside VM219 connects
  the containers and eth1 to isolated pve1 vmbr9; vmbr9 still has no host IP.
- [Containerlab bridge configuration](https://containerlab.dev/manual/network/)
  supports reusing the bridge. Masquerading and external access are disabled;
  the guest nft forward policy additionally denies external forwarding.
- Cisco SSH failure reproduced using Ubuntu libssh2 1.11.0 with custom KEX
  plus AES-CTR: handshake -43, server reported corrupted MAC. Including
  ext-info-c and kex-strict-c-v00@openssh.com succeeded. Both Cisco KEX lists
  now retain these extension markers. Cisco driver tests54/54 passed.
- Fresh demo-frr account uses /bin/sh with container sshd ForceCommand vtysh.
  Demo password and approver private key are VM-local. Root password is locked
  in the containers; newly generated host keys are pinned through Docker's
  local control interface, not through unverified network keyscan.
- Visitor `/bin/sh` exec request demonstrably enters virp-shell. The owner
  Match settings are installed in40-virp-demo.conf and effective MaxSessions
  is8. Keys have restrict,pty. UID1500 has no virp/docker/containerlab group.
- The demo seat's systemd-journal membership is removed after the standard
  installer: otherwise yesterday's command text could remain visible after
  chain reset. This is a demo-only privacy restriction.
- Daily reset files are deploy/demo/reset.py and virp-demo-reset.{service,timer}.
  Pristine state is /var/lib/virp-demo-pristine (root-only). Two hand runs
  verified its manifest, restored all /var/lib/virp state, and started onode.
  Signing/approval secrets under /etc are preserved. VM timezone is UTC;
  the timer's04:00 is UTC. New logins refuse during reset; old seats terminate.
- Evidence on the builder laptop: ~/audits/virp-demo-lab-2026-09-15/infra/.
  SSH-READY.md contains the first required checkpoint and render results.

### Reproduce source checks

```sh
python3 tests/test_demo_motd.py
python3 tests/test_demo_session.py
python3 tests/test_demo_network.py
python3 tests/test_virp_shell.py
python3 tests/test_template_uid_policy.py
bash tests/test_render_devices.sh
make CISCO=1 build/test_driver_cisco
build/test_driver_cisco
```

### Reproduce on enrolled VM219 only

```sh
cd /opt/virp
sudo bash deploy/demo/install-seat.sh
sudo install -d /usr/local/lib/virp/demo
sudo install -m0755 deploy/demo/*.py deploy/demo/*.sh /usr/local/lib/virp/demo/
sudo install -m0644 deploy/demo/*.service deploy/demo/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start virp-demo-fleet
sudo systemctl start virp-onode
sudo -u virp-shell python3 /usr/local/lib/virp/virp-shell -c 'show devices'
# Capture only once, with visitors excluded and a clean intended baseline:
# sudo python3 /usr/local/lib/virp/demo/reset.py --capture
sudo python3 /usr/local/lib/virp/demo/reset.py
sudo python3 /usr/local/lib/virp/demo/reset.py
```

Do not invoke these on any other host. Network activation, reboot persistence,
packet capture, pristine-phaseA snapshot and Claude's final second-key run
must still be recorded before declaring Phase A DONE.
