# Windows Server2025 provisioning through VIRP

Owner scope October19: configure Kestrel to create and install Windows2025 autonomously from one prompt. Qualified October 19, 2026: a fresh VM233 was installed from blank disk, configured and verified after reboot from one prompt, with no installation assistance. Final model record: `46cf21dacdb04d8b8912e3703eda93fb`, `ok: true`, `reason: verified_complete`. Independent guest/RDP checks and containment/replay tests passed. Earlier unsuccessful qualification attempts remain in the audit history.

Owner interface: `kestrel windows 'Create a Windows Server 2025 VM and verify it is ready.'`

Flow: VM227 root-controlled model runner exposes only `virp_windows`; fixed transport reaches VM211's forced-command router; isolated native VIRP daemon and requester identities sign exact `qm create 233` / `qm status 233` exchanges; source211-only hypervisor account reaches a closed root endpoint. Its create operation reserves a UUID and starts a fixed Windows installation recipe. It does not expose arbitrary qm arguments or arbitrary PowerShell.

Initial scope is reserved new VM233:4CPU,8GiB,80GiB SATA,UEFI SecureBoot,TPM2,VLAN50,10.0.50.233,Windows Server2025 Standard Evaluation Desktop Experience. No existing guest can be overwritten. Duplicate creation is refused; a repeated natural-language request can observe the existing installation. Adding additional capacity/VM slots requires protected deployment policy, not a model-selected VMID.

The endpoint uses pinned ISO hashes, creates the Administrator password outside the cage, generates transient unattended media, installs and configures the guest, removes installation credentials/media and verifies a reboot. The model polls until verified completion. No caller-provided shell, installation source, PowerShell payload, network, account or media path is accepted.

Native VIRP signs the fixed endpoint request/result, including final guest facts and journal hash. It does NOT individually execute or sign every asynchronous installation subcommand. The root endpoint journal records those exact commands and result hashes. This trust boundary is explicit; the endpoint is privileged and must remain root-controlled.

Revocation: `/var/lib/virp-kestrel-windows-scope/STOP` on211 blocks future model requests. `/var/lib/kestrel-windows/STOP` oncoloPVE1 stops the installation recipe at its next checkpoint; it does not cancel an already-dispatched command. Only administrators can clear these files. Disable `virp-kestrel-windows` and lock account `kestrel-windows` to retire the capability. Preserve ledger/state; never reset a reservation to replay uncertain work.

Credentials: `/var/lib/kestrel-windows/administrator.json` oncoloPVE1 is root-only. No credential retrieval tool exists in the cage. Engineer may escrow the completed guest credential in owner's SecretService over existing authenticated access without exposing it in model output or reports.

Limits: base OS provisioning, not full patch currency, domain/Entra join, production app readiness, broad fleet management or exhaustive cage-escape certification. Existing VM107 and switch capabilities remain separate. A failed/uncertain installation is retained for reconciliation; no destructive automatic cleanup or re-create.

Qualification corrections: Proxmox can retain empty optical slots in a disk-first boot order. Completion requires SATA first, no other boot-device classes, all optical media empty, deleted temporary answer media, and a changed Windows boot time with the same UUID. It does not require a particular order among empty optical slots. The forced SSH entry also permits exact unprivileged `uptime` for the native Linux driver's health check; no shell expansion or arbitrary uptime arguments are accepted.

Status reports the provisioning job and its timestamped verification result. It is not an ongoing guest-health monitor after the provisioning job finishes.

The owner CLI launches the model runner through existing authenticated coloPVE1 guest-agent administration of cage227, which works over the owner's VPN. This is the owner launch path, outside the model. Kestrel's managed-device operations still use its fixed cage-to-VIRP transport; no hypervisor credential or guest-agent tool is exposed to the model. The CLI returns a concise summary and cage evidence directory, and checks the typed model result instead of equating process exit0 with success.

Qualification consumed 42 model responses (205,810 provider-reported tokens, including 191,291 cached input tokens). One provision tool request produced one hypervisor create and one verification reboot. Windows boot changed from 18:06:21.500 UTC to 18:09:56.500 UTC with UUID `29c09f22-2533-4613-9a8f-fd14e7c77fad` unchanged. Failed first fixture VM232 is retained stopped; it is not the successful qualification. Owner credential escrow: SecretService service `kestrel-windows-server-2025-233`, host `10.0.50.233`, username `Administrator`.
