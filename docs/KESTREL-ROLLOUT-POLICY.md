# Kestrel rollout boundary — October 16, 2026

TLI only. nhoward-admin remains sole approver and retains super-admin rights. Kestrel has no device/login/signing credentials. The trusted transport and C node retain custody. This document describes the qualified boundary, not general infrastructure autonomy.

| Operation | Current enforcement / status |
|---|---|
| Designated Gi1/0/22 state, switchport, error counters, status | Fixed helper names and fixed command bytes; GREEN native ceiling; exact TACACS forms; v3 observation storage |
| Trunk inventory | Fixed `show interfaces trunk`; exact TACACS form; Po1/Po2 observed active, VLAN999 native |
| Gi1/0/22 fixed test description / original empty restore | External owner Duo plan, exact native proposal/approval, root grant, baseline checks and consumed-approval replay defense |
| Other interface writes, including Po1/Po2 and their members | Not exposed by helper; dedicated TACACS role only permits entering Gi1/0/22 |
| VLAN / shutdown / no shutdown | Not exposed or qualified; requires self-contained typed operation, fresh preconditions, verification and restore contract |
| Admin removal, AAA, TACACS, username, line vty, crypto, SSH, routes, boot, erase/reload/save | Not exposed; dedicated TACACS does not permit these command families. No model-side prompt can authorize them |
| Management SVI | No SVI write operation exposed. Exact SVI identity not freshly qualified in this phase; do not infer it from the management IP |
| Other platforms | Existing fixed diagnostics only; no expanded write privileges |

The legacy tap `deny_prefixes` setting is not the C execute gate. It has not been deployed as a replacement for these boundaries. Prefix blocking alone would not prove context/abbreviation-safe authorization.

## Recovery and evidence

Every dedicated helper exchange now reserves an attempt before dispatch and uses a stable root-owned recovery scope. Duplicate paths, interrupted delivery, chain append failure, invalid frames, close uncertainty and signed unknown outcomes leave the scope blocked. Only recognized signed non-dispatch refusal families release it. Trusted reconciliation archives the marker and records the reason; generating a new request ID is not recovery.

A signed apply outcome still requires a fresh verification read. No automatic recovery is allowed to invent authority for another write. The exact approved restore path remains separate.

## Open contract gaps

1. Chain inline artifact content is capped at8191 bytes. Base64 encoding a9659-byte signed full-interface-status frame exceeds this cap. The complete frame was retained locally and its signature verified; it was not truncated, re-signed or claimed appended. The broad read was removed from helper and TACACS; exact-port status is qualified. General full-output evidence requires a tested large-observation storage/export contract.
2. Correctly recognizing FRR `% Unknown command:` reveals that FRR does not implement the Cisco `show clock` watchdog probe. VM103's canary service is stopped with corrected59382bf installed and its helper STOP retained. Production C remains043e152. A separate explicit FRR probe/profile or a faithful IOS-XE lab must be qualified before broader canary rollout. Do not disable health checks or treat error text as success.
3. Helper-level unsupported-operation denials are enforced before device dispatch but are local endpoint results, not native signed gate_rejection entries. Production native gate refusals are signed. A future helper-denial attestation contract must preserve this distinction.

Private reports: /home/nhoward/audits/tli-ai-rollout-20261016/phase4-recovery/. No private keys or raw device configs belong in this repository.
