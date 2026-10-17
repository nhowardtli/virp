# Kestrel management policy — October 17, 2026

Status: owner-directed design, partially implemented; not deployed.

Owner: “remember we were going to give astrel mostly free reign to manage the network with approvals? These classifcations all need to be redone”. Follow-through authorization: “follow through and configure this as you can see what we want to do”.

This replaces the previous requirement to abandon every non-YELLOW port proposal. RED is an approval requirement, not a permanent prohibition. It does not make a missing executor supported. Nate (`nhoward-admin`) remains the sole production approver. Kestrel holds neither device credentials nor signing credentials.

## Decisions

| Class | Authority and examples |
| --- | --- |
| GREEN | Scoped routine diagnostics; automatic under a valid lease. |
| YELLOW | Typed, reversible changes on explicitly authorized targets with complete baseline, bounded rollback and machine verification. Autonomous execution requires a protected policy grant covering the exact operation and target. |
| RED | Security weakening, disruptive changes, management access, AAA/admin changes, routing/uplinks, or operations without enough contextual evidence to qualify as YELLOW. Independent operator approval binds the exact transaction. |
| Refused | Out of scope, malformed, altered or consumed approval, unresolved outcome, protected target without a specific approved scope, missing recovery capability. |

BLACK remains refused in the current implementation. Supporting an operator-approved reload or destructive operation requires a separately qualified executor and recovery workflow; do not enable BLACK passthrough to simulate it.

The native command-only classifier cannot know whether an interface is an access port, an uplink or a member of a bundle. Do not globally demote interface writes. Contextual policy must be in the trusted enforcement path and consume verified observations, not model assertions. Until that integration is qualified, newly supported port operations remain native RED and need exact approval. Config-visibility reads remain YELLOW because broader output can contain secrets.

## First implementation scope

Production target: SW-3850, 10.0.10.2, GigabitEthernet1/0/22 only.
Qualification target: isolated CML VM105, kestrel-ios Ethernet0/1. VM100 hosts other services and must not be repurposed. VM103 stays stopped.

The C driver now parses a finite set of interface operations and renders each through the existing configure-terminal / interface / single-line / end transaction. It preserves prompt draining, UNKNOWN handling, signed observations and the existing approval check. No policy ceiling was raised.

Supported grammar: canonical physical GigabitEthernet or Ethernet name plus one of:

- switchport mode access or switchport mode dynamic auto
- switchport access vlan 1..4094 or no switchport access vlan
- spanning-tree portfast or no spanning-tree portfast
- switchport port-security or no switchport port-security
- switchport port-security maximum 1..1024 or no switchport port-security maximum
- switchport port-security violation restrict/shutdown or no switchport port-security violation

These are transport capabilities, not grants. Dynamic-auto and negations exist to support exact baseline restoration; their use is still approval-gated. No trunk operations, interface ranges, SVI, port-channel, subinterfaces, shutdown/no shutdown, sticky MACs or arbitrary IOS blocks are added.

## Required trusted transaction checks before production

1. Capture full interface configuration and authenticated port facts. Check administrative shutdown, no neighbor/MAC, no channel membership and protected-set exclusion. Capture active VLAN inventory for VLAN changes.
2. Bind target, baseline bytes/hash, operation, rendered forward and restore, expected reads, and expiry into the approved transaction. Preserve absent config lines via their exact negation. Reject unsupported baseline forms rather than approximating them.
3. Obtain real owner Duo approval outside the cage. Do not reuse the description-only coordinator for arbitrary port changes.
4. Persist intent before dispatch; no automatic retry on UNKNOWN. Apply once, machine-verify, restore, machine-verify exact baseline. No save to startup-config.
5. Preserve approval consumption and replay refusal. Lease-expiry recovery must be explicitly implemented and tested; the current single-command lease is not that transaction guarantee.
6. Export native frames, chain, approvals and TACACS records with external public pins; verify offline.

## Deployment status and blocking guard

No production or canary deployment from this change. CML preflight found `/var/lib/virp-cml-phase11/STOP` present, pending absent, service active. Do not remove or route around that STOP by inventing another scope. Owner release is required before live qualification. Policy-aware helper, generalized owner coordinator and exact TACACS grants remain to be implemented and tested before activation.
