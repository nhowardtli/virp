```
VIRP                                                        N. Howard
Internet-Draft                                       Third Level IT LLC
Category: Experimental                                    March 11, 2026
Expires: September 11, 2026


        Verified Infrastructure Response Protocol (VIRP) Specification
                        draft-howard-virp-03

Abstract

   This document specifies the Verified Infrastructure Response Protocol (VIRP),
   a cryptographic trust framework for AI-managed network infrastructure.
   VIRP provides structural guarantees that observations of network
   state are authentic and that proposed changes are authorized, through
   channel-separated key binding and tiered approval enforcement.

   VIRP addresses the emerging threat of AI fabrication in network
   automation, where language model-based systems generate plausible
   but false device output, configuration state, or security findings.
   The protocol makes fabrication structurally impossible by requiring
   cryptographic proof of observation at the point of collection.

Status of This Memo

   This Internet-Draft is submitted to the community for review and
   comment. Distribution of this memo is unlimited.

   This document is published under the Apache License 2.0. The
   reference implementation is available at:
   https://github.com/nhowardtli/virp

Copyright Notice

   Copyright (c) 2026 Third Level IT LLC. All rights reserved.
   Licensed under Apache License 2.0.


Table of Contents

   1.  Introduction ................................................  2
   2.  Terminology .................................................  3
   3.  Protocol Overview ...........................................  4
   4.  Channel Architecture ........................................  5
   5.  Key Management ..............................................  7
   6.  Trust Tier System ........................................... 10
   7.  Message Format .............................................. 12
   8.  Message Types ............................................... 15
   9.  Observation Sub-Header ...................................... 20
  10.  HMAC Construction ........................................... 21
  11.  O-Node Operation ............................................ 23
  12.  R-Node Operation ............................................ 25
  13.  Socket Protocol ............................................. 26
  14.  REST API Binding ............................................ 28
  15.  Device Driver Interface ..................................... 30
  16.  Observation Freshness and Expiry ............................ 32
  17.  Multi-Node Coordination ..................................... 34
  18.  Protocol Versioning ......................................... 36
  19.  Threat Model ................................................ 38
  20.  Security Considerations ..................................... 42
  21.  Formal Security Properties .................................. 46
  22.  Conformance Requirements .................................... 48
  23.  IANA Considerations ......................................... 50
  24.  References .................................................. 52
  25.  Appendix A: Test Vectors .................................... 53
  26.  Appendix B: Comparison with Existing Protocols .............. 55
  27.  Appendix C: Future Extensions (Ed25519) ..................... 56
  28.  Session Establishment ........................................ 58
  29.  Per-Session Key Derivation ..................................... 60
  30.  Wire Format v2 — Context Binding ............................... 62
  31.  Author's Address .............................................. 64


1.  Introduction

1.1.  Motivation

   The introduction of AI reasoning systems into network infrastructure
   management creates a novel threat class: AI fabrication. Unlike
   traditional attack vectors (unauthorized access, man-in-the-middle,
   denial of service), AI fabrication occurs when a trusted automation
   system generates synthetic device output that is internally
   consistent and technically plausible but does not correspond to
   actual device state.

   During development of the TLI AI Operations Center, the following
   fabrication events were observed in production:

   (a) An AI system generated three complete firewall policies with
       syntactically valid UUIDs, correct vendor syntax, and proper
       structural formatting. None of these policies existed on any
       managed device. The AI labeled this output "Confidence: HIGH."

   (b) An AI system reported security alerts originating from IP
       addresses in the 192.0.2.0/24 and 198.51.100.0/24 ranges
       (RFC 5737 documentation addresses). These addresses do not
       exist on the production network. The AI presented these as
       active threats requiring immediate remediation.

   (c) An AI system proposed BGP route changes referencing OSPF
       adjacency states that did not match any observed device output.
       The supporting evidence was fabricated.

   Existing mitigations (prompt engineering, output validation, HMAC
   signing of executor output) proved insufficient. In case (a), the
   AI bypassed HMAC verification by generating fabricated output
   directly in its response text, never invoking the signed execution
   path. The HMAC protected the channel but not the consumer.

   VIRP addresses this by making the AI a protocol participant with
   structural constraints, rather than a trusted black box with
   advisory guardrails.

1.2.  Design Principles

   VIRP is built on four principles:

   (a) OBSERVATION PRIMACY: All reasoning about network state MUST
       be grounded in cryptographically signed observations. Unsigned
       assertions about device state carry no protocol weight.

   (b) CHANNEL SEPARATION: The path for collecting facts (Observation
       Channel) and the path for proposing changes (Intent Channel)
       are cryptographically isolated. Keys are bound to their
       channel at the code level.

   (c) STRUCTURAL ENFORCEMENT: Security properties are enforced by
       code, not policy. BLACK tier operations do not have a "deny"
       handler — they do not exist in the wire format.

   (d) MINIMUM VIABLE TRUST: The verification path contains no AI,
       no inference, no probabilistic computation. Signing and
       verification are deterministic operations on fixed-size
       buffers using HMAC-SHA256.

1.3.  Scope

   VIRP is designed for AI-managed network infrastructure but is
   applicable to any system where automated decision-makers consume
   observations of physical or logical state. The protocol is
   transport-agnostic; this specification defines Unix domain socket
   and REST API bindings. TCP transport with TLS 1.3 is planned for
   peer-to-peer operation.

1.4.  Applicability Beyond Networking

   While this specification uses network infrastructure examples
   throughout, the VIRP architecture applies to any domain where
   AI agents consume telemetry and propose actions:

   (a) SECURITY OPERATIONS: SIEM and SOAR platforms where AI
       assistants analyze logs and propose incident responses.
       Signed log origin prevents fabricated attack traces.

   (b) COMPLIANCE AND AUDIT: Frameworks such as CMMC, SOC 2, and
       FedRAMP require evidence integrity. Signed telemetry
       provides cryptographically verifiable audit trails.

   (c) CLOUD INFRASTRUCTURE: AI agents managing AWS, Azure, or GCP
       resources. Signed API observations prevent fabricated
       resource state reports.

   (d) AUTONOMOUS SYSTEMS: Any future system where AI performs
       planning, reasoning, and remediation over physical or logical
       infrastructure requires machine-verifiable truth about the
       current state of that infrastructure.


2.  Terminology

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in
   this document are to be interpreted as described in RFC 2119.

   O-Node: Observation Node. A process that connects to network
       devices, collects output, and signs observations. The O-Node
       holds an O-Key and operates exclusively on the Observation
       Channel for signing purposes.

   R-Node: Reasoning Node. A process that consumes signed observations
       and proposes changes. Typically an AI/LLM-based system. The
       R-Node holds an R-Key and operates exclusively on the Intent
       Channel for signing purposes.

   O-Key: Observation Key. A 256-bit symmetric key used for HMAC-SHA256
       signing of Observation Channel messages. An O-Key MUST NOT be
       used to sign Intent Channel messages.

   R-Key: Reasoning Key. A 256-bit symmetric key used for HMAC-SHA256
       signing of Intent Channel messages. An R-Key MUST NOT be used
       to sign Observation Channel messages.

   Observation: A signed record of device output collected by an O-Node.
       Contains the raw command output, a timestamp, sequence number,
       and HMAC-SHA256 signature.

   Proposal: A signed request for network state change, generated by
       an R-Node. MUST reference one or more supporting Observations.

   Approval: A signed authorization for a Proposal, generated by a
       human operator or automated approval system meeting the tier
       requirements.

   Trust Tier: A classification of operations by risk level (GREEN,
       YELLOW, RED, BLACK) that determines the approval requirements
       before execution.

   Channel: One of two cryptographically isolated communication paths.
       The Observation Channel (OC) carries signed facts. The Intent
       Channel (IC) carries signed proposals and approvals.

   Wire Format: The binary serialization of VIRP messages as
       transmitted between nodes.

   Freshness Window: The maximum age of an observation (measured from
       its timestamp) before it is considered stale and unsuitable
       for use as evidence in proposals.

   Observation TTL: Time-to-live value indicating the maximum duration
       an observation may be cached and served as current.

   Conformant Implementation: An implementation that satisfies all
       MUST-level requirements in this specification and passes the
       conformance test suite defined in Section 22.


3.  Protocol Overview

3.1.  Architecture

   A VIRP deployment consists of one or more O-Nodes, one or more
   R-Nodes, and the managed devices they observe and control.

       ┌──────────────────────────────────────────┐
       │            Managed Device                  │
       │  (Router, Firewall, Switch, Server)        │
       └────────────────┬─────────────────────────┘
                        │ SSH / API / SNMP
                        ▼
       ┌──────────────────────────────────────────┐
       │              O-Node                        │
       │                                            │
       │  Collects device output                    │
       │  Signs with O-Key (HMAC-SHA256)            │
       │  Serves signed observations via socket     │
       │                                            │
       │  O-Key is NEVER accessible to R-Node       │
       └────────────────┬─────────────────────────┘
                        │ Signed VIRP Messages
                        ▼
       ┌──────────────────────────────────────────┐
       │              R-Node                        │
       │                                            │
       │  Consumes signed observations              │
       │  Reasons about network state               │
       │  Proposes changes (signed with R-Key)      │
       │  CANNOT forge observations                 │
       └──────────────────────────────────────────┘

3.2.  Message Flow

   A typical observation flow proceeds as follows:

   1. R-Node sends an EXECUTE request to O-Node via socket
   2. O-Node authenticates to the target device via SSH/API
   3. O-Node executes the requested command
   4. O-Node constructs an OBSERVATION message containing:
      - The raw device output as payload
      - Current timestamp (nanosecond precision)
      - Monotonically increasing sequence number
      - Source node identifier
   5. O-Node computes HMAC-SHA256 over the message
   6. O-Node returns the signed message to the requestor

   A typical intent flow proceeds as follows:

   1. R-Node constructs a PROPOSAL referencing signed observations
   2. R-Node signs the PROPOSAL with its R-Key
   3. PROPOSAL is presented to human operators for approval
   4. Operators generate APPROVAL messages (signed)
   5. Upon sufficient approvals (per tier), execution proceeds
   6. O-Node collects post-change observations for verification


4.  Channel Architecture

4.1.  Observation Channel (OC)

   The Observation Channel carries messages representing measured
   network state. All OC messages are signed with O-Keys.

   The following message types are valid on the Observation Channel:

       Type              Code    Direction
       ─────────────────────────────────────
       OBSERVATION       0x01    O-Node → Consumer
       HELLO             0x02    Bidirectional
       HEARTBEAT         0x30    O-Node → Consumer
       TEARDOWN          0xF0    Bidirectional

   An attempt to sign an Intent Channel message type (PROPOSAL,
   APPROVAL, INTENT_ADVERTISE, INTENT_WITHDRAW) with an O-Key
   MUST return VIRP_ERR_CHANNEL_VIOLATION (error code 0x0003)
   without computing the HMAC.

4.2.  Intent Channel (IC)

   The Intent Channel carries messages representing proposed or
   authorized changes to network state. All IC messages are signed
   with R-Keys.

   The following message types are valid on the Intent Channel:

       Type              Code    Direction
       ─────────────────────────────────────
       PROPOSAL          0x10    R-Node → Approver
       APPROVAL          0x11    Approver → Executor
       INTENT_ADVERTISE  0x20    R-Node → Peers
       INTENT_WITHDRAW   0x21    R-Node → Peers
       HELLO             0x02    Bidirectional
       HEARTBEAT         0x30    Bidirectional
       TEARDOWN          0xF0    Bidirectional

   An attempt to sign an Observation Channel message type
   (OBSERVATION) with an R-Key MUST return
   VIRP_ERR_CHANNEL_VIOLATION (error code 0x0003) without
   computing the HMAC.

4.3.  Channel-Key Binding

   Channel-key binding is the core security property of VIRP. The
   binding is enforced at the function level in the signing
   implementation:

       virp_error_t virp_message_sign(
           virp_message_t *msg,
           const virp_key_t *key
       ) {
           // Channel-key binding check BEFORE HMAC computation
           if (key->channel == VIRP_CHANNEL_OC) {
               if (msg->header.type == VIRP_TYPE_PROPOSAL ||
                   msg->header.type == VIRP_TYPE_APPROVAL ||
                   msg->header.type == VIRP_TYPE_INTENT_ADV ||
                   msg->header.type == VIRP_TYPE_INTENT_WD) {
                   return VIRP_ERR_CHANNEL_VIOLATION;
               }
           }
           if (key->channel == VIRP_CHANNEL_IC) {
               if (msg->header.type == VIRP_TYPE_OBSERVATION) {
                   return VIRP_ERR_CHANNEL_VIOLATION;
               }
           }
           // HMAC computation proceeds only after binding check
           ...
       }

   This is not a policy decision. It is a code path. The HMAC
   function is never reached for cross-channel signing attempts.


5.  Key Management

5.1.  Key Structure

   A VIRP key is a 256-bit (32-byte) symmetric key with associated
   metadata:

       struct virp_key_t {
           uint8_t     material[32];   // 256-bit key
           uint8_t     channel;        // VIRP_CHANNEL_OC or _IC
           uint32_t    node_id;        // Owning node identifier
           uint8_t     fingerprint[32]; // SHA-256 of material
       };

   Key material MUST be generated from a cryptographically secure
   random number generator (e.g., /dev/urandom, OpenSSL RAND_bytes).

5.2.  Key File Format

   Keys are stored as raw 32-byte binary files with no header,
   no encoding, and no metadata. The file contains exactly 32 bytes
   of key material.

       Offset  Length  Field
       ──────────────────────────
       0       32      Key material (raw bytes)

   File permissions MUST be set to 0600 (owner read/write only).
   The channel association and node ID are maintained by the
   application, not stored in the key file.

5.3.  Key Fingerprint

   The key fingerprint is computed as:

       fingerprint = SHA-256(key_material)

   Fingerprints are used for key identification in HELLO messages
   and for human verification. Key material MUST NOT be transmitted
   over the network or exposed via API endpoints.

5.4.  Key Lifecycle

   (a) GENERATION: Keys are generated locally on the node that will
       use them. O-Keys are generated on O-Nodes. R-Keys are
       generated on R-Nodes. Keys SHOULD NOT be transmitted between
       nodes.

   (b) STORAGE: Keys are stored in files with 0600 permissions.
       In production deployments, keys SHOULD be stored in a
       Trusted Platform Module (TPM) or Hardware Security Module
       (HSM).

   (c) ROTATION: Key rotation is performed by generating a new key,
       distributing the new fingerprint, and retiring the old key.
       Messages signed with the old key remain verifiable as long
       as the old key is retained for verification purposes.

   (d) DESTRUCTION: Key material MUST be securely zeroed using
       a function that cannot be optimized away by the compiler
       (e.g., explicit_bzero, memset_s, or volatile-qualified
       memory writes).

5.5.  Key Rotation Procedure

   Key rotation SHOULD be performed at regular intervals. The
   RECOMMENDED rotation period is 90 days for production
   deployments.

   The rotation procedure is:

   1. Generate new key material on the node
   2. Compute fingerprint of the new key
   3. Send a TEARDOWN message (reason: 0x01, Key rotation) signed
      with the current key
   4. Load the new key into the signing path
   5. Send a HELLO message with the new key fingerprint
   6. Peers update their fingerprint tables
   7. Retain the old key in a read-only verification-only store
      for the duration of the Observation TTL (Section 16) to
      allow verification of in-flight messages

   During the transition window (between steps 3 and 6), peers
   MUST accept messages signed with either the old or new key.
   The transition window MUST NOT exceed 600 seconds.

5.6.  Key Revocation

   If a key is believed compromised, the following emergency
   procedure applies:

   1. Generate a new key immediately
   2. Send a TEARDOWN message (reason: 0x03, Error condition)
      with the compromised key (if still held)
   3. Load the new key
   4. Send HELLO with new fingerprint
   5. Notify all peers out-of-band that the old fingerprint
      is revoked
   6. Destroy the compromised key material (Section 5.4d)
   7. All peers MUST immediately cease accepting messages signed
      with the revoked key fingerprint

   Observations signed with the compromised key that are still
   within the Observation TTL SHOULD be flagged as
   VERIFICATION_SUSPECT and re-collected using the new key
   before being used as evidence in proposals.

5.7.  Key Compromise Detection

   Implementations SHOULD monitor for anomalous signing patterns
   that may indicate key compromise:

   (a) Observations from devices that are known to be powered off
       or physically disconnected
   (b) Observations with timestamps significantly ahead of the
       local clock
   (c) Sequence number gaps larger than expected given the
       observation rate
   (d) Observations containing output that contradicts physical
       topology constraints (e.g., a device reporting an interface
       that does not exist in the device registry)


6.  Trust Tier System

6.1.  Tier Definitions

   VIRP defines four trust tiers that govern the approval
   requirements for operations:

       Tier     Value   Name         Approval Required
       ──────────────────────────────────────────────────
       GREEN    0x01    Passive      None (auto-execute)
       YELLOW   0x02    Active       Single operator
       RED      0x03    Critical     m-of-n operators
       BLACK    0xFF    Forbidden    Structurally impossible

6.2.  Tier Assignment

   Tiers are assigned based on the operation's potential impact:

   GREEN (0x01) - Passive observation, no state change:
       - show ip bgp summary
       - show ip route
       - show ip interface brief
       - show access-lists
       - show ip ospf neighbor
       - show running-config (read-only)
       - show logging
       - show version
       - get system status (FortiOS)
       - get system performance status (FortiOS)
       - Get-Process, Get-Service (Windows)

   YELLOW (0x02) - Active diagnostics, minimal state change:
       - debug ip bgp updates (temporary)
       - show tech-support (resource intensive)
       - test ip route
       - ping / traceroute (generates traffic)
       - diagnose sys session stat (FortiOS)

   RED (0x03) - Configuration changes, state modification:
       - configure terminal (any config mode entry)
       - ip route (static route changes)
       - router bgp / router ospf (protocol changes)
       - interface shutdown / no shutdown
       - access-list modifications
       - write memory / copy running startup
       - config firewall policy (FortiOS)

   BLACK (0xFF) - Destructive, irreversible, or trust-breaking:
       - Key deletion or modification
       - Approval bypass
       - Factory reset
       - Disabling the observation channel
       - Modifying the trust tier assignments
       - execute factoryreset (FortiOS)
       - erase startup-config (Cisco IOS)

6.3.  BLACK Tier Enforcement

   BLACK tier operations are not denied at runtime. They do not
   exist in the protocol. There is no message type for key deletion.
   There is no approval workflow for disabling observers. The
   absence is structural, not procedural.

   An implementation MUST NOT provide any mechanism — including
   administrative override, emergency mode, or debug interface —
   that allows BLACK tier operations to be performed through the
   VIRP protocol. Such operations, if required, MUST be performed
   through out-of-band mechanisms (physical console access, direct
   file system manipulation) that are outside the protocol's scope.

6.4.  Tier Validation

   The O-Node MUST validate the trust tier of each requested
   command before execution. Tier assignment is performed by
   pattern matching against a command classification table.

   Commands not matching any tier pattern MUST default to RED
   (requiring explicit approval).

6.5.  Tier Assignment Context

   Tier assignment MAY be context-dependent. An implementation
   MAY assign different tiers to the same command based on:

   (a) TARGET DEVICE: "show running-config" on a lab router
       may be GREEN; on a production border router, YELLOW.
   (b) TIME OF DAY: Configuration changes during maintenance
       windows may be RED; outside maintenance windows, they
       require additional approval (m-of-n with higher m).
   (c) CUMULATIVE IMPACT: The first "interface shutdown" in a
       session may be RED; the tenth may escalate to require
       additional approval.

   Context-dependent tier assignment MUST be documented in the
   deployment's configuration and MUST NOT reduce a tier below
   the default assignment for any command.

6.6.  Tier Override Policy

   Deployments MAY define a tier override policy that elevates
   (but never reduces) the default tier for specific commands
   on specific devices. The override policy MUST be:

   (a) Stored outside the R-Node's access (the AI cannot modify
       its own tier constraints)
   (b) Signed or integrity-protected to prevent tampering
   (c) Auditable — all overrides MUST be logged with timestamp,
       the identity of the administrator who configured them,
       and the justification


7.  Message Format

7.1.  Header Structure

   All VIRP messages share a common 56-byte fixed header:

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |    Version    |     Type      |            Length             |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |            Length (cont.)     |   Channel     |     Tier     |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |     Flags     |   Reserved    |          Reserved            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       +                       Timestamp (64-bit)                      +
       |                       nanoseconds since epoch                 |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      Source Node ID                           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      Sequence Number                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       +                                                               +
       |                                                               |
       +                     HMAC-SHA256 (256 bits)                    +
       |                                                               |
       +                                                               +
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Total header size: 56 bytes (VIRP_HEADER_SIZE)

7.2.  Header Fields

   Version (8 bits):
       Protocol version. Current version is 0x01. Implementations
       MUST reject messages with unknown version numbers.
       See Section 18 for version negotiation.

   Type (8 bits):
       Message type identifier. See Section 8 for defined types.

   Length (32 bits, network byte order):
       Total message length in bytes, including header and payload.
       Minimum value is 56 (header only, no payload).

   Channel (8 bits):
       Channel identifier:
           0x01 = Observation Channel (OC)
           0x02 = Intent Channel (IC)

   Tier (8 bits):
       Trust tier of the operation:
           0x01 = GREEN
           0x02 = YELLOW
           0x03 = RED
           0xFF = BLACK (MUST be rejected by implementations)

   Flags (8 bits):
       Bitfield for message flags:
           Bit 0: COMPRESSED - Payload is zlib-compressed
           Bit 1: FRAGMENTED - Message is part of a fragment set
           Bit 2: ENCRYPTED - Payload is encrypted
           Bit 3: STALE - Observation exceeds freshness window
                   (set by verifier, not originator)
           Bits 4-7: Reserved, MUST be zero

   Reserved (24 bits):
       Reserved for future use. MUST be set to zero on transmission.
       Implementations MUST reject messages with non-zero reserved
       fields to prevent protocol confusion attacks.

   Timestamp (64 bits, network byte order):
       Nanoseconds since Unix epoch (January 1, 1970 00:00:00 UTC).
       Implementations MUST reject observations with timestamps
       more than the configured freshness window (default: 300
       seconds) from the local clock to prevent replay attacks.
       See Section 16 for freshness semantics.

   Source Node ID (32 bits, network byte order):
       Unique identifier of the originating node. Assigned during
       node configuration. Node IDs MUST be unique within a VIRP
       deployment.

   Sequence Number (32 bits, network byte order):
       Monotonically increasing counter per source node. Wraps to
       zero at 2^32. Implementations SHOULD track the last seen
       sequence number per source and reject messages with sequence
       numbers more than 1000 behind the current value to detect
       replay attacks.

   HMAC-SHA256 (256 bits / 32 bytes):
       HMAC-SHA256 computed over the header (with HMAC field zeroed)
       and payload. See Section 10 for construction details.

7.3.  Payload

   The payload immediately follows the 56-byte header. Payload
   length is computed as:

       payload_length = Length - VIRP_HEADER_SIZE

   Payload contents are type-dependent. See Section 8 for
   per-type payload formats.

7.4.  Maximum Message Size

   Implementations MUST support messages up to 65,536 bytes
   (header + payload). Implementations MAY support larger
   messages using the FRAGMENTED flag.

7.5.  Byte Order

   All multi-byte integer fields are transmitted in network byte
   order (big-endian), as per Internet convention.


8.  Message Types

8.1.  OBSERVATION (0x01)

   Channel: Observation Channel (OC) only
   Tier: GREEN (0x01) for read-only commands

   Carries signed device output collected by an O-Node.

   Payload: Observation sub-header (see Section 9) followed by
   raw device output as UTF-8 text.

   An OBSERVATION message represents a single command execution
   on a single device. The payload contains the complete,
   unmodified output of the command as returned by the device.

   O-Nodes MUST NOT modify, filter, or summarize device output
   before signing. The signed payload MUST be the exact byte
   sequence returned by the device driver.

8.2.  HELLO (0x02)

   Channel: Both OC and IC
   Tier: GREEN (0x01)

   Peer introduction message exchanged during connection
   establishment.

   Payload format:
       Offset  Length  Field
       ──────────────────────────────────────────
       0       32      O-Key fingerprint (SHA-256)
       32      32      R-Key fingerprint (SHA-256)
       64      2       Supported version (min)
       66      2       Supported version (max)
       68      4       Capabilities bitfield
       72      var     Node name (UTF-8, null-terminated)

   Capabilities bitfield:
       Bit 0: CISCO_IOS driver available
       Bit 1: FORTINET driver available
       Bit 2: JUNIPER driver available
       Bit 3: PALO_ALTO driver available
       Bit 4: LINUX driver available
       Bit 5: MOCK driver available
       Bit 6: ARISTA driver available
       Bit 7: WINDOWS driver available
       Bits 8-31: Reserved

8.3.  PROPOSAL (0x10)

   Channel: Intent Channel (IC) only
   Tier: RED (0x03) minimum

   AI-generated change request. MUST reference one or more signed
   observations as supporting evidence.

   Payload format:
       Offset  Length  Field
       ──────────────────────────────────────────
       0       4       Number of evidence refs (N)
       4       N*36    Evidence references (see below)
       4+N*36  4       Number of commands (M)
       8+N*36  var     Command list (see below)

   Evidence reference (36 bytes each):
       Offset  Length  Field
       ──────────────────────────────────────────
       0       4       Source node ID of observation
       4       32      HMAC of referenced observation

   Command entry (variable length):
       Offset  Length  Field
       ──────────────────────────────────────────
       0       4       Target device node ID
       4       1       Command tier
       5       2       Command length (bytes)
       7       var     Command string (UTF-8)

   A PROPOSAL with zero evidence references MUST be rejected
   by the receiving node with VIRP_ERR_NO_EVIDENCE (0x0007).

   A PROPOSAL referencing observations that have exceeded their
   freshness window (Section 16) MUST be rejected with
   VIRP_ERR_STALE_EVIDENCE (0x0008).

8.4.  APPROVAL (0x11)

   Channel: Intent Channel (IC) only
   Tier: Matches the tier of the approved PROPOSAL

   Human or automated authorization for a PROPOSAL.

   Payload format:
       Offset  Length  Field
       ──────────────────────────────────────────
       0       32      HMAC of approved PROPOSAL
       32      4       Approver node ID
       36      1       Approval type (0x01=human, 0x02=auto)
       37      var     Approver identity (UTF-8, null-term)

8.5.  INTENT_ADVERTISE (0x20)

   Channel: Intent Channel (IC) only
   Tier: YELLOW (0x02) minimum

   Advertises route or prefix reachability. Analogous to BGP
   UPDATE with NLRI.

   Payload format:
       Offset  Length  Field
       ──────────────────────────────────────────
       0       1       Address family (IPv4=1, IPv6=2)
       1       1       Prefix length (CIDR notation)
       2       4/16    Prefix (4 bytes IPv4, 16 bytes IPv6)
       var     4       Next hop node ID
       var     4       Metric
       var     32      Supporting observation HMAC

8.6.  INTENT_WITHDRAW (0x21)

   Channel: Intent Channel (IC) only
   Tier: YELLOW (0x02) minimum

   Withdraws a previously advertised route or prefix. Analogous
   to BGP UPDATE with withdrawn routes.

   Payload format:
       Offset  Length  Field
       ──────────────────────────────────────────
       0       1       Address family (IPv4=1, IPv6=2)
       1       1       Prefix length
       2       4/16    Prefix
       var     32      Original INTENT_ADVERTISE HMAC

8.7.  HEARTBEAT (0x30)

   Channel: Both OC and IC
   Tier: GREEN (0x01)

   Liveness and health reporting message. O-Nodes SHOULD send
   heartbeats every 30 seconds.

   Payload format:
       Offset  Length  Field
       ──────────────────────────────────────────
       0       4       Uptime (seconds)
       4       4       Total observations signed
       8       4       Total proposals processed
       12      2       Active device count
       14      2       Failed device count
       16      1       Health status (0=OK, 1=DEGRADED, 2=FAIL)
       17      var     Status message (UTF-8, optional)

8.8.  TEARDOWN (0xF0)

   Channel: Both OC and IC
   Tier: GREEN (0x01)

   Graceful shutdown notification. Peers receiving TEARDOWN
   SHOULD close the connection and clear cached state for the
   departing node.

   Payload format:
       Offset  Length  Field
       ──────────────────────────────────────────
       0       1       Reason code:
                       0x00 = Normal shutdown
                       0x01 = Key rotation
                       0x02 = Configuration change
                       0x03 = Error condition
       1       var     Reason string (UTF-8, optional)


9.  Observation Sub-Header

   OBSERVATION messages (type 0x01) include a sub-header before
   the device output payload:

       Offset  Length  Field
       ──────────────────────────────────────────
       0       1       Observation type:
                       0x01 = Command output
                       0x02 = Configuration snapshot
                       0x03 = Log extract
                       0x04 = Metric sample
                       0x05 = Error response
       1       1       Scope:
                       0x01 = Single device
                       0x02 = Interface
                       0x03 = Protocol instance
       2       2       Data length (bytes of device output)
       4       var     Device output (raw UTF-8)

   The data length field specifies the exact number of bytes
   of device output that follow. This allows parsers to
   distinguish between device output and any future trailer
   fields.

   Observation type 0x05 (Error response) is used when the
   O-Node cannot complete the requested command. The payload
   contains the error description rather than device output.
   Error observations are still HMAC-signed, providing
   cryptographic proof that the O-Node attempted and failed
   to collect the data. This prevents the AI from filling
   gaps with fabricated output — a signed error is better
   than an unsigned guess.


10.  HMAC Construction

10.1.  Signing

   The HMAC-SHA256 is computed over the concatenation of:

   (a) Header bytes 0-23 (version through sequence number)
   (b) Payload bytes (all bytes after the header)

   The HMAC field (header bytes 24-55) is EXCLUDED from the
   computation. During signing, this field is treated as if it
   contains all zeros.

   Procedure:

       1. Construct the complete message (header + payload)
       2. Set the HMAC field (bytes 24-55) to all zeros
       3. Compute HMAC-SHA256:
          data = header[0:24] || payload[0:payload_length]
          hmac = HMAC-SHA256(key.material, data)
       4. Copy the 32-byte HMAC into header bytes 24-55

10.2.  Verification

   Procedure:

       1. Extract the HMAC from header bytes 24-55
       2. Set the HMAC field to all zeros
       3. Compute HMAC-SHA256 over the same data range:
          data = header[0:24] || payload[0:payload_length]
          expected = HMAC-SHA256(key.material, data)
       4. Compare using constant-time comparison:
          result = CRYPTO_memcmp(received_hmac, expected, 32)
       5. Restore the original HMAC field

   Implementations MUST use constant-time comparison to prevent
   timing side-channel attacks.

10.3.  Key Selection

   The signing key is selected based on the message channel:

       Channel     Key Type    Error if Wrong Key
       ──────────────────────────────────────────────
       OC (0x01)   O-Key       VIRP_ERR_CHANNEL_VIOLATION
       IC (0x02)   R-Key       VIRP_ERR_CHANNEL_VIOLATION

   Key selection and channel-binding validation MUST occur
   BEFORE the HMAC computation begins.


11.  O-Node Operation

11.1.  Startup Sequence

   1. Load or generate O-Key from configured path
   2. Compute and log key fingerprint
   3. Load device registry from JSON configuration
   4. Create Unix domain socket
   5. Begin heartbeat timer (30-second interval)
   6. Enter request processing loop

11.2.  Device Registry

   The O-Node maintains a registry of managed devices in JSON
   format:

       {
           "devices": [
               {
                   "hostname": "R1",
                   "host": "192.168.1.1",
                   "port": 22,
                   "vendor": "cisco_ios",
                   "username": "virp-svc",
                   "password": "<credential>",
                   "enable": "<credential>",
                   "node_id": "01010101"
               }
           ]
       }

   Credentials in the device registry MUST be protected with
   file permissions (0600) and SHOULD be encrypted at rest in
   production deployments.

11.3.  Command Execution

   Upon receiving an EXECUTE request:

   1. Validate the target device exists in the registry
   2. Determine the trust tier of the requested command
   3. If tier > GREEN, return the tier requirement to the
      requestor for approval handling
   4. Connect to the device using the appropriate driver
   5. Execute the command
   6. Capture the complete output
   7. Construct an OBSERVATION message
   8. Sign with O-Key
   9. Return the signed message

   The O-Node MUST NOT cache command output. Each request
   MUST result in a fresh connection and execution.

11.4.  Sequence Number Management

   The O-Node maintains a single monotonically increasing
   sequence counter. The counter starts at 1 on startup and
   increments for every message sent (including heartbeats).
   The counter wraps to 0 at 2^32.

11.5.  Error Observation Generation

   When a command execution fails (device unreachable, timeout,
   authentication failure), the O-Node MUST still generate a
   signed OBSERVATION message with:

   (a) Observation type 0x05 (Error response)
   (b) Payload containing the error description
   (c) Valid HMAC signature

   This ensures that the absence of data is itself a verified
   fact. The R-Node receives cryptographic proof that the O-Node
   attempted the collection and failed, rather than silence
   which the R-Node might fill with fabricated data.


12.  R-Node Operation

12.1.  Observation Consumption

   R-Nodes consume signed observations from O-Nodes. Before
   using any observation for reasoning or display, the R-Node
   SHOULD verify the HMAC signature using the O-Node's key
   fingerprint.

   Observations that fail verification MUST be flagged as
   UNVERIFIED and MUST NOT be used as evidence in PROPOSAL
   messages.

12.2.  Proposal Construction

   When an R-Node determines that a network change is needed:

   1. Identify the supporting observations (signed, verified)
   2. Verify that all referenced observations are within the
      freshness window (Section 16)
   3. Construct the PROPOSAL with evidence references
   4. Sign with R-Key
   5. Submit for approval per the tier requirements

   A PROPOSAL MUST reference at least one verified observation.
   R-Nodes MUST NOT construct proposals based on unverified
   data, cached observations older than the configured TTL,
   or internally generated (fabricated) device state.

12.3.  Anti-Fabrication Enforcement

   R-Nodes that are AI/LLM-based systems SHOULD include the
   following constraints in their system prompts:

   (a) Data in signed observation tags is cryptographically
       verified. Never fabricate device data.
   (b) If no verified observation exists for a query, respond
       with "no verified data available."
   (c) Never generate synthetic device output.

   These prompt-level constraints are ADVISORY. The protocol-
   level constraint (requiring signed evidence for proposals)
   is STRUCTURAL and does not depend on AI compliance.

12.4.  Observation Staleness Handling

   R-Nodes MUST track the timestamp of each observation they
   consume. When presenting observations to users, R-Nodes
   SHOULD indicate the age of the data:

   (a) Observations collected within the last 30 seconds:
       Present as "live" or "current"
   (b) Observations between 30 seconds and the freshness
       window: Present with explicit age (e.g., "collected
       2 minutes ago")
   (c) Observations beyond the freshness window: Present
       as "stale" with a warning that re-collection is
       recommended
   (d) Observations beyond the TTL: MUST NOT be presented
       as current data under any circumstances


13.  Socket Protocol

13.1.  Transport

   The O-Node listens on a Unix domain socket (SOCK_STREAM).
   The default path is /tmp/virp-onode.sock.

13.2.  Request Format

   Requests are JSON objects sent as raw bytes (no length
   prefix):

       {
           "action": "<action_name>",
           "device": "<hostname>",
           "command": "<command_string>"
       }

   Defined actions:

       Action          Description
       ──────────────────────────────────────────
       execute         Execute command on device
       health          O-Node health status
       heartbeat       Request heartbeat message
       list_devices    List registered devices
       shutdown        Graceful shutdown

13.3.  Response Format

   Responses are raw binary VIRP messages. The response
   format depends on the result:

   Success: Complete VIRP message (header + payload), minimum
   56 bytes. The message type indicates the response content
   (OBSERVATION for execute, HEARTBEAT for heartbeat, etc.).

   Error: 4-byte error code in network byte order:

       Code    Name                        Description
       ──────────────────────────────────────────────────────
       0x0001  VIRP_ERR_UNKNOWN_DEVICE     Device not in registry
       0x0002  VIRP_ERR_CONNECT_FAILED     SSH/API connection failed
       0x0003  VIRP_ERR_CHANNEL_VIOLATION  Channel-key binding error
       0x0004  VIRP_ERR_INVALID_MESSAGE    Malformed message
       0x0005  VIRP_ERR_HMAC_FAILED        HMAC verification failed
       0x0006  VIRP_ERR_TIMEOUT            Command execution timeout
       0x0007  VIRP_ERR_NO_EVIDENCE        Proposal lacks evidence
       0x0008  VIRP_ERR_STALE_EVIDENCE     Evidence exceeds freshness
       0x0009  VIRP_ERR_VERSION_MISMATCH   Unsupported protocol version
       0x000A  VIRP_ERR_KEY_REVOKED        Signing key has been revoked
       0x000B  VIRP_ERR_TIER_VIOLATION     Operation exceeds tier auth
       0x000C  VIRP_ERR_REPLAY_DETECTED    Sequence/timestamp replay

   Clients distinguish success from error by response size:
   4 bytes = error code, 56+ bytes = VIRP message.


14.  REST API Binding

14.1.  Overview

   The VIRP Appliance wraps the O-Node Unix socket protocol
   in an HTTP REST API for consumption by web-based platforms
   and AI systems.

   Default port: 8470

14.2.  Endpoints

   GET /api/health

       Response: JSON object with O-Node status
       {
           "status": "healthy",
           "uptime_seconds": 10860,
           "observations_total": 285,
           "devices_registered": 10,
           "key_loaded": true,
           "key_fingerprint": "6ef82457fa137799..."
       }

   GET /api/devices

       Response: JSON array of registered devices
       [
           {
               "hostname": "R1",
               "host": "192.168.1.1",
               "vendor": "cisco_ios",
               "enabled": true
           }
       ]

       Note: Credentials are NEVER included in API responses.

   POST /api/observe

       Request:
       {
           "device": "R1",
           "command": "show ip bgp summary"
       }

       Response:
       {
           "observation": {
               "type": "OBSERVATION",
               "channel": "OBSERVATION",
               "trust_tier": "GREEN",
               "verified": true,
               "timestamp": "2026-03-01T17:11:13.000000Z",
               "source_node_id": "0x00000001",
               "sequence": 42,
               "payload": "<device output>",
               "hmac": "a3b4c5d6...",
               "freshness": "live",
               "age_seconds": 0.3
           }
       }

   POST /api/sweep

       Request:
       {
           "commands": [
               "show ip bgp summary",
               "show ip route",
               "show ip ospf neighbor",
               "show ip interface brief"
           ],
           "devices": ["R1", "R2"]  // optional, default: all
       }

       Response:
       {
           "sweep": {
               "total_observations": 8,
               "verified": 8,
               "failed": 0,
               "stale": 0,
               "duration_ms": 8800,
               "observations": [...]
           }
       }

   GET /api/observations

       Response: JSON array of recent observations (last 100)

   GET /api/key

       Response:
       {
           "fingerprint": "6ef82457fa137799...",
           "channel": "OC",
           "algorithm": "HMAC-SHA256"
       }

       Note: Key material is NEVER exposed via the API.


15.  Device Driver Interface

15.1.  Driver Structure

   Each device driver implements the following interface:

       typedef struct {
           const char    *name;
           virp_vendor_t  vendor;

           virp_error_t (*connect)(
               virp_device_t *device,
               virp_connection_t **conn
           );

           virp_error_t (*execute)(
               virp_connection_t *conn,
               const char *command,
               char *output,
               size_t *output_length
           );

           void (*disconnect)(
               virp_connection_t *conn
           );

           virp_vendor_t (*detect)(
               const char *host,
               uint16_t port
           );

           virp_error_t (*health_check)(
               virp_connection_t *conn
           );
       } virp_driver_t;

15.2.  Vendor Identifiers

       Vendor          Code    Driver Status
       ──────────────────────────────────────────
       CISCO_IOS       0x01    Implemented
       FORTINET        0x02    Implemented (SSH)
       JUNIPER         0x03    Planned
       PALO_ALTO       0x04    Planned
       LINUX           0x05    Planned
       ARISTA          0x06    Planned
       WINDOWS         0x07    Planned (WinRM)
       MOCK            0x63    Implemented (testing)

15.3.  Driver Requirements

   Drivers MUST:

   (a) Return the complete, unmodified command output in the
       output buffer. No filtering, summarizing, or reformatting.

   (b) Set *output_length to the exact number of bytes written.

   (c) Handle authentication (username, password, enable secret)
       using credentials from the device registry.

   (d) Support connection timeout (default: 10 seconds).

   (e) Support command execution timeout (default: 30 seconds).

   (f) Clean up all resources (sockets, memory) on disconnect.

   Drivers MUST NOT:

   (a) Cache command output between executions.
   (b) Modify device configuration without explicit request.
   (c) Store credentials outside the provided device structure.


16.  Observation Freshness and Expiry

16.1.  Freshness Window

   The freshness window defines the maximum age of an observation
   that may be presented as "current" data. The default freshness
   window is 300 seconds (5 minutes).

   An observation's age is computed as:

       age = current_time - observation.timestamp

   Observations within the freshness window are considered
   authoritative for reasoning purposes. Observations outside
   the freshness window MUST be flagged with the STALE bit
   (Flags bit 3) when served from cache.

16.2.  Observation TTL

   The Observation TTL defines the maximum age of an observation
   that may be served at all. The default TTL is 3600 seconds
   (1 hour).

   Observations exceeding the TTL MUST be evicted from any
   cache and MUST NOT be served in response to queries. If no
   fresh observation exists for a device and the cached
   observation has exceeded TTL, the O-Node MUST re-collect
   or return an error observation (type 0x05) indicating that
   no current data is available.

   The TTL MUST always be greater than or equal to the
   freshness window.

16.3.  Freshness Categories

   Implementations SHOULD categorize observation freshness as
   follows:

       Category    Age Range           Presentation
       ─────────────────────────────────────────────────
       LIVE        0 - 30 seconds      "Current" (no qualifier)
       RECENT      30s - freshness_window  "Collected X ago"
       STALE       freshness - TTL     "Stale (X minutes old)"
       EXPIRED     > TTL               Do not serve

16.4.  Freshness in Proposals

   A PROPOSAL MUST NOT reference observations that have exceeded
   the freshness window. If an R-Node determines that a network
   change is needed based on an observation that is now stale,
   it MUST first re-collect the observation and verify the
   condition still exists before constructing the PROPOSAL.

   This prevents proposals based on transient conditions that
   may have self-resolved.

16.5.  Configuration

   The freshness window and TTL are deployment-configurable.
   Implementations MUST support the following configuration
   parameters:

       Parameter           Default     Minimum     Maximum
       ─────────────────────────────────────────────────────
       freshness_window    300s        30s         3600s
       observation_ttl     3600s       300s        86400s

   These parameters MAY be set per-device or globally.
   Per-device freshness windows allow tighter requirements
   for critical devices (e.g., border routers) and relaxed
   requirements for stable devices (e.g., access switches).


17.  Multi-Node Coordination

17.1.  Overview

   Production deployments MAY use multiple O-Nodes for
   redundancy, geographic distribution, or scaling. This
   section defines the coordination requirements for multi-
   O-Node deployments.

17.2.  Observation Authority

   When multiple O-Nodes can observe the same device, the
   following authority rules apply:

   (a) PRIMARY AUTHORITY: Each device SHOULD have a designated
       primary O-Node. The primary O-Node is the authoritative
       source of observations for that device.

   (b) SECONDARY OBSERVATION: Other O-Nodes MAY observe the
       same device for redundancy. Secondary observations are
       valid and verifiable but the primary observation takes
       precedence if they conflict.

   (c) CONFLICT RESOLUTION: If two O-Nodes report conflicting
       observations for the same device within the freshness
       window, the observation with the more recent timestamp
       is authoritative. R-Nodes SHOULD flag the conflict for
       human review.

   (d) FAILOVER: If the primary O-Node fails (no heartbeat
       for 90 seconds), a secondary O-Node SHOULD assume
       primary authority for the affected devices.

17.3.  Node ID Assignment

   In multi-node deployments, Node IDs MUST be unique across
   all nodes. The RECOMMENDED assignment scheme is:

       Node ID Range       Assignment
       ──────────────────────────────────────────
       0x00000001-0x0000FFFF   O-Nodes
       0x00010000-0x0001FFFF   R-Nodes
       0x00020000-0x0002FFFF   Approver nodes
       0xFFFF0000-0xFFFFFFFF   Reserved

17.4.  Key Independence

   Each O-Node MUST have its own independent O-Key. O-Keys
   MUST NOT be shared between O-Nodes. This ensures that
   compromise of one O-Node does not compromise observations
   from other O-Nodes.

   R-Nodes maintain a fingerprint table mapping Node IDs to
   key fingerprints. When verifying an observation, the R-Node
   selects the verification key based on the Source Node ID
   in the message header.

17.5.  Heartbeat Aggregation

   In multi-node deployments, R-Nodes SHOULD aggregate
   heartbeats from all O-Nodes and present a unified health
   view. The aggregated health status is:

   (a) OK: All O-Nodes report OK
   (b) DEGRADED: One or more O-Nodes report DEGRADED or are
       missing heartbeats
   (c) FAIL: All O-Nodes report FAIL or are missing heartbeats


18.  Protocol Versioning

18.1.  Version Negotiation

   VIRP uses version numbers to ensure interoperability between
   implementations of different specification revisions.

   The current protocol version is 0x01.

   Version negotiation occurs during the HELLO exchange:

   1. Each peer sends a HELLO message containing its supported
      version range (min_version, max_version)
   2. The negotiated version is the highest version supported
      by both peers
   3. If no common version exists, both peers MUST send
      TEARDOWN (reason: 0x03) and close the connection

18.2.  Version Compatibility Rules

   (a) A version 0x01 implementation receiving a message with
       version 0x02 MUST reject the message with
       VIRP_ERR_VERSION_MISMATCH (0x0009)

   (b) Future versions MUST NOT change the meaning of existing
       message types. New functionality MUST use new message
       types.

   (c) Future versions MUST NOT reduce the header size below
       56 bytes. Additional header fields, if needed, MUST be
       appended after the existing fields or encoded in the
       payload.

   (d) Future versions MAY add new Flags bits, new error codes,
       new message types, new observation types, new vendor
       identifiers, and new trust tier values (excluding BLACK,
       which is permanently assigned to 0xFF).

18.3.  Deprecation

   When a version is deprecated, implementations SHOULD support
   it for at least 24 months after the deprecation announcement
   to allow migration.


19.  Threat Model

19.1.  Overview

   This section formally describes the adversary model for
   VIRP. A complete threat model is essential for understanding
   what VIRP protects against and, equally important, what it
   does not protect against. Security engineers evaluating VIRP
   for deployment should use this section to determine whether
   the protocol's guarantees match their threat environment.

19.2.  Trust Boundaries

   VIRP defines the following trust boundaries:

   (a) TRUSTED COMPONENTS:
       - The O-Node process and its host operating system
       - The O-Key material stored on the O-Node host
       - The device registry and its credentials
       - The managed devices themselves
       - The SSH/API transport between O-Node and devices

   (b) UNTRUSTED COMPONENTS:
       - The R-Node (AI/LLM system)
       - The network between O-Node and R-Node
       - The user interface presenting observations
       - Any caching layer between O-Node and R-Node

   (c) SEMI-TRUSTED COMPONENTS:
       - The human operators approving proposals (trusted for
         authorization, not trusted to be infallible)
       - The approval system infrastructure (trusted for
         availability, not trusted for integrity without
         signatures)

19.3.  Threats VIRP Protects Against

   VIRP provides structural protection against the following
   threat classes:

   (a) AI FABRICATION (Primary threat):
       The R-Node generates synthetic device output that appears
       authentic. VIRP prevents this because the R-Node cannot
       produce valid HMAC signatures — it does not hold the
       O-Key.

       Attack vector: AI generates "show ip bgp summary" output
       with plausible data and presents it as device output.
       VIRP defense: Output lacks HMAC signature. UI marks it
       as UNVERIFIED. Proposals referencing it are rejected.

   (b) AI FABRICATION VIA RESPONSE INJECTION:
       The R-Node generates fabricated output directly in its
       response text, bypassing the signed execution path.
       VIRP defense: Only data within signed observation tags
       carries protocol weight. Text outside signed observations
       is treated as AI commentary, not device output.

   (c) UNAUTHORIZED CONFIGURATION CHANGES:
       The R-Node attempts to execute destructive or unauthorized
       commands.
       VIRP defense: Trust tier enforcement at the O-Node.
       RED/BLACK commands require approval before execution.
       The O-Node enforces tiers, not the R-Node.

   (d) CROSS-CHANNEL KEY MISUSE:
       An attacker with access to an R-Key attempts to forge
       observations.
       VIRP defense: Channel-key binding check occurs before
       HMAC computation. R-Keys cannot sign OC messages.

   (e) MESSAGE REPLAY:
       An attacker captures and replays a previously valid
       observation.
       VIRP defense: Sequence numbers and timestamps. Receivers
       reject messages with stale sequence numbers or timestamps
       outside the freshness window.

   (f) MESSAGE MODIFICATION:
       An attacker intercepts and modifies a message in transit.
       VIRP defense: HMAC-SHA256. Any modification invalidates
       the signature.

   (g) LOG POISONING / TELEMETRY SPOOFING:
       An attacker injects false data into the telemetry pipeline
       between the O-Node and R-Node.
       VIRP defense: Injected data lacks valid HMAC signatures.
       The R-Node rejects unverified observations.

   (h) MIDDLEWARE INJECTION:
       A compromised component between the O-Node and R-Node
       injects fabricated observations.
       VIRP defense: The middleware cannot forge HMAC signatures
       without the O-Key. Injected messages fail verification.

19.4.  Threats VIRP Does NOT Protect Against

   The following threats are explicitly outside VIRP's scope.
   Deployments facing these threats MUST implement additional
   mitigations:

   (a) COMPROMISED O-NODE:
       If an attacker gains control of the O-Node process or
       its host operating system, they have access to the O-Key
       and can forge observations. VIRP cannot detect this.
       Mitigation: OS hardening, process isolation, TPM-backed
       key storage, hardware security modules, anomaly detection
       on observation patterns (Section 5.7).

   (b) COMPROMISED MANAGED DEVICE:
       If a managed device is compromised, it returns false
       data to legitimate queries. The O-Node faithfully signs
       this false data because it is authentic device output.
       VIRP guarantees that the device said X; it does not
       guarantee that X is true.
       Mitigation: Cross-device correlation, physical security,
       out-of-band verification, device integrity monitoring.

   (c) COMPROMISED SIGNING KEYS:
       If O-Key material is exfiltrated, an attacker can forge
       observations from any device. VIRP provides key
       revocation (Section 5.6) but cannot retroactively
       invalidate observations signed before the compromise
       was detected.
       Mitigation: Key rotation (Section 5.5), TPM/HSM storage,
       access controls on key files, monitoring for anomalous
       signing patterns.

   (d) DENIAL OF SERVICE:
       An attacker can flood the O-Node with requests, preventing
       legitimate observation collection. VIRP's availability
       guarantees are limited to what the underlying transport
       and OS provide.
       Mitigation: Rate limiting, connection limits, firewall
       rules on the O-Node socket.

   (e) SIDE-CHANNEL ATTACKS ON HMAC:
       Timing attacks on HMAC verification could theoretically
       leak information about the expected HMAC value.
       Mitigation: Constant-time comparison (Section 10.2).
       This is a MUST-level requirement.

   (f) AI REASONING ERRORS:
       VIRP guarantees the AI sees authentic data. It does not
       guarantee the AI reasons correctly about that data. An
       AI may misinterpret valid observations and propose
       inappropriate changes.
       Mitigation: Human approval for RED tier operations,
       post-change observation verification.

   (g) SOCIAL ENGINEERING OF APPROVERS:
       A sophisticated AI could craft convincing but misleading
       proposals that technically reference valid observations
       but lead to harmful outcomes.
       Mitigation: Approver training, proposal review tools,
       impact analysis requirements, m-of-n approval for
       critical operations.

19.5.  Trust Assumptions

   VIRP's security properties rest on the following assumptions.
   If any assumption is violated, the corresponding security
   property may not hold:

   Assumption                          If Violated
   ──────────────────────────────────────────────────────────
   O-Node host is not compromised      Observations may be forged
   O-Key is not exfiltrated            Observations may be forged
   HMAC-SHA256 is collision-resistant   Signatures may be forged
   Device output is authentic           Signed lies propagate
   Clock drift < freshness window       Replay detection fails
   Sequence counter is monotonic        Replay detection fails


20.  Security Considerations

20.1.  Fabrication Resistance

   VIRP provides fabrication resistance through three mechanisms:

   (a) SIGNING AT COLLECTION: Observations are signed at the
       point of collection, before the data enters any AI
       processing pipeline. The AI receives pre-signed data.

   (b) CHANNEL-KEY BINDING: Even if an AI system obtains an
       R-Key, it cannot forge observations because R-Keys
       cannot sign OC messages. The binding is enforced before
       HMAC computation.

   (c) EVIDENCE REQUIREMENTS: Proposals must reference signed
       observations. Proposals without evidence are rejected
       at the protocol level.

20.2.  Replay Protection

   Replay attacks are mitigated by three independent mechanisms:

   (a) SEQUENCE NUMBERS: Monotonically increasing per source node.
       Receivers track the last seen sequence and reject messages
       significantly behind the current value. The RECOMMENDED
       maximum sequence gap is 1000. Messages with a sequence
       number more than 1000 behind the current known value for
       that source SHOULD be rejected.

   (b) TIMESTAMPS: Nanosecond-precision timestamps allow receivers
       to reject observations that are too old. The RECOMMENDED
       maximum clock skew tolerance is 300 seconds. Observations
       with timestamps more than 300 seconds from the receiver's
       local clock MUST be rejected.

   (c) SESSION BINDING: In implementations with session semantics,
       session IDs embedded in execution contexts prevent
       cross-session replay.

   These mechanisms are independent and complementary. An attacker
   must defeat all three to successfully replay a message.

20.3.  Timing Attacks

   HMAC verification uses constant-time comparison
   (CRYPTO_memcmp or equivalent) to prevent timing side-channel
   attacks that could leak information about the expected HMAC
   value.

20.4.  Key Compromise

   If an O-Key is compromised, an attacker can forge observations.
   Mitigations:

   (a) Key material should be stored in TPM/HSM when available.
   (b) Key rotation should be performed regularly (Section 5.5).
   (c) Anomaly detection on observation patterns can identify
       forged observations (Section 5.7).
   (d) Key revocation procedure should be executed immediately
       upon detection (Section 5.6).

   If an R-Key is compromised, an attacker can forge proposals
   but cannot forge observations. Proposals still require
   approval (YELLOW/RED tier) before execution.

20.5.  Denial of Service

   An attacker with access to the O-Node socket can flood it
   with requests. Implementations SHOULD implement:

   (a) Rate limiting on the socket listener
   (b) Maximum concurrent connection limits
   (c) Request timeout enforcement

20.6.  Physical Kill Switch

   The VIRP hardware appliance (planned) includes a physical
   GPIO-connected switch that electrically disconnects the
   Intent Channel circuit. When the kill switch is engaged:

   (a) The Observation Channel continues to operate
   (b) The Intent Channel is physically broken
   (c) No software override is possible
   (d) The appliance operates in observation-only mode

   This provides a hardware-enforced guarantee that no
   configuration changes can be proposed or executed through
   the VIRP protocol, regardless of software state.

20.7.  Credential Protection

   Device credentials stored in the device registry (Section
   11.2) represent a high-value target. Compromise of the
   device registry provides direct access to all managed
   devices, independent of VIRP.

   Implementations MUST:

   (a) Store the device registry with file permissions 0600
   (b) Never expose credentials via API endpoints
   (c) Never include credentials in log output
   (d) Support encrypted-at-rest credential storage

   Implementations SHOULD:

   (a) Support external credential providers (e.g., HashiCorp
       Vault, AWS Secrets Manager)
   (b) Rotate device credentials independently of VIRP keys
   (c) Use least-privilege credentials (read-only for GREEN
       tier operations)


21.  Formal Security Properties

21.1.  Overview

   This section states VIRP's security properties as formal
   assertions. Each property follows from the protocol's
   structural design and is verified by the conformance test
   suite (Section 22).

21.2.  Properties

   Property 1 (Observation Authenticity):
       An observation bearing a valid HMAC-SHA256 signature was
       produced by a process holding the corresponding O-Key.
       No other process can produce a valid signature for the
       Observation Channel.

       Depends on: HMAC-SHA256 security, O-Key confidentiality

   Property 2 (Channel Isolation):
       An O-Key cannot produce a valid signature for Intent
       Channel message types. An R-Key cannot produce a valid
       signature for Observation Channel message types. The
       channel-key binding check is executed before HMAC
       computation begins.

       Depends on: Correct implementation of binding check

   Property 3 (Evidence Binding):
       A PROPOSAL message that does not reference at least one
       verified, non-expired observation is rejected by the
       protocol with VIRP_ERR_NO_EVIDENCE or
       VIRP_ERR_STALE_EVIDENCE. No configuration change can
       proceed without grounding in observed facts.

       Depends on: PROPOSAL validation in the approval path

   Property 4 (Tier Enforcement):
       Commands classified as RED or BLACK cannot be executed
       through the protocol without the required approvals.
       BLACK tier commands cannot be executed through the
       protocol under any circumstances.

       Depends on: O-Node tier validation, absence of BLACK
       message types

   Property 5 (Replay Resistance):
       An observation with a sequence number more than 1000
       behind the current known value for its source, or with
       a timestamp outside the configured freshness window, is
       rejected by conformant implementations.

       Depends on: Sequence tracking, clock synchronization
       within the freshness tolerance

   Property 6 (Fabrication Non-Existence):
       The R-Node cannot produce data that a conformant
       implementation would accept as a verified observation.
       The R-Node does not hold an O-Key, and R-Keys are
       structurally prevented from signing observation messages.

       Depends on: Properties 1 and 2, O-Key isolation from
       R-Node process

   Property 7 (Error Authenticity):
       A signed error observation (type 0x05) provides
       cryptographic proof that the O-Node attempted and failed
       to collect data. The absence of data is itself a verified
       fact, preventing the R-Node from filling gaps with
       fabricated output.

       Depends on: O-Node error observation generation
       (Section 11.5)

   Property 8 (Modification Detection):
       Any modification to a signed message (header or payload)
       invalidates the HMAC-SHA256 signature. The probability
       of a modified message passing verification is 2^-256.

       Depends on: HMAC-SHA256 security


22.  Conformance Requirements

22.1.  Overview

   This section defines what constitutes a conformant VIRP
   implementation. The requirements are organized into
   mandatory (MUST) and optional (MAY) categories.

22.2.  Mandatory Requirements

   A conformant VIRP implementation MUST:

   (a) Implement HMAC-SHA256 signing and verification as
       specified in Section 10
   (b) Enforce channel-key binding as specified in Section 4.3
   (c) Support all message types defined in Section 8
   (d) Implement trust tier validation for GREEN, YELLOW,
       RED, and BLACK tiers as specified in Section 6
   (e) Default unrecognized commands to RED tier
   (f) Use constant-time comparison for HMAC verification
   (g) Generate signed error observations for failed commands
   (h) Support the freshness window mechanism (Section 16)
   (i) Reject proposals referencing stale evidence
   (j) Reject proposals with zero evidence references
   (k) Never expose key material via API or log output
   (l) Support all error codes defined in Section 13.3

22.3.  Conformance Test Categories

   The reference implementation test suite is organized into
   the following categories:

       Category                Tests   Requirement
       ─────────────────────────────────────────────────
       HMAC signing            12      MUST pass
       Channel-key binding     8       MUST pass
       Message serialization   6       MUST pass
       Trust tier enforcement  10      MUST pass
       Replay detection        6       MUST pass
       Freshness validation    5       MUST pass
       Error observation       4       MUST pass
       Proposal validation     8       MUST pass
       Multi-node (if impl.)   6       SHOULD pass
       Performance             4       INFORMATIONAL

   A total of 59 MUST-pass tests define minimum conformance.
   The full test suite contains additional tests for optional
   features and performance benchmarking.

22.4.  Interoperability Testing

   Two independently developed conformant implementations
   MUST be able to:

   (a) Complete a HELLO exchange and negotiate a common version
   (b) Exchange signed observations that the other can verify
   (c) Exchange proposals that the other can validate
   (d) Reject each other's cross-channel signing attempts
   (e) Agree on trust tier classification for a standard set
       of commands


23.  IANA Considerations

23.1.  Overview

   This document defines the following registries that would
   require IANA registration if VIRP is standardized. No IANA
   registration is requested at this time. This document is
   published as an experimental protocol specification.

23.2.  VIRP Message Type Registry

       Value   Name              Reference
       ──────────────────────────────────────
       0x01    OBSERVATION       Section 8.1
       0x02    HELLO             Section 8.2
       0x10    PROPOSAL          Section 8.3
       0x11    APPROVAL          Section 8.4
       0x20    INTENT_ADVERTISE  Section 8.5
       0x21    INTENT_WITHDRAW   Section 8.6
       0x30    HEARTBEAT         Section 8.7
       0xF0    TEARDOWN          Section 8.8
       0x03-0x0F    Unassigned (OC)
       0x12-0x1F    Unassigned (IC)
       0x22-0x2F    Unassigned (IC)
       0x31-0xEF    Unassigned
       0xF1-0xFE    Unassigned (control)
       0xFF         Reserved (MUST NOT be used)

23.3.  VIRP Channel Identifier Registry

       Value   Name              Reference
       ──────────────────────────────────────
       0x01    Observation (OC)  Section 4.1
       0x02    Intent (IC)       Section 4.2
       0x00    Reserved
       0x03-0xFE Unassigned
       0xFF    Reserved

23.4.  VIRP Trust Tier Registry

       Value   Name              Reference
       ──────────────────────────────────────
       0x01    GREEN             Section 6.1
       0x02    YELLOW            Section 6.1
       0x03    RED               Section 6.1
       0x04-0xFE Unassigned
       0xFF    BLACK             Section 6.1

23.5.  VIRP Error Code Registry

       Value   Name                      Reference
       ─────────────────────────────────────────────
       0x0001  UNKNOWN_DEVICE            Section 13.3
       0x0002  CONNECT_FAILED            Section 13.3
       0x0003  CHANNEL_VIOLATION         Section 13.3
       0x0004  INVALID_MESSAGE           Section 13.3
       0x0005  HMAC_FAILED               Section 13.3
       0x0006  TIMEOUT                   Section 13.3
       0x0007  NO_EVIDENCE               Section 13.3
       0x0008  STALE_EVIDENCE            Section 13.3
       0x0009  VERSION_MISMATCH          Section 13.3
       0x000A  KEY_REVOKED               Section 13.3
       0x000B  TIER_VIOLATION            Section 13.3
       0x000C  REPLAY_DETECTED           Section 13.3
       0x000D-0xFFFF Unassigned

23.6.  VIRP Vendor Identifier Registry

       Value   Name              Reference
       ──────────────────────────────────────
       0x01    CISCO_IOS         Section 15.2
       0x02    FORTINET          Section 15.2
       0x03    JUNIPER           Section 15.2
       0x04    PALO_ALTO         Section 15.2
       0x05    LINUX             Section 15.2
       0x06    ARISTA            Section 15.2
       0x07    WINDOWS           Section 15.2
       0x08-0x62 Unassigned
       0x63    MOCK (testing)    Section 15.2
       0x64-0xFF Unassigned

23.7.  VIRP Port Number

   Port 8470 (TCP and UDP) is requested for VIRP REST API
   and future TCP transport binding.


24.  References

24.1.  Normative References

   [RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
              Requirement Levels", BCP 14, RFC 2119, March 1997.

   [RFC2104]  Krawczyk, H., Bellare, M., and R. Canetti, "HMAC:
              Keyed-Hashing for Message Authentication", RFC 2104,
              February 1997.

   [RFC6234]  Eastlake 3rd, D. and T. Hansen, "US Secure Hash
              Algorithms (SHA and SHA-based HMAC and HKDF)",
              RFC 6234, May 2011.

   [RFC8032]  Josefsson, S. and I. Liusvaara, "Edwards-Curve
              Digital Signature Algorithm (EdDSA)", RFC 8032,
              January 2017.

24.2.  Informative References

   [RFC4271]  Rekhter, Y., Li, T., and S. Hares, "A Border Gateway
              Protocol 4 (BGP-4)", RFC 4271, January 2006.

   [RFC2328]  Moy, J., "OSPF Version 2", RFC 2328, April 1998.

   [RFC5737]  Arkko, J., Cotton, M., and L. Vegoda, "IPv4 Address
              Blocks Reserved for Documentation", RFC 5737,
              January 2010.

   [NETCLAW]  Capobianco, J. and S. Mahoney, "NetClaw: AI Agents
              as BGP Speakers", 2025.

   [HACKERBOT-CLAW]  Multiple authors, "Analysis of Autonomous
              Agent CI/CD Exploitation", February 2026.
              Note: Autonomous bot exploiting GitHub Actions
              workflows across Microsoft, DataDog, and CNCF
              projects demonstrated the real-world threat of
              AI agents operating without verified observations.


25.  Appendix A: Test Vectors

25.1.  HMAC Signing Test Vector

   Given:
       Key (hex):    deadbeef01020304...  (32 bytes)
       Version:      0x01
       Type:         0x01 (OBSERVATION)
       Length:       72 (56 header + 16 payload)
       Channel:      0x01 (OC)
       Tier:         0x01 (GREEN)
       Timestamp:    1709312473000000000 (nanoseconds)
       Source Node:  0x00000001
       Sequence:     1
       Payload:      "show ip route\n" (16 bytes UTF-8)

   Procedure:
       1. Construct header with HMAC field zeroed
       2. Concatenate header[0:24] || payload
       3. HMAC-SHA256(key, data)
       4. Insert result at header[24:56]

   Implementations SHOULD verify their HMAC computation against
   the reference implementation test suite.

25.2.  Channel-Key Binding Test Vector

   Given:
       O-Key with channel = VIRP_CHANNEL_OC
       Message with type = VIRP_TYPE_PROPOSAL (0x10)

   Expected result:
       virp_message_sign() returns VIRP_ERR_CHANNEL_VIOLATION
       HMAC field is NOT computed (remains zeroed)

   Given:
       R-Key with channel = VIRP_CHANNEL_IC
       Message with type = VIRP_TYPE_OBSERVATION (0x01)

   Expected result:
       virp_message_sign() returns VIRP_ERR_CHANNEL_VIOLATION
       HMAC field is NOT computed (remains zeroed)

25.3.  Replay Detection Test Vector

   Given:
       Receiver's last known sequence for source 0x00000001: 500
       Incoming message: source=0x00000001, sequence=100

   Expected result:
       Message rejected (sequence gap > 1000 threshold: 400 < 1000,
       so this message is accepted; gap of 400 is within tolerance)

   Given:
       Receiver's last known sequence for source 0x00000001: 5000
       Incoming message: source=0x00000001, sequence=100

   Expected result:
       Message rejected (sequence gap = 4900 > 1000 threshold)

25.4.  Freshness Validation Test Vector

   Given:
       Freshness window: 300 seconds
       Current time: 1709312773000000000 (nanoseconds)
       Observation timestamp: 1709312473000000000

   Computed age: 300.000 seconds

   Expected result:
       Observation is at the boundary of the freshness window.
       Implementations SHOULD treat the boundary as inclusive
       (age <= freshness_window passes).


26.  Appendix B: Comparison with Existing Protocols

       Property          BGP         OSPF        SNMP        VIRP
       ─────────────────────────────────────────────────────────────
       Data basis        Reachability LSAs       Polling     Verified
                                                             observations
       Trust model       Implicit    Implicit    Community   Cryptographic
                         peer trust  area trust  strings     proof
       AI integration    None        None        Passive     First-class
       Fabrication       None        None        None        Structural
       protection
       Approval          None        None        None        Protocol-
       workflow                                              native
       Channel           No          No          No          Yes
       separation
       Key binding       N/A         N/A         N/A         Code-level
       Freshness         N/A         MaxAge      N/A         Configurable
       semantics                     (3600s)                 (30s-86400s)
       Multi-vendor      No          No          Yes         Yes
       observation

   Additional comparison with AI operations platforms:

       Property          CrowdStrike Palo Alto   Microsoft   VIRP
                         Charlotte   XSIAM       Copilot
       ─────────────────────────────────────────────────────────────
       Multi-vendor      No          Partial     Partial     Yes
       observation
       Cryptographic     No          No          No          Yes
       verification
       Fabrication       None        None        None        Structural
       protection
       Open source       No          No          No          Yes
       Trust tiers       N/A         N/A         N/A         Protocol-
                                                             native


27.  Appendix C: Future Extensions (Ed25519)

27.1.  Motivation

   The current specification uses HMAC-SHA256 (symmetric key)
   for observation signing. While HMAC-SHA256 provides strong
   authentication guarantees for single-node deployments, it
   has a structural limitation: the same key that signs also
   verifies. In multi-node deployments, distribution of
   verification keys implicitly grants signing capability.

   Ed25519 (RFC 8032) asymmetric signatures address this by
   separating signing authority (private key, held only by the
   O-Node) from verification capability (public key, distributed
   to all verifiers). This provides:

   (a) NON-REPUDIATION: A signed observation can be proven to
       originate from a specific O-Node, even if the verifier
       is fully compromised.

   (b) SAFE KEY DISTRIBUTION: Public keys can be freely
       distributed without compromising signing authority.

   (c) INDEPENDENT NODE VERIFICATION: Any entity with the
       public key can verify observations without being able
       to forge them.

27.2.  Wire Format Extension

   To support Ed25519, the following changes are anticipated
   for a future protocol version:

   (a) A signature_type field (8 bits) in the header, replacing
       one Reserved byte:
           0x01 = HMAC-SHA256 (current)
           0x02 = Ed25519

   (b) For Ed25519 signatures, the HMAC field (32 bytes)
       is replaced with the first 32 bytes of the 64-byte
       Ed25519 signature. The remaining 32 bytes are appended
       as a signature trailer between the header and payload.
       This maintains backward compatibility for parsers that
       skip the HMAC field.

   (c) HELLO messages include the Ed25519 public key (32 bytes)
       in addition to the HMAC fingerprint.

27.3.  Migration Path

   Implementations SHOULD prepare for Ed25519 support by:

   (a) Using the signature_type field in internal data
       structures even when only HMAC-SHA256 is supported
   (b) Abstracting the signing and verification functions
       behind a common interface
   (c) Supporting dual-mode operation during migration
       (accepting both HMAC-SHA256 and Ed25519 signatures)

   The migration is expected to be non-breaking: HMAC-SHA256
   implementations will continue to function and interoperate
   with Ed25519 implementations through the version negotiation

28.  Session Establishment

28.1.  Purpose

   VIRP implementations MUST establish a negotiated session before
   exchanging Observation or Intent messages. The session-establishment
   phase provides protocol version negotiation, capability negotiation,
   algorithm negotiation, and freshness binding via nonce exchange.

   This phase converts VIRP from a message-signing format into a
   stateful trust protocol. The AI node cannot receive verified
   observations until a session is cryptographically bound.

   VIRP does not let the AI speak first. Reality speaks first,
   inside a bound session.

28.2.  Session State Machine

   A VIRP session SHALL follow this state machine:

      DISCONNECTED
            |
            v
      HELLO_SENT
            |
            v
      NEGOTIATED
            |
            v
      SESSION_BOUND
            |
            v
      ACTIVE
            |
            | idle timeout / socket drop / SESSION_CLOSE
            v
      CLOSED -------------------------> DISCONNECTED

   Observation and Intent messages MUST NOT be exchanged before
   the session reaches SESSION_BOUND.

28.3.  HELLO Message

   The initiating peer (AI node) sends HELLO to advertise supported
   protocol parameters. Required fields:

      msg_type              Fixed: HELLO
      client_id             Stable identity of initiating peer
      supported_versions    Ordered list of supported VIRP versions
      supported_channels    e.g. OBSERVATION, INTENT
      supported_algorithms  e.g. HMAC-SHA256
      client_nonce          Cryptographically random freshness value
      timestamp_ns          Local send time, nanoseconds since epoch

28.4.  HELLO_ACK Message

   The O-Node selects negotiated parameters and returns HELLO_ACK.
   Required fields:

      msg_type              Fixed: HELLO_ACK
      server_id             Stable identity of O-Node
      selected_version      Negotiated protocol version
      selected_algorithm    Selected cryptographic suite
      accepted_channels     Permitted channels for this session
      session_id            Generated by O-Node (not AI node)
      client_nonce          Echo of initiator nonce
      server_nonce          Responder freshness material
      timestamp_ns          Local send time, nanoseconds since epoch

   The O-Node generates the session_id. The AI node does not.

28.5.  SESSION_BIND Message

   The AI node confirms the session by echoing session_id, client_nonce,
   and server_nonce. The O-Node verifies all three match. On success,
   the session advances to SESSION_BOUND then ACTIVE.

28.6.  Session Properties

   In-memory only: Session state is not persisted. O-Node restart
   requires fresh handshake. This is intentional.

   Single active session: A new HELLO while a session is ACTIVE is
   rejected with VIRP_ERR_SESSION_INVALID.

   Timeout enforcement: NEGOTIATED state times out after 30 seconds
   without SESSION_BIND. ACTIVE sessions idle for 5 minutes are reset.
   Socket disconnect triggers immediate forced reset to DISCONNECTED.

   Generation counter: Every session reset increments a monotonic
   generation counter. Stale session IDs cannot be replayed across
   resets.

29.  Per-Session Key Derivation

29.1.  Overview

   Following successful SESSION_BIND, the O-Node derives a per-session
   observation key from the master observation key using HKDF-SHA256.
   The master key never directly signs runtime observations.

29.2.  Derivation

   The session key is derived as follows:

      transcript_hash = SHA-256(
          serialize(HELLO) ||
          serialize(HELLO_ACK) ||
          serialize(SESSION_BIND)
      )

      session_key = HKDF-SHA256(
          ikm  = master_observation_key,
          salt = transcript_hash,
          info = generation (uint64, big-endian)
      )

   The transcript hash binds the derived key to exactly what was
   negotiated. A session key derived from a different HELLO exchange
   will be different even with the same master key.

29.3.  Properties

   The master key never signs runtime observations directly.
   Every session gets its own cryptographic context.
   The session key is zeroed with OPENSSL_cleanse() on session reset.
   Replay of stale observations from previous sessions fails because
   the session_id and generation differ.

   Security statement: This observation was signed by the O-Node
   inside this specific negotiated session, using a key that did not
   exist before the handshake and does not exist after it ends.

30.  Wire Format v2 — Context Binding

30.1.  Overview

   Wire format v2 extends the signed boundary to include device
   identity, command identity, and session context. This closes
   the attribution ambiguity present in v1 where a valid observation
   payload could theoretically be reassigned to a different device
   or command at a higher layer.

30.2.  v2 Header Structure

      typedef struct {
          uint8_t  version;           /* VIRP_VERSION_2              */
          uint8_t  channel;           /* OBSERVATION / INTENT        */
          uint8_t  tier;              /* GREEN/YELLOW/RED/BLACK      */
          uint8_t  _reserved;         /* must be zero                */
          uint64_t node_id;           /* stable O-Node identity      */
          uint64_t timestamp_ns;      /* nanoseconds since epoch     */
          uint64_t seq_num;           /* monotonically increasing    */
          uint8_t  session_id[16];    /* from SESSION_BIND           */
          uint64_t device_id;         /* stable device UUID          */
          uint8_t  command_hash[32];  /* SHA-256 of canonical command*/
          uint32_t payload_len;
      } virp_obs_header_v2_t;

30.3.  Trust Guarantee by Version

      v1: Payload authentic
          AI cannot fabricate what it observed.

      v2: Payload + context authentic
          AI cannot fabricate the source, session, or command.

   A valid v2 observation is a cryptographic commitment to:

      who collected it       (node_id)
      + which session        (session_id)
      + which device         (device_id)
      + which command        (command_hash)
      + what was returned    (payload)
      + when                 (timestamp_ns)
      + sequence position    (seq_num)

30.4.  Canonical Command Hashing

      command_hash = SHA-256(canonical_command_string)

   Canonicalization rules applied in order:
      1. Trim leading and trailing whitespace
      2. Collapse repeated spaces to single space
      3. Normalize line endings to LF
      4. Strip CLI prompts and transport-specific wrappers

30.5.  Backward Compatibility

   Nodes SHOULD accept both v1 and v2 during transition periods.
   The negotiated session version from HELLO/HELLO_ACK determines
   which guarantee applies.

   mechanism (Section 18).


31.  Author's Address

   Nate Howard
   Third Level IT LLC
   Allen Park, Michigan
   United States of America

   Email: nhoward@thirdlevelit.com
   Web:   https://thirdlevel.ai
   Code:  https://github.com/nhowardtli/virp
```
