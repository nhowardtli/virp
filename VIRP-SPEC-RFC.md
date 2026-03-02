```
VIRP                                                        N. Howard
Internet-Draft                                       Third Level IT LLC
Category: Experimental                                    March 1, 2026
Expires: September 1, 2026


        Verified Intent Routing Protocol (VIRP) Specification
                        draft-howard-virp-00

Abstract

   This document specifies the Verified Intent Routing Protocol (VIRP),
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
   6.  Trust Tier System ...........................................  9
   7.  Message Format .............................................. 11
   8.  Message Types ............................................... 14
   9.  Observation Sub-Header ...................................... 19
  10.  HMAC Construction ........................................... 20
  11.  O-Node Operation ............................................ 22
  12.  R-Node Operation ............................................ 24
  13.  Socket Protocol ............................................. 25
  14.  REST API Binding ............................................ 27
  15.  Device Driver Interface ..................................... 29
  16.  Security Considerations ..................................... 31
  17.  IANA Considerations ......................................... 34
  18.  References .................................................. 35
  19.  Appendix A: Test Vectors .................................... 36
  20.  Appendix B: Comparison with Existing Protocols .............. 38
  21.  Author's Address ............................................ 39


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

   YELLOW (0x02) - Active diagnostics, minimal state change:
       - debug ip bgp updates (temporary)
       - show tech-support (resource intensive)
       - test ip route
       - ping / traceroute (generates traffic)

   RED (0x03) - Configuration changes, state modification:
       - configure terminal (any config mode entry)
       - ip route (static route changes)
       - router bgp / router ospf (protocol changes)
       - interface shutdown / no shutdown
       - access-list modifications
       - write memory / copy running startup

   BLACK (0xFF) - Destructive, irreversible, or trust-breaking:
       - Key deletion or modification
       - Approval bypass
       - Factory reset
       - Disabling the observation channel
       - Modifying the trust tier assignments

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
           Bits 3-7: Reserved, MUST be zero

   Reserved (24 bits):
       Reserved for future use. MUST be set to zero on transmission.
       Implementations MUST reject messages with non-zero reserved
       fields to prevent protocol confusion attacks.

   Timestamp (64 bits, network byte order):
       Nanoseconds since Unix epoch (January 1, 1970 00:00:00 UTC).
       Implementations SHOULD reject observations with timestamps
       more than 300 seconds from the local clock to prevent
       replay attacks.

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
       Bits 6-31: Reserved

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
   2. Construct the PROPOSAL with evidence references
   3. Sign with R-Key
   4. Submit for approval per the tier requirements

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
               "hmac": "a3b4c5d6..."
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
       FORTINET        0x02    Planned
       JUNIPER         0x03    Planned
       PALO_ALTO       0x04    Planned
       LINUX           0x05    Planned
       ARISTA          0x06    Planned
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


16.  Security Considerations

16.1.  Threat Model

   VIRP assumes the following threat model:

   (a) TRUSTED: The O-Node process and its host operating system.
       The O-Node has physical or network access to managed devices
       and holds the O-Key.

   (b) UNTRUSTED: The R-Node (AI system). The R-Node may
       fabricate observations, propose unauthorized changes, or
       attempt to forge signatures. VIRP structurally prevents
       these actions.

   (c) UNTRUSTED: The network between O-Node and R-Node. Messages
       may be intercepted, replayed, or modified. HMAC signatures
       detect modification. Sequence numbers detect replay.
       Timestamps detect delayed replay.

16.2.  Fabrication Resistance

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

16.3.  Replay Protection

   Replay attacks are mitigated by:

   (a) SEQUENCE NUMBERS: Monotonically increasing per source node.
       Receivers track the last seen sequence and reject messages
       significantly behind the current value.

   (b) TIMESTAMPS: Nanosecond-precision timestamps allow receivers
       to reject observations that are too old (recommended
       threshold: 300 seconds).

   (c) SESSION BINDING: In the TLI implementation, session IDs
       are embedded in execution contexts, preventing cross-session
       replay.

16.4.  Timing Attacks

   HMAC verification uses constant-time comparison
   (CRYPTO_memcmp or equivalent) to prevent timing side-channel
   attacks that could leak information about the expected HMAC
   value.

16.5.  Key Compromise

   If an O-Key is compromised, an attacker can forge observations.
   Mitigations:

   (a) Key material should be stored in TPM/HSM when available.
   (b) Key rotation should be performed regularly.
   (c) Anomaly detection on observation patterns can identify
       forged observations (e.g., observations from devices that
       are physically disconnected).

   If an R-Key is compromised, an attacker can forge proposals
   but cannot forge observations. Proposals still require
   approval (YELLOW/RED tier) before execution.

16.6.  Denial of Service

   An attacker with access to the O-Node socket can flood it
   with requests. Implementations SHOULD implement:

   (a) Rate limiting on the socket listener
   (b) Maximum concurrent connection limits
   (c) Request timeout enforcement

16.7.  Physical Kill Switch

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


17.  IANA Considerations

   This document defines the following values that would require
   IANA registration if VIRP is standardized:

   (a) VIRP Message Types (Section 8)
   (b) VIRP Channel Identifiers (Section 4)
   (c) VIRP Trust Tier Values (Section 6)
   (d) VIRP Error Codes (Section 13)
   (e) VIRP Vendor Identifiers (Section 15)
   (f) VIRP Port Number: 8470 (TCP and UDP)

   No IANA registration is requested at this time. This document
   is published as an experimental protocol specification.


18.  References

18.1.  Normative References

   [RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
              Requirement Levels", BCP 14, RFC 2119, March 1997.

   [RFC2104]  Krawczyk, H., Bellare, M., and R. Canetti, "HMAC:
              Keyed-Hashing for Message Authentication", RFC 2104,
              February 1997.

   [RFC6234]  Eastlake 3rd, D. and T. Hansen, "US Secure Hash
              Algorithms (SHA and SHA-based HMAC and HKDF)",
              RFC 6234, May 2011.

18.2.  Informative References

   [RFC4271]  Rekhter, Y., Li, T., and S. Hares, "A Border Gateway
              Protocol 4 (BGP-4)", RFC 4271, January 2006.

   [RFC2328]  Moy, J., "OSPF Version 2", RFC 2328, April 1998.

   [RFC5737]  Arkko, J., Cotton, M., and L. Vegoda, "IPv4 Address
              Blocks Reserved for Documentation", RFC 5737,
              January 2010.

   [NETCLAW]  Capobianco, J. and S. Mahoney, "NetClaw: AI Agents
              as BGP Speakers", 2025.


19.  Appendix A: Test Vectors

19.1.  HMAC Signing Test Vector

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
   the reference implementation test suite (42 tests).

19.2.  Channel-Key Binding Test Vector

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


20.  Appendix B: Comparison with Existing Protocols

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


21.  Author's Address

   Nate Howard
   Third Level IT LLC
   Southfield, Michigan
   United States of America

   Email: nhoward@thirdlevelit.com
   Web:   https://thirdlevel.ai
   Code:  https://github.com/nhowardtli/virp
```
