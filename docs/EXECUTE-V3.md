# Execute observations under v3 Ed25519

The production daemon's opt-in `-3` switch requires `-S` and uses that
node-local chain signing key for execute observations. Chain entry canonical
bytes and VIRP-CHAIN-ENTRY-SIG-v1 are unchanged. Requests may also explicitly
select obs_version 3. Legacy deployments and v1/v2 verification remain supported.

Execute v3 requires an active bound session and matching observation/chain
public keys before dispatch. No v1 fallback is returned. A session reset during
dispatch prevents signing the result under the replacement session.

The signed payload profile is `VIRP-XO1` (eight ASCII bytes), followed by the
existing observation subheader: type (one byte), scope (one byte), body length
(big-endian uint16), and body. DEVICE_OUTPUT (7) and ERROR (15) are distinct
signed types; device text beginning ERROR cannot impersonate a gate rejection.
The framing, command hash, session HMAC, and detached Ed25519 signature follow
the existing v3 wire format. Untyped historical v3 payloads remain readable.
The profile discriminator is reserved for this new execute producer.

Reusing a consumed approval records gate_rejection/1 with error_code -37,
approval_id, proposal_id and original_outcome_id before returning refusal.
If an intent exists without an outcome (for example after a crash), the original
outcome is explicitly null with outcome_status not_recorded. It never invents
a successful outcome. Earlier artifacts are not rewritten.

The execute response is an observation frame, not an automatic chain append.
Clients must persist it through the existing observation append operation to
include its exact bytes in an export. Existing artifact-size limits still apply.
The canary qualification must verify both emitted frames and stored artifacts.

Validation in progress: test_execute_v3, approval-consumption regression,
Python typed-payload and historical v3 vector tests. No production deployment
or clean-machine VERIFIED acceptance is claimed by this document.
