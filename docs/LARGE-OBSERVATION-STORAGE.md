# Bounded full observation storage

Signed observation/fed_observation bodies may carry one full wire frame up to
65536 bytes, encoded as base64: plus at most87384 base64 characters. The daemon
request ceiling is131072 bytes. Other artifact types retain8191 bytes. Hash
binding and existing v1/v2/v3 signature gates precede storage; no unsigned-body
exception or new wire/chain format is introduced.

The helper retains exact raw bytes before append. Frames over65536 bytes fail
closed. Append errors retain the pending attempt and do not retry execution.

Verification hashes complete bodies before grading historical truncation.
A mismatching body exactly8191 bytes long remains legacy UNVERIFIABLE (the old
truncating field's maximum); a larger mismatching body is FAIL. A matching body
of any length is bound. Missing-body and indirect commitments retain their
existing grades. The unsigned legacy truncation ambiguity at exactly8191 bytes
remains a limitation, not proof that truncation actually occurred.

Existing producers that intentionally submit commitment-only records retain
their behavior and unverifiable grade. Historical oversized unlinked captures
are not backfilled or re-signed by this change. Deployment requires the matching
daemon and helper, canary proof and clean public verifier0.1.3 compatibility.
