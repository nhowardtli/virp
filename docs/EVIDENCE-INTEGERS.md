# Evidence integers on the wire

**An evidence integer that may exceed 2^53 travels as a DECIMAL STRING.**

JSON has one number type and every mainstream parser decodes it to an
IEEE-754 double. A double represents integers exactly only up to
2^53 = 9,007,199,254,740,992. Nanosecond timestamps are around
1.79 x 10^18, two orders of magnitude past that.

Measured on the real parse paths, 2026-09-06:

| language | in | out | delta |
|---|---|---|---|
| C, cJSON `valuedouble` | `1788722800424766173` | `1788722800424766208` | +35 ns |
| Python, `int(float(x))` | `1788722800424766173` | `1788722800424766208` | +35 ns |

Thirty-five nanoseconds is not a rounding detail when the number is
inside a signature payload, a match window, or an expiry.

## The rule

**Producers** emit any of these as a decimal string:

- anything named `*_ns`
- large counters
- sequence values and offsets that can grow past 2^53

**Consumers**:

- accept a decimal string ALWAYS. This is the required form.
- accept a JSON number ONLY when its value is strictly inside
  ±2^53. Strictly, not up to: the literal `2^53 + 1` decodes to exactly
  `2^53`, and it is the one value a `<=` test would let through as
  "safe". Every other integer above 2^53 rounds to something strictly
  greater and is caught by the bound itself. The cost is the single
  value `2^53`, which the rule says to send as a string anyway.
- REJECT a larger numeric literal with an explicit error. **Never
  truncate, never round, never silently accept the decoded value.** A
  wrong number that looks precise is worse than a refusal.

## Where it is enforced

| place | what |
|---|---|
| `src/virp_onode.c` `json_extract_int64_cjson` | the ingress. Accepts a decimal string exactly; accepts a number only strictly inside ±2^53; refuses everything else. Every consumer of `expires_at_ns`, `from_sequence`, `to_sequence`, `obs_version`, `max_commands` and `supported_channels` inherits it, because they all go through `json_extract_u64_bounded`. |
| `src/virp_approval.c` `jadd_u64str` / `jget_u64str` | the producing half, correct since the approval flow shipped: `approved_at_ns` has always been written as a decimal string, with the reason stated in a comment. This document generalises that decision rather than inventing it. |
| `tacacs/virp_tacacs_policy.py` `evidence_int()` | the policy compiler. Accepts an int or a decimal string; accepts a float only inside the safe range; raises otherwise, and `compile_grants` turns the raise into a refusal with a reason rather than a grant built on a wrong timestamp. |
| `tests/test_json_hygiene.c` | pins all of it, through the real `parse_request()`. |

Python's `json` module parses integer literals as arbitrary-precision
`int`, so a Python consumer that never touches `float` is already exact.
That is a property of one language and not a substitute for the wire
rule: the Go verifier and every JavaScript reader decode to a double.

## What is NOT covered, and why

**Fields inside the canonical object keep their current serialization.**
`timestamp_ns` and `monotonic_ns` are JSON numbers in
`build_canonical_json` (`src/virp_chain.c`). Changing that changes the
canonical bytes of every entry ever written. It belongs in
`docs/CANONICAL-FORMAT-WINDOW.md`, not here. The C producer and both
verifiers build those bytes with integer formatting (`%llu`), never via a
double, so the canonical form itself is exact today; the hazard is only
in a consumer that re-parses it with a double-based JSON reader, and that
consumer must use the rule above.

**`tacacs_accounting/1` and `/2` bodies carry `recv_utc_ns` and
`recv_monotonic_ns` as JSON numbers.** `/2` is defined as `/1` plus three
signature fields and nothing else, so changing their serialization inside
`/2` would break that contract. Python signs and verifies these bodies
with exact integer parsing, so nothing is wrong today. Converting them to
decimal strings is a `/3` change and is noted as a follow-up.
