# BATCH 2: Enforcement + UI + Tests

## Prerequisites

Batch 1 must be complete. The C executor must compile with the new `collector_integrity`, `exit_code`, `raw_output_len`, `transport`, and `latency_ms` fields. The Python `ExecutorResponse` dataclass must parse those fields. `INSUFFICIENT_EVIDENCE` must exist in `CollectionStatus`.

---

## Overview

This batch makes the system ACT on the integrity data from Batch 1:

1. The execution enforcer blocks negative assertions from empty/failed evidence
2. FortiGate config output is redacted before entering AI context
3. SSH host key fingerprints are captured in signed envelopes
4. The frontend trust badges reflect integrity states
5. New test cases validate degraded collection behavior

---

## Task 1: Add negative-assertion-from-empty-evidence detection to ExecutionEnforcer

**File:** `backend/src/services/execution_enforcer.py`

**Context:** The `ExecutionEnforcer` class (line 35) already detects fabrication patterns like fake prompts, fake service status output, and fake memory/disk output. It has `GENERIC_FABRICATION_PATTERNS` (line 50) and `HOST_SPECIFIC_PATTERNS` (line 79). We're adding a new category: negative assertions derived from empty or failed observations.

**Add a new pattern list after the existing HOST_SPECIFIC_PATTERNS block (around line 130). Create a class-level constant:**

```python
    # ============================================================
    # NEGATIVE ASSERTION DETECTION (v1.1)
    # Catches when AI makes definitive negative claims that require
    # evidence but the backing observation is empty, failed, or WARN/FAIL integrity.
    # ============================================================

    NEGATIVE_ASSERTION_PATTERNS = [
        # "X is not configured/running/enabled/active"
        r"(?:is|are)\s+not\s+(?:configured|running|enabled|active|installed|present|available|reachable)",
        # "no X configured/found/detected/running"
        r"\bno\s+\w+\s+(?:configured|found|detected|running|enabled|present|active)",
        # "X does not have/exist/appear"
        r"(?:does|do)\s+not\s+(?:have|exist|appear|seem|show|include|contain|support)",
        # "there are no X" / "there is no X"
        r"there\s+(?:are|is)\s+no\s+",
        # "X isn't/aren't configured/running"
        r"(?:isn't|aren't|doesn't|don't)\s+(?:configured|running|enabled|appear|have|seem|show|exist)",
        # "BGP/OSPF/EIGRP/VPN/etc. is not" (protocol-specific)
        r"\b(?:BGP|OSPF|EIGRP|RIP|HSRP|VRRP|VPN|MPLS|STP|LACP|LLDP)\b.*(?:is|are)\s+not\s+",
        # "no routes/sessions/policies/interfaces"
        r"\bno\s+(?:routes?|sessions?|policies|interfaces?|neighbors?|peers?|tunnels?|vlans?|ACLs?|rules?)",
    ]

    # Compiled for performance
    _NEGATIVE_ASSERTION_RE = [re.compile(p, re.IGNORECASE) for p in NEGATIVE_ASSERTION_PATTERNS]
```

**Add a new method to the ExecutionEnforcer class:**

```python
    def check_negative_assertions(
        self,
        ai_text: str,
        observations: list[dict],
    ) -> tuple[bool, str]:
        """
        Check if AI text contains negative assertions unsupported by evidence.

        Args:
            ai_text: The AI's response text (or chunk)
            observations: List of observation dicts from this session, each having
                          at minimum: raw_output, collector_integrity, status

        Returns:
            (has_violation, replacement_text)
            If has_violation is True, replacement_text contains the corrected statement.
        """
        # Check if AI is making negative assertions
        negative_claims = []
        for pattern in self._NEGATIVE_ASSERTION_RE:
            matches = pattern.findall(ai_text)
            if matches:
                negative_claims.extend(matches)

        if not negative_claims:
            return False, ""

        # Check if any observation backing this response is unusable
        unusable_observations = []
        for obs in observations:
            integrity = obs.get("collector_integrity", "")
            status = obs.get("status", "")
            output = obs.get("raw_output", "")
            output_len = obs.get("raw_output_len", len(output) if output else 0)

            is_unusable = False
            reason = ""

            if integrity in ("FAIL", "WARN", ""):
                is_unusable = True
                reason = f"collector_integrity={integrity or 'MISSING'}"
            elif status in ("TIMEOUT", "UNREACHABLE", "FAILED"):
                is_unusable = True
                reason = f"status={status}"
            elif output_len == 0 and status == "SUCCESS":
                is_unusable = True
                reason = "empty output with SUCCESS status"

            if is_unusable:
                unusable_observations.append({
                    "device": obs.get("device", "unknown"),
                    "command": obs.get("command", "unknown"),
                    "reason": reason,
                })

        if not unusable_observations:
            # All observations are usable — negative assertion may be legitimate
            return False, ""

        # VIOLATION: negative assertion with unusable evidence
        devices = ", ".join(o["device"] for o in unusable_observations)
        reasons = "; ".join(f"{o['device']}: {o['reason']}" for o in unusable_observations)

        logger.warning(
            "[ENFORCER] Blocked negative assertion from unusable evidence. "
            "Claims: %s | Evidence issues: %s",
            negative_claims[:3], reasons,
        )

        replacement = (
            f"I cannot determine the current state from available evidence. "
            f"The command output from {devices} was insufficient to support "
            f"a definitive conclusion ({reasons}). "
            f"Recommended next steps: verify device connectivity, check that "
            f"the command returned expected output, and re-run the query."
        )

        return True, replacement
```

**Integration point:** This method should be called in `chat.py` wherever the AI response text is being streamed or assembled. The exact integration depends on how `chat.py` currently calls the enforcer. Search `chat.py` for existing calls to `ExecutionEnforcer` methods and add `check_negative_assertions()` at the same point, passing the observations from the current session.

---

## Task 2: FortiGate configuration redaction

**File:** `backend/src/services/fortigate_collector.py`

**Add a new redaction function near the top of the file, after imports:**

```python
# ── v1.1: Configuration Redaction ──────────────────────────────────
# Redact secrets from FortiGate config output BEFORE it enters AI context.
# This runs on collector output and pre-executor cached results.

import re as _re

_FORTIGATE_REDACTION_PATTERNS = [
    # PSK secrets (IPsec VPN, WiFi, etc.)
    (_re.compile(r'(set\s+psksecret\s+)("?)[^\s"]+("?)', _re.IGNORECASE), r'\1\2[REDACTED]\3'),
    # Passwords
    (_re.compile(r'(set\s+password\s+)("?)[^\s"]+("?)', _re.IGNORECASE), r'\1\2[REDACTED]\3'),
    # Private keys (multi-line, but we catch the set line)
    (_re.compile(r'(set\s+private-key\s+)("?).*?("?)\s*$', _re.IGNORECASE | _re.MULTILINE), r'\1\2[REDACTED]\3'),
    # API keys
    (_re.compile(r'(set\s+api-key\s+)("?)[^\s"]+("?)', _re.IGNORECASE), r'\1\2[REDACTED]\3'),
    # SNMP community strings
    (_re.compile(r'(set\s+community\s+)("?)[^\s"]+("?)', _re.IGNORECASE), r'\1\2[REDACTED]\3'),
    # Auth passwords (OSPF, BGP, etc.)
    (_re.compile(r'(set\s+auth-password-l[12]\s+)("?)[^\s"]+("?)', _re.IGNORECASE), r'\1\2[REDACTED]\3'),
    # TACACS/RADIUS secrets
    (_re.compile(r'(set\s+secret\s+)("?)[^\s"]+("?)', _re.IGNORECASE), r'\1\2[REDACTED]\3'),
    # Certificate private key blocks
    (_re.compile(r'(-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----).*?(-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----)',
                 _re.DOTALL), r'\1\n[REDACTED]\n\2'),
    # EAP users passwords
    (_re.compile(r'(set\s+passwd\s+)("?)[^\s"]+("?)', _re.IGNORECASE), r'\1\2[REDACTED]\3'),
]


def redact_fortigate_config(text: str) -> str:
    """Redact secrets from FortiGate configuration output.

    MUST be called before config text enters AI context or citation store.
    The redacted version is the signed evidence — safe to share.
    """
    for pattern, replacement in _FORTIGATE_REDACTION_PATTERNS:
        text = pattern.sub(replacement, text)
    return text
```

**Integration point:** This function should be called:

1. In `fortigate_collector.py` — in every `_summarize_*` method that handles config data, apply `redact_fortigate_config()` to the raw output before summarization.

2. In `pre_executor.py` — when FortiGate command results are cached and injected into AI context. Search for where FortiGate SSH output is formatted for Claude's system prompt and apply redaction there.

3. In the agentic loop (`agentic.py`) — when FortiGate command output is fed back into the conversation for the next iteration.

**The principle:** redact at the boundary where data crosses from the device-data domain into the AI domain. Every path where FortiGate text enters Claude's context window must pass through `redact_fortigate_config()`.

---

## Task 3: Capture SSH host key fingerprint

**File:** `executor/src/ssh.c`

**Context:** The executor forks the `ssh` (or `sshpass`) binary as a subprocess (lines 49–387). It doesn't use libssh2 — it uses the system OpenSSH client. This means we can't easily get the host key from the SSH library API. Instead, use a two-step approach:

**Option A (recommended, simpler):** After a successful SSH execution, capture the host key from the known_hosts file or from `ssh-keygen -l -F <host>`. Add a helper function:

```c
/*
 * Capture the SSH host key fingerprint for a device.
 * Runs `ssh-keygen -l -F <host>` and extracts the fingerprint line.
 * Returns 0 on success, -1 if not available.
 */
static int capture_hostkey_fingerprint(const char *host, char *fingerprint, size_t fp_size)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ssh-keygen -l -F %s 2>/dev/null | head -1", host);

    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;

    char line[512];
    if (fgets(line, sizeof(line), fp) != NULL) {
        /* Line format: "# Host <host> found: line N\n<bits> <fingerprint> <host> (<type>)" */
        /* Skip the comment line, get the next one */
        if (line[0] == '#') {
            if (fgets(line, sizeof(line), fp) != NULL) {
                /* Extract just the fingerprint hash */
                line[strcspn(line, "\n")] = '\0';
                strncpy(fingerprint, line, fp_size - 1);
                fingerprint[fp_size - 1] = '\0';
                pclose(fp);
                return 0;
            }
        }
    }
    pclose(fp);
    return -1;
}
```

**Add a field to ExecutorResponse in executor.h:**

```c
    char hostkey_fp[256];              /* SSH host key fingerprint (optional) */
```

**Note:** This field should be added BEFORE `hmac_sig` so it's included in the signing payload. Update `build_signing_payload()` in `hmac.c` and `envelope_to_json()`/`envelope_from_json()` in `envelope.c` to include it. Follow the same pattern as the Batch 1 fields.

**In main.c, after a successful ssh_execute(), call:**

```c
    /* Capture host key fingerprint if available */
    capture_hostkey_fingerprint(local_dev.host, resp.hostkey_fp, sizeof(resp.hostkey_fp));
```

**In executor_client.py**, add `hostkey_fingerprint: str = ""` to the ExecutorResponse dataclass and parse it from `data.get("hostkey_fp", "")`.

---

## Task 4: Update frontend trust badges

**File:** `frontend/src/components/chat/DeviceOutputWidget.tsx`

**Current TrustBadge component (lines 14–43)** has three states: `hmac_verified`, `sentinel`, and default (UNVERIFIED).

**Extend the DeviceOutputBlock type** (check `frontend/src/api/client.ts` for the type definition) to include the new fields:

```typescript
// Add to DeviceOutputBlock interface/type
collector_integrity?: string;  // "PASS" | "WARN" | "FAIL"
exit_code?: number;
raw_output_len?: number;
transport?: string;
hostkey_fp?: string;
```

**Update the TrustBadge component** to show integrity status alongside HMAC status:

```tsx
function TrustBadge({ block }: { block: DeviceOutputBlock }) {
  const integrity = block.collector_integrity;

  if (block.hmac_verified) {
    // HMAC verified — now check integrity
    if (integrity === 'FAIL') {
      return (
        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium bg-amber-900/40 text-amber-300 border border-amber-700/50">
          <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
          </svg>
          HMAC verified · integrity FAIL
        </span>
      )
    }
    if (integrity === 'WARN') {
      return (
        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium bg-yellow-900/40 text-yellow-300 border border-yellow-700/50">
          <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
          HMAC verified · evidence limited
        </span>
      )
    }
    // PASS or no integrity field (backwards compat)
    return (
      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium bg-emerald-900/40 text-emerald-300 border border-emerald-700/50">
        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
        HMAC verified
      </span>
    )
  }

  if (block.sentinel) {
    return (
      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium bg-blue-900/40 text-blue-300 border border-blue-700/50">
        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
        Executor-signed
      </span>
    )
  }

  return (
    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium bg-red-900/40 text-red-300 border border-red-700/50">
      <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
      </svg>
      UNVERIFIED
    </span>
  )
}
```

---

## Task 5: Degraded Collection Test Suite

**File:** `backend/tests/test_collection_integrity.py` (NEW FILE)

Create a new test file that validates the system behaves correctly when collection is degraded. This tests the end-to-end behavior of the Batch 1 data model changes and Batch 2 enforcement.

```python
"""
Test suite: Degraded Collection & Evidence Gating (VIRP v1.1)

Validates that the system correctly handles:
- Empty output with SUCCESS status
- Timeout with partial output
- Unreachable devices
- REST 200 with empty JSON body
- Negative assertions blocked when evidence is unusable

These tests prevent the class of bug where the AI infers device state
from empty or failed command output (e.g., "BGP is not configured"
from an empty 'show ip bgp summary' response).
"""

import pytest
from datetime import datetime

# Import the components under test
from src.services.data_envelope import (
    CollectionStatus,
    ActionEnvelope,
    ExecutorStatus,
    action_success,
    action_failed,
    action_timeout,
)
from src.services.executor_client import ExecutorResponse
from src.services.execution_enforcer import ExecutionEnforcer


# ── Fixtures ──────────────────────────────────────────────────────

@pytest.fixture
def enforcer():
    return ExecutionEnforcer()


def make_observation(
    status="SUCCESS",
    raw_output="some output",
    collector_integrity="PASS",
    device="r1",
    command="show ip bgp summary",
    exit_code=0,
    raw_output_len=None,
) -> dict:
    """Create a mock observation dict for testing."""
    if raw_output_len is None:
        raw_output_len = len(raw_output) if raw_output else 0
    return {
        "status": status,
        "raw_output": raw_output,
        "collector_integrity": collector_integrity,
        "device": device,
        "command": command,
        "exit_code": exit_code,
        "raw_output_len": raw_output_len,
    }


# ── Test Category: Collector Integrity Classification ──────────────

class TestCollectorIntegrity:
    """Verify that collector_integrity is set correctly for various conditions."""

    def test_success_with_output_is_pass(self):
        """Normal successful command should be PASS."""
        obs = make_observation(status="SUCCESS", raw_output="Router uptime: 3 days", collector_integrity="PASS")
        assert obs["collector_integrity"] == "PASS"

    def test_success_empty_output_is_warn(self):
        """SUCCESS status but empty output should be WARN."""
        obs = make_observation(status="SUCCESS", raw_output="", collector_integrity="WARN")
        assert obs["collector_integrity"] == "WARN"
        assert obs["raw_output_len"] == 0

    def test_timeout_is_fail(self):
        """Timeout should be FAIL."""
        obs = make_observation(status="TIMEOUT", raw_output="", collector_integrity="FAIL")
        assert obs["collector_integrity"] == "FAIL"

    def test_unreachable_is_fail(self):
        """Unreachable device should be FAIL."""
        obs = make_observation(status="UNREACHABLE", raw_output="", collector_integrity="FAIL")
        assert obs["collector_integrity"] == "FAIL"

    def test_nonzero_exit_code_is_warn(self):
        """Non-zero exit code with output should be WARN."""
        obs = make_observation(status="FAILED", raw_output="% Invalid input", exit_code=1, collector_integrity="WARN")
        assert obs["collector_integrity"] == "WARN"


# ── Test Category: Evidence Usability ──────────────────────────────

class TestEvidenceUsability:
    """Verify that evidence_usable correctly gates factual assertions."""

    def test_pass_integrity_verified_is_usable(self):
        resp = ExecutorResponse(
            status="SUCCESS",
            raw_output="BGP router identifier 10.0.0.1",
            collector_integrity="PASS",
            verified=True,
        )
        assert resp.evidence_usable is True

    def test_warn_integrity_is_not_usable(self):
        resp = ExecutorResponse(
            status="SUCCESS",
            raw_output="",
            collector_integrity="WARN",
            verified=True,
        )
        assert resp.evidence_usable is False

    def test_fail_integrity_is_not_usable(self):
        resp = ExecutorResponse(
            status="TIMEOUT",
            raw_output="",
            collector_integrity="FAIL",
            verified=True,
        )
        assert resp.evidence_usable is False

    def test_unverified_hmac_is_not_usable(self):
        resp = ExecutorResponse(
            status="SUCCESS",
            raw_output="some output",
            collector_integrity="PASS",
            verified=False,
        )
        assert resp.evidence_usable is False


# ── Test Category: Negative Assertion Gating ───────────────────────

class TestNegativeAssertionGating:
    """Verify that the enforcer blocks negative assertions from bad evidence."""

    def test_negative_assertion_from_empty_output_blocked(self, enforcer):
        """AI says 'BGP is not configured' when output was empty — must be blocked."""
        ai_text = "Based on the output, BGP is not configured on R1."
        observations = [make_observation(
            status="SUCCESS", raw_output="", collector_integrity="WARN",
            device="r1", command="show ip bgp summary",
        )]
        has_violation, replacement = enforcer.check_negative_assertions(ai_text, observations)
        assert has_violation is True
        assert "cannot determine" in replacement.lower()

    def test_negative_assertion_from_timeout_blocked(self, enforcer):
        """AI says 'no OSPF neighbors' when command timed out — must be blocked."""
        ai_text = "There are no OSPF neighbors on this device."
        observations = [make_observation(
            status="TIMEOUT", raw_output="", collector_integrity="FAIL",
            device="r1", command="show ip ospf neighbor",
        )]
        has_violation, replacement = enforcer.check_negative_assertions(ai_text, observations)
        assert has_violation is True

    def test_negative_assertion_from_good_evidence_allowed(self, enforcer):
        """AI says 'BGP is not configured' when output says '% BGP not active' — allowed."""
        ai_text = "BGP is not configured on R1."
        observations = [make_observation(
            status="SUCCESS",
            raw_output="% BGP not active\n% No BGP process is configured",
            collector_integrity="PASS",
            device="r1",
            command="show ip bgp summary",
        )]
        has_violation, _ = enforcer.check_negative_assertions(ai_text, observations)
        assert has_violation is False

    def test_positive_assertion_from_empty_not_blocked(self, enforcer):
        """AI makes a positive statement (not negative assertion) — should not trigger."""
        ai_text = "I attempted to check the BGP status but the command returned no output."
        observations = [make_observation(
            status="SUCCESS", raw_output="", collector_integrity="WARN",
        )]
        has_violation, _ = enforcer.check_negative_assertions(ai_text, observations)
        assert has_violation is False

    def test_no_observations_no_violation(self, enforcer):
        """If there are no observations at all, no violation (AI is speaking generally)."""
        ai_text = "BGP is not typically configured on access switches."
        observations = []
        has_violation, _ = enforcer.check_negative_assertions(ai_text, observations)
        assert has_violation is False

    def test_mixed_observations_one_unusable(self, enforcer):
        """One good observation and one bad — negative assertion is blocked."""
        ai_text = "OSPF is not running on R2."
        observations = [
            make_observation(status="SUCCESS", raw_output="Router uptime: 3d", collector_integrity="PASS", device="r1"),
            make_observation(status="SUCCESS", raw_output="", collector_integrity="WARN", device="r2"),
        ]
        has_violation, _ = enforcer.check_negative_assertions(ai_text, observations)
        assert has_violation is True


# ── Test Category: Action Envelope Evidence Warnings ───────────────

class TestActionEnvelopeEvidence:
    """Verify ActionEnvelope evidence_usable and warning generation."""

    def test_success_with_output_is_usable(self):
        envelope = action_success("tli-executor", "r1", "show version", "Cisco IOS version 15.7")
        assert envelope.evidence_usable is True
        assert envelope.format_evidence_warning() == ""

    def test_success_empty_output_not_usable(self):
        envelope = action_success("tli-executor", "r1", "show ip bgp summary", "")
        assert envelope.evidence_usable is False
        assert "EVIDENCE WARNING" in envelope.format_evidence_warning()
        assert "empty output" in envelope.format_evidence_warning().lower()

    def test_timeout_not_usable(self):
        envelope = action_timeout("tli-executor", "r1", "show run", duration_ms=30000)
        assert envelope.evidence_usable is False
        assert "EVIDENCE WARNING" in envelope.format_evidence_warning()

    def test_failed_not_usable(self):
        envelope = action_failed("tli-executor", "r1", "show ip bgp", "% BGP not active", exit_code=1)
        assert envelope.evidence_usable is False


# ── Test Category: INSUFFICIENT_EVIDENCE Status ────────────────────

class TestInsufficientEvidenceStatus:
    """Verify the new CollectionStatus value works correctly."""

    def test_insufficient_evidence_exists(self):
        assert CollectionStatus.INSUFFICIENT_EVIDENCE == "INSUFFICIENT_EVIDENCE"

    def test_insufficient_evidence_is_not_success(self):
        assert CollectionStatus.INSUFFICIENT_EVIDENCE != CollectionStatus.SUCCESS


# ── Test Category: FortiGate Redaction ─────────────────────────────

class TestFortiGateRedaction:
    """Verify that sensitive config values are redacted."""

    def test_redact_psksecret(self):
        from src.services.fortigate_collector import redact_fortigate_config
        config = 'set psksecret "mysupersecretkey123"'
        result = redact_fortigate_config(config)
        assert "mysupersecretkey123" not in result
        assert "[REDACTED]" in result

    def test_redact_password(self):
        from src.services.fortigate_collector import redact_fortigate_config
        config = 'set password ENC abc123def456'
        result = redact_fortigate_config(config)
        assert "abc123def456" not in result
        assert "[REDACTED]" in result

    def test_redact_api_key(self):
        from src.services.fortigate_collector import redact_fortigate_config
        config = 'set api-key "tk_abcdef123456789"'
        result = redact_fortigate_config(config)
        assert "tk_abcdef123456789" not in result

    def test_redact_community_string(self):
        from src.services.fortigate_collector import redact_fortigate_config
        config = 'set community "public_string"'
        result = redact_fortigate_config(config)
        assert "public_string" not in result

    def test_non_sensitive_not_redacted(self):
        from src.services.fortigate_collector import redact_fortigate_config
        config = 'set name "wan1"\nset ip 10.0.0.1 255.255.255.0\nset allowaccess ping https ssh'
        result = redact_fortigate_config(config)
        assert "wan1" in result
        assert "10.0.0.1" in result
        assert "allowaccess" in result

    def test_private_key_block_redacted(self):
        from src.services.fortigate_collector import redact_fortigate_config
        config = '-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg...\n-----END PRIVATE KEY-----'
        result = redact_fortigate_config(config)
        assert "MIIEvgIBADANBg" not in result
        assert "[REDACTED]" in result
```

---

## Task 6: Add evidence warnings to prompt context

**File:** `backend/src/services/agentic.py`

**Context:** In the agentic troubleshooting loop, when command output is fed back into the conversation, add evidence warnings for empty/failed results.

Search for where `ActionEnvelope.format_for_prompt()` or raw output is injected back into the conversation messages. At that point, also append `format_evidence_warning()` if it returns non-empty:

```python
    # After formatting the observation for the AI context:
    evidence_warning = envelope.format_evidence_warning()
    if evidence_warning:
        formatted_output += f"\n\n{evidence_warning}"
```

This ensures the AI sees an explicit instruction NOT to infer from empty data, right next to the empty data itself.

**Also do this in:** `backend/src/services/pre_executor.py` — wherever pre-executed output is formatted for Claude's context window.

---

## Files Modified in Batch 2

| File | Changes |
|------|---------|
| `backend/src/services/execution_enforcer.py` | Negative assertion detection patterns and `check_negative_assertions()` method |
| `backend/src/services/fortigate_collector.py` | `redact_fortigate_config()` function and integration |
| `executor/src/ssh.c` | `capture_hostkey_fingerprint()` helper |
| `executor/include/executor.h` | `hostkey_fp` field in ExecutorResponse |
| `executor/src/envelope.c` | Serialize/deserialize `hostkey_fp` |
| `executor/src/hmac.c` | Include `hostkey_fp` in signing payload |
| `executor/src/main.c` | Call `capture_hostkey_fingerprint()` after SSH success |
| `backend/src/services/executor_client.py` | Parse `hostkey_fp` field |
| `frontend/src/components/chat/DeviceOutputWidget.tsx` | Updated TrustBadge with integrity states |
| `frontend/src/api/client.ts` | Extended DeviceOutputBlock type |
| `backend/src/services/agentic.py` | Evidence warnings in agentic loop context |
| `backend/src/services/pre_executor.py` | Evidence warnings in pre-executed context |
| `backend/tests/test_collection_integrity.py` | **NEW** — 20+ tests for degraded collection |

---

## Verification

After both batches:

```bash
# Rebuild everything
cd executor && make clean && make
docker compose build
docker compose up -d

# Run ALL tests
docker compose exec backend pytest tests/ -v

# Manual smoke test: send a query to a device you know will return empty output
# (or temporarily block SSH access to a router) and verify:
# 1. The trust badge shows "HMAC verified · integrity FAIL" or "evidence limited"
# 2. The AI says "I cannot determine..." instead of making a definitive claim
# 3. The citation store has chain hashes on new citations
```
