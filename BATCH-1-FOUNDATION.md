# BATCH 1: Foundation — C Executor + Python Data Model

## Overview

Add collection integrity attestation to the VIRP envelope. New fields in the C executor struct, signed under the existing O-Key HMAC, propagated through the Python executor client and data envelope, and stored in a tamper-evident citation chain.

**After this batch:** the executor produces richer signed envelopes with integrity metadata. Existing tests must still pass. New fields appear in JSON responses from the Unix socket.

**Do not touch in this batch:** execution_enforcer.py, prompt_engine.py, DeviceOutputWidget.tsx, or any frontend code. That's Batch 2.

---

## Task 1: Add new fields to ExecutorResponse struct

**File:** `executor/include/executor.h`

**Current struct (lines 145–155):**
```c
typedef struct {
    char status[MAX_STATUS_SIZE];
    char device[MAX_DEVICE_NAME];
    char device_ip[MAX_IP_SIZE];
    char command[MAX_COMMAND_SIZE];
    char raw_output[MAX_OUTPUT_SIZE];
    time_t timestamp;
    char session_id[MAX_SESSION_ID];
    char pentest_tier[8];
    char hmac_sig[HMAC_SIG_HEX_SIZE];
} ExecutorResponse;
```

**Add these fields BEFORE `hmac_sig` (so they're included in the signing payload):**

```c
typedef struct {
    char status[MAX_STATUS_SIZE];
    char device[MAX_DEVICE_NAME];
    char device_ip[MAX_IP_SIZE];
    char command[MAX_COMMAND_SIZE];
    char raw_output[MAX_OUTPUT_SIZE];
    time_t timestamp;
    char session_id[MAX_SESSION_ID];
    char pentest_tier[8];
    /* ── VIRP v1.1: Collection Integrity Fields ──────────────── */
    int  exit_code;                    /* SSH process exit code (0 = success) */
    int  raw_output_len;               /* strlen(raw_output) at capture time */
    char collector_integrity[8];       /* "PASS", "WARN", or "FAIL" */
    char transport[12];                /* "SSH", "REST", "RESTCONF", "LOCAL" */
    int  latency_ms;                   /* round-trip execution time in ms */
    /* ── End v1.1 fields ─────────────────────────────────────── */
    char hmac_sig[HMAC_SIG_HEX_SIZE];
} ExecutorResponse;
```

**Also add constants near the other status codes (around line 64–70):**

```c
/* ─── Collector integrity values ─────────────────────────────────── */
#define INTEGRITY_PASS   "PASS"
#define INTEGRITY_WARN   "WARN"
#define INTEGRITY_FAIL   "FAIL"
```

---

## Task 2: Update envelope_build() to initialize new fields

**File:** `executor/src/envelope.c`

**In `envelope_build()` (line 19–45):** The function already does `memset(resp, 0, sizeof(*resp))` which zeros everything. After the existing field assignments (after the `session_id` assignment), add:

```c
    /* v1.1: integrity fields default to unknown state */
    resp->exit_code = -1;
    resp->raw_output_len = (int)strlen(raw_output);
    strncpy(resp->collector_integrity, INTEGRITY_PASS, sizeof(resp->collector_integrity) - 1);
    strncpy(resp->transport, "SSH", sizeof(resp->transport) - 1);
    resp->latency_ms = 0;
```

**In `envelope_to_json()` (line 51–82):** Add the new fields to JSON serialization, BEFORE the hmac_sig field:

```c
    json_object_object_add(obj, "exit_code",
        json_object_new_int(resp->exit_code));
    json_object_object_add(obj, "raw_output_len",
        json_object_new_int(resp->raw_output_len));
    json_object_object_add(obj, "collector_integrity",
        json_object_new_string(resp->collector_integrity));
    json_object_object_add(obj, "transport",
        json_object_new_string(resp->transport));
    json_object_object_add(obj, "latency_ms",
        json_object_new_int(resp->latency_ms));
```

**In `envelope_from_json()` (line 88–134):** Add deserialization for the new fields, before the hmac_sig parsing:

```c
    if (json_object_object_get_ex(obj, "exit_code", &val))
        resp->exit_code = json_object_get_int(val);

    if (json_object_object_get_ex(obj, "raw_output_len", &val))
        resp->raw_output_len = json_object_get_int(val);

    if (json_object_object_get_ex(obj, "collector_integrity", &val))
        strncpy(resp->collector_integrity, json_object_get_string(val),
                sizeof(resp->collector_integrity) - 1);

    if (json_object_object_get_ex(obj, "transport", &val))
        strncpy(resp->transport, json_object_get_string(val),
                sizeof(resp->transport) - 1);

    if (json_object_object_get_ex(obj, "latency_ms", &val))
        resp->latency_ms = json_object_get_int(val);
```

---

## Task 3: Include new fields in HMAC signing payload

**File:** `executor/src/hmac.c`

**In `build_signing_payload()` (line 105–130):** The current payload format is:

```
status|device|command|raw_output|timestamp|session_id|pentest_tier
```

Change to include the new fields. Update the `snprintf` to:

```c
    snprintf(payload, needed + 128,
             "%s|%s|%s|%s|%ld|%s|%s|%d|%d|%s|%s|%d",
             resp->status,
             resp->device,
             resp->command,
             resp->raw_output,
             (long)resp->timestamp,
             resp->session_id,
             resp->pentest_tier,
             resp->exit_code,
             resp->raw_output_len,
             resp->collector_integrity,
             resp->transport,
             resp->latency_ms);
```

**Also update the `needed` size calculation** to account for the additional fields (add space for the ints and new strings):

```c
    size_t needed = strlen(resp->status) + 1
                  + strlen(resp->device) + 1
                  + strlen(resp->command) + 1
                  + strlen(resp->raw_output) + 1
                  + 21  /* max digits for time_t + NUL */
                  + strlen(resp->session_id) + 1
                  + strlen(resp->pentest_tier) + 1
                  + 12  /* exit_code int */
                  + 12  /* raw_output_len int */
                  + strlen(resp->collector_integrity) + 1
                  + strlen(resp->transport) + 1
                  + 12; /* latency_ms int */
```

**IMPORTANT:** This changes the signing payload format. All existing signed envelopes will fail verification after this change. That's correct — ephemeral keys mean restarting the executor generates new keys anyway. Note this is a breaking change if there are any persisted envelopes being re-verified, but the current architecture doesn't do that.

---

## Task 4: Set integrity fields in main.c command dispatch

**File:** `executor/src/main.c`

**In the SSH dispatch section (around lines 234–270):** After `ssh_execute()` returns and before `envelope_build()`, capture timing and set integrity:

```c
    char output[MAX_OUTPUT_SIZE];
    int exit_code = -1;

    struct timespec ts_start, ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    int result = ssh_execute(&local_dev, &merged_cred, command, timeout,
                             output, sizeof(output), &exit_code);

    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    int latency_ms = (int)((ts_end.tv_sec - ts_start.tv_sec) * 1000
                         + (ts_end.tv_nsec - ts_start.tv_nsec) / 1000000);

    /* Zero credentials on stack after use */
    hmac_secure_zero(&merged_cred, sizeof(merged_cred));

    /* Build response */
    ExecutorResponse resp;
    const char *status;
    const char *integrity;

    switch (result) {
        case 0:
            status = (exit_code == 0) ? STATUS_SUCCESS : STATUS_FAILED;
            break;
        case -1:
            status = STATUS_UNREACHABLE;
            break;
        case -2:
            status = STATUS_TIMEOUT;
            break;
        default:
            status = STATUS_FAILED;
            break;
    }

    /* Determine collector integrity */
    size_t output_len = strlen(output);
    if (result == 0 && exit_code == 0 && output_len > 0) {
        integrity = INTEGRITY_PASS;
    } else if (result == 0 && exit_code == 0 && output_len == 0) {
        /* Command succeeded but returned nothing — WARN, not PASS */
        integrity = INTEGRITY_WARN;
    } else if (result == -2) {
        /* Timeout */
        integrity = INTEGRITY_FAIL;
    } else if (result == -1) {
        /* Unreachable */
        integrity = INTEGRITY_FAIL;
    } else {
        /* Non-zero exit code or other failure */
        integrity = INTEGRITY_WARN;
    }

    envelope_build(&resp, status, local_dev.name, local_dev.host, command,
                   output, session_id);

    /* Set v1.1 integrity fields */
    resp.exit_code = exit_code;
    resp.raw_output_len = (int)output_len;
    strncpy(resp.collector_integrity, integrity, sizeof(resp.collector_integrity) - 1);
    strncpy(resp.transport, "SSH", sizeof(resp.transport) - 1);
    resp.latency_ms = latency_ms;

    hmac_sign_response(&resp, &g_okey, VIRP_TYPE_OBSERVATION);
```

**Do the same for the pentest dispatch section (around lines 387–415)** — set `exit_code`, `raw_output_len`, `collector_integrity`, `transport` = "LOCAL", and `latency_ms` after `envelope_build()` and before `hmac_sign_response()`.

**Add `#include <time.h>` at the top of main.c if not already present** (it's included via executor.h, but confirm).

---

## Task 5: Update Python ExecutorResponse dataclass

**File:** `backend/src/services/executor_client.py`

**In the ExecutorResponse dataclass (lines 60–77):** Add the new fields:

```python
@dataclass
class ExecutorResponse:
    """Mirrors the C ExecutorResponse struct."""
    status: str = ""
    device: str = ""
    device_ip: str = ""
    command: str = ""
    raw_output: str = ""
    timestamp: int = 0
    session_id: str = ""
    pentest_tier: str = ""
    hmac_sig: str = ""
    # Client-side metadata (not from C binary)
    verified: bool = False
    duration_ms: int = 0
    error: str = ""
    # VIRP O-Key fingerprint — identifies which O-Node signed this observation
    okey_fingerprint: str = ""
    # VIRP v1.1: Collection integrity fields (from C executor, signed)
    exit_code: int = -1
    raw_output_len: int = 0
    collector_integrity: str = ""  # "PASS", "WARN", "FAIL"
    transport: str = ""            # "SSH", "REST", "RESTCONF", "LOCAL"
    latency_ms_executor: int = 0   # Executor-measured latency (vs client-measured duration_ms)
```

**In the `execute()` method (around line 332–344):** Parse the new fields from the JSON response:

```python
        resp = ExecutorResponse(
            status=data.get("status", "FAILED"),
            device=data.get("device", device),
            device_ip=data.get("device_ip", ""),
            command=data.get("command", command),
            raw_output=data.get("raw_output", ""),
            timestamp=data.get("timestamp", 0),
            session_id=data.get("session_id", session_id),
            pentest_tier=data.get("pentest_tier", ""),
            hmac_sig=data.get("hmac_sig", ""),
            duration_ms=duration_ms,
            okey_fingerprint=self._okey_fingerprint,
            # v1.1 integrity fields
            exit_code=data.get("exit_code", -1),
            raw_output_len=data.get("raw_output_len", 0),
            collector_integrity=data.get("collector_integrity", ""),
            transport=data.get("transport", ""),
            latency_ms_executor=data.get("latency_ms", 0),
        )
```

**Do the same in `pentest_execute()` (around line 391–400).**

**In `to_dict()` (lines 103–120):** Add the new fields:

```python
        if self.collector_integrity:
            d["collector_integrity"] = self.collector_integrity
        if self.exit_code != -1:
            d["exit_code"] = self.exit_code
        d["raw_output_len"] = self.raw_output_len
        if self.transport:
            d["transport"] = self.transport
```

**Add a convenience property:**

```python
    @property
    def evidence_usable(self) -> bool:
        """Whether this observation can be used as evidence for assertions."""
        return self.collector_integrity == "PASS" and self.verified
```

---

## Task 6: Add INSUFFICIENT_EVIDENCE to CollectionStatus

**File:** `backend/src/services/data_envelope.py`

**In the CollectionStatus enum (lines 32–38):** Add the new status:

```python
class CollectionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    EMPTY = "EMPTY"
    UNREACHABLE = "UNREACHABLE"
    ERROR = "ERROR"
    NOT_REQUESTED = "NOT_REQUESTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"  # v1.1: data exists but not usable as evidence
```

**In the ActionEnvelope.format_for_prompt() method (lines 207–226):** Add handling for the integrity status. After the existing format method, add:

```python
    @property
    def evidence_usable(self) -> bool:
        """Whether this action result can support factual assertions."""
        if self._status != ExecutorStatus.SUCCESS:
            return False
        if not self._raw_output or not self._raw_output.strip():
            return False
        return True

    def format_evidence_warning(self) -> str:
        """Return a warning string if evidence is not usable, empty string if OK."""
        if self._status == ExecutorStatus.SUCCESS and not self._raw_output.strip():
            return (
                f"[EVIDENCE WARNING: Command '{self._command}' on {self._device} "
                f"returned empty output. Do NOT make assertions about device state "
                f"based on empty output. State that you cannot determine the status "
                f"from available evidence and suggest diagnostic next steps.]"
            )
        if self._status in (ExecutorStatus.TIMEOUT, ExecutorStatus.FAILED):
            return (
                f"[EVIDENCE WARNING: Command '{self._command}' on {self._device} "
                f"status={self._status.value}. Do NOT infer device state from failed "
                f"commands. Report the failure and suggest remediation.]"
            )
        return ""
```

---

## Task 7: Add hash chain to CitationStore

**File:** `backend/src/services/citation_store.py`

**Add `import hashlib` to imports (top of file).**

**Add a `record_hash` field to the Citation dataclass (line 27):**

```python
@dataclass
class Citation:
    """A single citation linking a finding to its data source."""
    source: str
    query_type: str
    query_params: dict
    opensearch_query: dict | None
    timestamp: datetime
    result_count: int
    sample_data: list
    verification_command: str
    record_hash: str = ""      # v1.1: SHA-256 chain hash
    prev_hash: str = ""        # v1.1: hash of previous record
```

**Add chain hashing to the CitationStore class. Add a `_last_hash` field to `__init__` (line 78):**

```python
    def __init__(self):
        self._contexts: OrderedDict[str, list[CitationContext]] = OrderedDict()
        self._lock = threading.Lock()
        self.MAX_CONTEXTS_PER_SESSION = 10
        # v1.1: tamper-evident chain hash
        self._last_hash: str = hashlib.sha256(b"VIRP_CITATION_GENESIS").hexdigest()
```

**Add a chain hash method to CitationStore:**

```python
    def _compute_chain_hash(self, citation: Citation) -> str:
        """Compute tamper-evident chain hash for a citation record."""
        record_json = json.dumps({
            "source": citation.source,
            "query_type": citation.query_type,
            "query_params": citation.query_params,
            "timestamp": citation.timestamp.isoformat(),
            "result_count": citation.result_count,
            "prev_hash": self._last_hash,
        }, sort_keys=True)
        return hashlib.sha256(record_json.encode()).hexdigest()
```

**Modify `CitationContext.add_citation()` to accept and set hash fields. Then in `CitationStore.create_context()`, update the context's `add_citation` calls to chain hashes. The simplest approach: override `add_citation` at the store level:**

Add a new method to CitationStore:

```python
    def add_citation_to_context(self, context: CitationContext, **kwargs) -> Citation:
        """Add a citation with chain hash to a context."""
        with self._lock:
            citation = Citation(**kwargs, timestamp=datetime.utcnow())
            citation.prev_hash = self._last_hash
            citation.record_hash = self._compute_chain_hash(citation)
            self._last_hash = citation.record_hash
            context.citations.append(citation)
            return citation
```

---

## Task 8: Verify it all compiles and existing tests pass

After all changes:

```bash
# Rebuild executor
cd executor && make clean && make

# Rebuild Docker
docker compose build backend

# Run existing test suite
docker compose exec backend pytest tests/test_channel_separation.py -v
```

**Expected:** All 60+ existing tests pass. The new fields are present in executor JSON responses. HMAC signatures are computed over the extended payload.

---

## Files Modified in Batch 1

| File | Changes |
|------|---------|
| `executor/include/executor.h` | New fields in ExecutorResponse, new INTEGRITY_* constants |
| `executor/src/envelope.c` | Serialize/deserialize new fields in JSON |
| `executor/src/hmac.c` | Extended signing payload format |
| `executor/src/main.c` | Capture exit_code, output_len, latency, compute integrity |
| `backend/src/services/executor_client.py` | Parse new fields, add evidence_usable property |
| `backend/src/services/data_envelope.py` | INSUFFICIENT_EVIDENCE status, evidence warnings |
| `backend/src/services/citation_store.py` | Chain hash, prev_hash, record_hash fields |
