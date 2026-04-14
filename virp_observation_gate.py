"""
VIRP Observation Gate — Content fidelity verification for AI-generated device claims.

SECURITY MODEL: The AI's text output is UNTRUSTED. Only tool call metadata from the
API response is trusted. verified_devices and the observation cache are populated
exclusively from tool_use/tool_result block pairs in the API message history — never
from text content that may contain fabricated HMAC strings.

Two enforcement layers:
  1. Structural gate: flags any mention of a VIRP device without a real tool call
  2. Content fidelity: verifies numeric counts, universal/negation claims, and IP
     addresses in AI output against cached observation payloads from tool results
"""

import re
import time
import threading
import logging

logger = logging.getLogger("virp.observation_gate")


# ── Observation Payload Cache ────────────────────────────────────────────────

class ObservationPayloadCache:
    """Thread-safe cache of raw observation payloads keyed by device hostname.

    Entries MUST be populated via populate_cache_from_messages() or with a
    valid tool_use_id proving provenance from a real tool call.  Direct
    store() calls without tool_use_id are rejected.
    """

    def __init__(self, ttl=300):
        self._store = {}       # hostname -> {output, timestamp, hmac, tool_use_id}
        self._lock = threading.Lock()
        self._ttl = ttl

    def store(self, hostname, output, hmac=None, tool_use_id=None):
        """Store an observation.  Requires tool_use_id to prove provenance."""
        if not tool_use_id:
            logger.warning(
                "ObservationPayloadCache.store() called without tool_use_id "
                "for %s — REJECTED (possible fabrication attempt)", hostname
            )
            return
        with self._lock:
            self._store[hostname.lower()] = {
                "output": output or "",
                "timestamp": time.time(),
                "hmac": hmac,
                "tool_use_id": tool_use_id,
            }

    def get(self, hostname):
        with self._lock:
            entry = self._store.get(hostname.lower())
            if entry is None:
                return None
            if time.time() - entry["timestamp"] > self._ttl:
                del self._store[hostname.lower()]
                return None
            return entry

    def get_all(self):
        with self._lock:
            now = time.time()
            return {
                k: v for k, v in self._store.items()
                if now - v["timestamp"] <= self._ttl
            }

    def clear(self):
        with self._lock:
            self._store.clear()


# ── Message-Based Verification (TRUSTED SOURCE) ─────────────────────────────
#
# These functions extract verified device information exclusively from the
# structural metadata of API messages (tool_use blocks from the assistant,
# tool_result blocks from the server).  The AI cannot inject or forge these
# block types — they are controlled by the API framework.

_TOOL_NAMES = {"run_device_command", "pyats_run_show_command"}


def extract_verified_devices_from_messages(messages, tool_names=None):
    """
    Build verified_devices set from API message history.

    Scans for tool_use blocks (assistant) paired with tool_result blocks
    (server-generated).  Only devices with a real tool call + non-error
    result are considered verified.

    The AI's text blocks are NEVER inspected — only structural tool metadata.

    Returns:
        set of lowercase device hostnames that have real tool-call evidence.
    """
    if tool_names is None:
        tool_names = _TOOL_NAMES

    # Step 1: collect tool_use blocks from assistant messages
    # Map: tool_use_id -> hostname
    tool_calls = {}
    for msg in messages:
        if msg.get("role") != "assistant":
            continue
        content = msg.get("content", [])
        if isinstance(content, str):
            continue
        for block in content:
            if (block.get("type") == "tool_use"
                    and block.get("name") in tool_names):
                tool_id = block.get("id", "")
                inp = block.get("input", {})
                hostname = (inp.get("hostname")
                            or inp.get("device_name")
                            or "")
                if tool_id and hostname:
                    tool_calls[tool_id] = hostname.lower()

    if not tool_calls:
        return set()

    # Step 2: find matching tool_result blocks in user/server messages
    verified = set()
    for msg in messages:
        if msg.get("role") != "user":
            continue
        content = msg.get("content", [])
        if isinstance(content, str):
            continue
        for block in content:
            if block.get("type") != "tool_result":
                continue
            tool_id = block.get("tool_use_id", "")
            if tool_id not in tool_calls:
                continue

            # Extract text from tool_result content
            result_content = block.get("content", "")
            if isinstance(result_content, list):
                result_content = " ".join(
                    b.get("text", "") for b in result_content
                    if isinstance(b, dict) and b.get("type") == "text"
                )

            # Reject blocked/error results — no real observation occurred
            if not result_content:
                continue
            if "BLOCKED" in result_content:
                continue
            if result_content.startswith("Error:"):
                continue

            # Accept if the result contains HMAC evidence from the O-Node
            # The HMAC in tool_result is server-generated (from onode_execute),
            # NOT from AI text.  We check for the "HMAC:" prefix that
            # server.py embeds from the real binary VIRP response.
            if "HMAC:" in result_content or "hmac" in result_content.lower()[:100]:
                verified.add(tool_calls[tool_id])

    return verified


def populate_cache_from_messages(messages, cache, tool_names=None):
    """
    Populate observation cache ONLY from tool_result blocks that match
    real tool_use calls.  Never reads from AI text blocks.

    Args:
        messages: API message history
        cache: ObservationPayloadCache instance
        tool_names: set of tool names to trust (default: run_device_command)
    """
    if tool_names is None:
        tool_names = _TOOL_NAMES

    # Build tool_use map: tool_id -> (hostname, command)
    tool_calls = {}
    for msg in messages:
        if msg.get("role") != "assistant":
            continue
        content = msg.get("content", [])
        if isinstance(content, str):
            continue
        for block in content:
            if (block.get("type") == "tool_use"
                    and block.get("name") in tool_names):
                tool_id = block.get("id", "")
                inp = block.get("input", {})
                hostname = (inp.get("hostname")
                            or inp.get("device_name")
                            or "")
                if tool_id and hostname:
                    tool_calls[tool_id] = hostname

    # Extract observation payloads from matching tool_results
    for msg in messages:
        if msg.get("role") != "user":
            continue
        content = msg.get("content", [])
        if isinstance(content, str):
            continue
        for block in content:
            if block.get("type") != "tool_result":
                continue
            tool_id = block.get("tool_use_id", "")
            if tool_id not in tool_calls:
                continue

            hostname = tool_calls[tool_id]
            result_content = block.get("content", "")
            if isinstance(result_content, list):
                result_content = " ".join(
                    b.get("text", "") for b in result_content
                    if isinstance(b, dict) and b.get("type") == "text"
                )

            if not result_content or "BLOCKED" in result_content:
                continue

            # Extract HMAC from server-generated tool_result content
            hmac_match = re.search(r'HMAC:\s*([0-9a-fA-F]{6,})', result_content)
            hmac_val = hmac_match.group(1) if hmac_match else None

            if hmac_val:
                cache.store(
                    hostname, result_content,
                    hmac=hmac_val, tool_use_id=tool_id,
                )


# ── Numeric Count Extraction & Verification ──────────────────────────────────

_COUNT_RE = re.compile(
    r"\b(\d+)\s+(?:(running|active|established|failed|down|up|idle|stopped)\s+)?"
    r"([a-zA-Z][\w-]*(?:\s+[\w-]+)?)\b",
    re.IGNORECASE,
)


def extract_numeric_counts(text):
    """
    Pull numeric-count claims from prose.

    Matches patterns like "3 VMs", "0 running VMs", "12 established peers".
    Returns list of (number, subject_string) tuples.
    """
    results = []
    for num_str, adj, noun in _COUNT_RE.findall(text):
        subject = f"{adj} {noun}".strip() if adj else noun
        results.append((int(num_str), subject.lower()))
    return results


def count_occurrences_in_observation(observation_text, subject):
    """Count occurrences of *subject* in a raw observation payload."""
    if not observation_text:
        return 0
    lines = observation_text.strip().split("\n")
    subject_lower = subject.lower()

    # ── VM / QEMU counting (Proxmox qm list) ────────────────────────────
    if any(kw in subject_lower for kw in ("vm", "virtual machine", "qemu")):
        count = 0
        for line in lines:
            s = line.strip()
            if s and s[0].isdigit() and len(s.split()) >= 2:
                if "running" in subject_lower:
                    count += "running" in s.lower()
                elif "stopped" in subject_lower:
                    count += "stopped" in s.lower()
                else:
                    count += 1
        return count

    # ── Container counting (Proxmox pct list) ────────────────────────────
    if any(kw in subject_lower for kw in ("container", "ct", "lxc")):
        count = 0
        for line in lines:
            s = line.strip()
            if s and s[0].isdigit() and len(s.split()) >= 2:
                if "running" in subject_lower:
                    count += "running" in s.lower()
                elif "stopped" in subject_lower:
                    count += "stopped" in s.lower()
                else:
                    count += 1
        return count

    # ── BGP peer / neighbor / session counting ───────────────────────────
    if any(kw in subject_lower for kw in ("peer", "neighbor", "session", "bgp")):
        count = 0
        for line in lines:
            parts = line.strip().split()
            if len(parts) >= 2 and parts[0][:1].isdigit() and "." in parts[0]:
                if "established" in subject_lower:
                    last = parts[-1]
                    if last.isdigit() or "established" in line.lower():
                        count += 1
                elif "down" in subject_lower or "idle" in subject_lower:
                    last = parts[-1]
                    if not last.isdigit() and "established" not in line.lower():
                        count += 1
                else:
                    count += 1
        return count

    # ── Generic keyword match ────────────────────────────────────────────
    keywords = subject_lower.split()
    return sum(1 for line in lines if all(kw in line.lower() for kw in keywords))


def verify_numeric_claims(claim_text, observation_cache):
    """
    Cross-check every numeric-count claim against cached observations.

    Returns list of {claim, claimed, actual, device, passed} dicts.
    """
    claims = extract_numeric_counts(claim_text)
    if not claims:
        return []

    cached = (observation_cache.get_all()
              if hasattr(observation_cache, "get_all") else observation_cache)
    if not cached:
        return []

    results = []
    for claimed_count, subject in claims:
        for device, entry in cached.items():
            output = entry.get("output", "") if isinstance(entry, dict) else entry
            actual = count_occurrences_in_observation(output, subject)
            if actual > 0 or claimed_count == 0:
                results.append({
                    "claim": f"{claimed_count} {subject}",
                    "claimed": claimed_count,
                    "actual": actual,
                    "device": device,
                    "passed": claimed_count == actual,
                })
    return results


# ── Universal Claim Checking ("all peers are up") ───────────────────────────

_UNIVERSAL_PATTERNS = [
    (re.compile(r"\ball\b.*\b(?:peers?|neighbors?|sessions?)\b.*\b(?:up|established|active)\b", re.I), "all_up"),
    (re.compile(r"\bevery\b.*\b(?:peer|neighbor|session)\b.*\b(?:up|established|active)\b", re.I), "all_up"),
    (re.compile(r"\ball\b.*\b(?:devices?|routers?|nodes?)\b.*\b(?:up|reachable|online)\b", re.I), "all_up"),
    (re.compile(r"\ball\b.*\b(?:services?|processes?|interfaces?)\b.*\b(?:up|running|active)\b", re.I), "all_up"),
]


def check_universal_claims(claim_text, observation_text):
    """
    Detect "all X are Y" claims and verify none of the observation lines
    contradict them.  Returns list of {pattern, claim_type, passed, evidence}.
    """
    results = []
    for pattern, claim_type in _UNIVERSAL_PATTERNS:
        match = pattern.search(claim_text)
        if not match:
            continue
        if claim_type == "all_up":
            has_down = False
            evidence = []
            for line in observation_text.strip().split("\n"):
                parts = line.strip().split()
                if len(parts) >= 2 and parts[0][:1].isdigit() and "." in parts[0]:
                    last = parts[-1]
                    if not last.isdigit() and last.lower() != "established":
                        has_down = True
                        evidence.append(line.strip())
            results.append({
                "pattern": match.group(0),
                "claim_type": claim_type,
                "passed": not has_down,
                "evidence": evidence[:3],
            })
    return results


# ── Negation Claim Checking ("no failed peers") ─────────────────────────────

_NEGATION_PATTERNS = [
    (re.compile(r"\bno\b.*\b(?:failed|down|errors?|failures?)\b", re.I), "no_failed"),
    (re.compile(r"\bzero\b.*\b(?:failed|down|errors?|failures?)\b", re.I), "no_failed"),
    (re.compile(r"\bnone\b.*\b(?:failed|down|errors?|failures?)\b", re.I), "no_failed"),
    (re.compile(r"\bno\b.*\bpeers?\b.*\bdown\b", re.I), "no_failed"),
]


def check_negation_claims(claim_text, observation_text):
    """
    Detect "no failed X" / "zero errors" claims and verify against
    observation data.  Returns list of {pattern, claim_type, passed, evidence}.
    """
    results = []
    for pattern, claim_type in _NEGATION_PATTERNS:
        match = pattern.search(claim_text)
        if not match:
            continue
        if claim_type == "no_failed":
            has_failed = False
            evidence = []
            for line in observation_text.strip().split("\n"):
                stripped = line.strip()
                parts = stripped.split()
                if len(parts) >= 2 and parts[0][:1].isdigit() and "." in parts[0]:
                    last = parts[-1]
                    if not last.isdigit() and last.lower() != "established":
                        has_failed = True
                        evidence.append(stripped)
                elif any(kw in stripped.lower() for kw in ("failed", "error", "down")):
                    if not stripped.startswith("Neighbor") and not stripped.startswith("---"):
                        has_failed = True
                        evidence.append(stripped)
            results.append({
                "pattern": match.group(0),
                "claim_type": claim_type,
                "passed": not has_failed,
                "evidence": evidence[:3],
            })
    return results


# ── IP Address Verification ──────────────────────────────────────────────────

_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)


def verify_ip_addresses(claim_text, observation_text):
    """
    Verify every IP address in *claim_text* appears in *observation_text*.
    Returns list of {ip, found_in_observation, passed} dicts.
    """
    claimed_ips = set(_IP_RE.findall(claim_text))
    obs_ips = set(_IP_RE.findall(observation_text)) if observation_text else set()
    return [
        {"ip": ip, "found_in_observation": ip in obs_ips, "passed": ip in obs_ips}
        for ip in sorted(claimed_ips)
    ]


# ── Structural Gate (device mention without signed observation) ──────────────

_VIRP_DEVICE_NAMES = {f"r{i}" for i in range(1, 36)} | {
    "home-fg", "fortigate", "fortigate-200g", "asa-5525", "pa-850", "sw-3850",
    "wazuh", "wazuh-siem", "proxmox-colo", "proxmox-home", "wazuh-colo",
    "wazuh-home", "srx-300", "fortiwifi-60f",
}

_DEVICE_REF_RE = re.compile(
    r"\b(?:r\d{1,2}|home-fg|fortigate(?:-\w+)?|asa-5525|pa-850|sw-3850"
    r"|proxmox-(?:colo|home)|wazuh-(?:colo|home)|wazuh(?:-siem)?"
    r"|srx-300|fortiwifi-60f)\b",
    re.IGNORECASE,
)


def gate_unverified_device_claims(diagnosis, verified_devices=None, *,
                                  messages=None):
    """
    VIRP Observation Gate — pure structural enforcement.

    Rule: If the response references a VIRP-managed device and no REAL tool
    call (tool_use + tool_result pair) was made for that device in this
    session, flag it.  No exceptions.

    When *messages* is provided, verified_devices is derived from API message
    structure (tool_use/tool_result blocks) — the AI's text is NEVER used to
    determine verification status.  This is the SECURE path.

    When *messages* is None, falls back to the caller-provided
    *verified_devices* set (DEPRECATED — callers should pass messages).
    """
    if not diagnosis:
        return None

    # SECURE PATH: derive verified_devices from API messages
    if messages is not None:
        verified_devices = extract_verified_devices_from_messages(messages)
        logger.info(
            "[OBSERVATION-GATE] Derived verified_devices from messages: %s",
            sorted(verified_devices) if verified_devices else "none",
        )
    elif verified_devices is None:
        verified_devices = set()

    device_refs = set(m.lower() for m in _DEVICE_REF_RE.findall(diagnosis))
    virp_refs = device_refs & _VIRP_DEVICE_NAMES

    if not virp_refs:
        return None

    unverified = virp_refs - verified_devices
    if not unverified:
        return None

    flagged_list = ", ".join(sorted(unverified))
    verified_list = (", ".join(sorted(verified_devices))
                     if verified_devices else "none")
    return (
        f"\n\n**[OBSERVATION GATE: UNVERIFIED]** "
        f"This response references **{flagged_list}** without HMAC-signed "
        f"observations from tool calls in this session. "
        f"Verified devices: [{verified_list}]. "
        f"Unverified device references may contain fabricated state. "
        f"Run commands through the O-Node to get verified data."
    )


# ── Full Gate Pipeline ───────────────────────────────────────────────────────

def run_observation_gate(claim_text, verified_devices=None,
                         observation_cache=None, *, messages=None):
    """
    Run both enforcement layers and return a single result dict.

    When *messages* is provided, verified_devices and the observation cache
    are populated exclusively from API message metadata.  This is the
    SECURE path — it ignores any caller-provided verified_devices.

    Returns:
        {
            "flagged": bool,
            "structural_warning": str | None,
            "fidelity_failures": [...],
            "verified_devices": [...],
        }
    """
    # SECURE PATH: derive everything from messages
    if messages is not None:
        verified_devices = extract_verified_devices_from_messages(messages)
        if observation_cache is not None:
            observation_cache.clear()
            populate_cache_from_messages(messages, observation_cache)
    elif verified_devices is None:
        verified_devices = set()

    result = {
        "flagged": False,
        "structural_warning": None,
        "fidelity_failures": [],
        "verified_devices": sorted(verified_devices) if verified_devices else [],
    }

    # Layer 1 — structural
    structural = gate_unverified_device_claims(
        claim_text, verified_devices=verified_devices,
    )
    if structural:
        result["flagged"] = True
        result["structural_warning"] = structural

    # Layer 2 — content fidelity
    if observation_cache is None:
        return result

    cached = (observation_cache.get_all()
              if hasattr(observation_cache, "get_all") else {})

    # 2a  numeric counts
    for nr in verify_numeric_claims(claim_text, observation_cache):
        if not nr["passed"]:
            result["flagged"] = True
            suffix = nr["claim"].split(" ", 1)[1] if " " in nr["claim"] else ""
            result["fidelity_failures"].append({
                "type": "numeric_mismatch",
                "detail": (f"Claimed {nr['claimed']} {suffix}, "
                           f"observation shows {nr['actual']}"),
                "device": nr["device"],
            })

    # 2b  universal / negation claims
    all_obs = "\n".join(e["output"] for e in cached.values() if e.get("output"))

    for ur in check_universal_claims(claim_text, all_obs):
        if not ur["passed"]:
            result["flagged"] = True
            result["fidelity_failures"].append({
                "type": "universal_claim_violated",
                "detail": f'Claim "{ur["pattern"]}" contradicted by observation',
                "evidence": ur["evidence"],
            })

    for nr in check_negation_claims(claim_text, all_obs):
        if not nr["passed"]:
            result["flagged"] = True
            result["fidelity_failures"].append({
                "type": "negation_claim_violated",
                "detail": f'Claim "{nr["pattern"]}" contradicted by observation',
                "evidence": nr["evidence"],
            })

    # 2c  IP addresses
    for ir in verify_ip_addresses(claim_text, all_obs):
        if not ir["passed"]:
            result["flagged"] = True
            result["fidelity_failures"].append({
                "type": "phantom_ip",
                "detail": f"IP {ir['ip']} claimed but not found in any observation",
            })

    return result


# ── POST /api/gate endpoint handler ─────────────────────────────────────────

def handle_gate_request(body, verified_devices=None, observation_cache=None,
                        *, messages=None):
    """
    Handle a POST /api/gate request.

    Expected body:  {"claim_text": "...", "messages": [...]}

    When messages are provided (either in body or as kwarg), verified_devices
    is derived from API message structure — never from body parameters.

    Returns (status_code, response_dict).
    """
    claim_text = body.get("claim_text", "")
    if not claim_text:
        return 400, {"error": "claim_text is required"}

    # Prefer messages kwarg, fall back to body
    if messages is None:
        messages = body.get("messages")

    if messages is not None:
        # SECURE PATH: derive from messages
        return 200, run_observation_gate(
            claim_text, observation_cache=observation_cache,
            messages=messages,
        )

    # DEPRECATED fallback: caller-provided verified_devices
    if verified_devices is None:
        verified_devices = set(
            d.lower() for d in body.get("verified_devices", [])
        )

    return 200, run_observation_gate(
        claim_text, verified_devices, observation_cache,
    )
