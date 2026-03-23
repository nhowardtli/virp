"""
VIRP Data Models — Typed representations of VIRP protocol objects.

These models map directly to the VIRP RFC wire format:
- Observations: signed device output on the Observation Channel
- Intents: proposed changes on the Intent Channel
- Chain entries: immutable audit trail records
- Devices: registered infrastructure endpoints

Copyright 2026 Nate Howard, Third Level IT LLC
Licensed under Apache 2.0
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class TrustTier(Enum):
    """
    VIRP Trust Tiers — structural enforcement of agent capabilities.

    GREEN:  Auto-execute. Read-only operations. No approval needed.
    YELLOW: Flagged. Non-critical changes, logged for review.
    RED:    Human approval required. Critical operations.
    BLACK:  Structurally impossible. O-Node refuses at protocol level.
    """
    GREEN = "GREEN"
    YELLOW = "YELLOW"
    RED = "RED"
    BLACK = "BLACK"

    @classmethod
    def from_str(cls, value: str) -> "TrustTier":
        try:
            return cls(value.upper())
        except ValueError:
            return cls.GREEN


@dataclass
class ObservationResult:
    """A signed observation from the VIRP Observation Channel."""
    device: str
    command: str
    output: str
    hmac: str
    sequence: int
    timestamp: str
    trust_tier: TrustTier
    node_id: str
    verified: bool
    channel: str = "observation"

    def to_dict(self) -> dict:
        return {
            "device": self.device,
            "command": self.command,
            "output": self.output,
            "hmac": self.hmac,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "trust_tier": self.trust_tier.value,
            "node_id": self.node_id,
            "verified": self.verified,
            "channel": self.channel,
        }


@dataclass
class IntentResult:
    """A signed intent from the VIRP Intent Channel."""
    device: str
    action: str
    trust_tier: TrustTier
    approved: bool
    intent_id: str
    hmac: str
    sequence: int
    timestamp: str
    reason: str = ""
    requires_approval: bool = True

    def to_dict(self) -> dict:
        return {
            "device": self.device,
            "action": self.action,
            "trust_tier": self.trust_tier.value,
            "approved": self.approved,
            "intent_id": self.intent_id,
            "hmac": self.hmac,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "reason": self.reason,
            "requires_approval": self.requires_approval,
        }


@dataclass
class DeviceInfo:
    """A device registered with the VIRP O-Node."""
    name: str
    address: str
    vendor: str = "unknown"
    last_observation: str = ""
    observation_count: int = 0
    reachable: bool = False
    trust_tier: TrustTier = TrustTier.GREEN

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "address": self.address,
            "vendor": self.vendor,
            "last_observation": self.last_observation,
            "observation_count": self.observation_count,
            "reachable": self.reachable,
            "trust_tier": self.trust_tier.value,
        }


@dataclass
class ChainEntry:
    """An entry in the VIRP audit chain (chain.db)."""
    sequence: int
    device: str
    action_type: str  # "observation" or "intent"
    hmac: str
    prev_hash: str
    timestamp: str
    channel: str
    chain_valid: bool
    node_id: str = ""

    def to_dict(self) -> dict:
        return {
            "sequence": self.sequence,
            "device": self.device,
            "action_type": self.action_type,
            "hmac": self.hmac,
            "prev_hash": self.prev_hash,
            "timestamp": self.timestamp,
            "channel": self.channel,
            "chain_valid": self.chain_valid,
            "node_id": self.node_id,
        }
