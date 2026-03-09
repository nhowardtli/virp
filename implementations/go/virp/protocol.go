// Copyright (c) 2026 Third Level IT LLC. All rights reserved.
// VIRP -- Verified Infrastructure Response Protocol
// Protocol constants and types -- Go implementation

package virp

import "fmt"

// Protocol constants
const (
	Version        = 1
	Port           = 1790
	HeaderSize     = 56 // 24 bytes fields + 32 HMAC
	HMACSize       = 32 // SHA-256
	KeySize        = 32 // 256-bit signing keys
	MaxMessageSize = 65536
	MaxPayloadSize = MaxMessageSize - HeaderSize
	MaxObsRefs     = 64
	MaxIntentData  = 8192
	Magic          = 0x56495250 // "VIRP" in ASCII
)

// Channel identifiers -- the two channels can NEVER cross.
const (
	ChannelOC uint8 = 0x01 // Observation Channel
	ChannelIC uint8 = 0x02 // Intent Channel
)

// Trust tiers
const (
	TierGreen  uint8 = 0x01 // Passive -- no approval required
	TierYellow uint8 = 0x02 // Active -- single approval required
	TierRed    uint8 = 0x03 // Critical -- multi-human approval
	TierBlack  uint8 = 0xFF // Forbidden -- never transmitted
)

// Message types
const (
	MsgObservation uint8 = 0x01 // Signed measurement (OC)
	MsgHello       uint8 = 0x02 // Peer initialization (OC)
	MsgProposal    uint8 = 0x10 // Proposed change (IC)
	MsgApproval    uint8 = 0x11 // Approval/rejection (IC)
	MsgIntentAdv   uint8 = 0x20 // Intent advertisement (IC)
	MsgIntentWd    uint8 = 0x21 // Intent withdrawal (IC)
	MsgHeartbeat   uint8 = 0x30 // Liveness proof (OC)
	MsgTeardown    uint8 = 0xF0 // Graceful termination (both)
)

// Observation types
const (
	ObsPrefixReachable uint8 = 0x01
	ObsLinkState       uint8 = 0x02
	ObsPeerState       uint8 = 0x03
	ObsForwardingState uint8 = 0x04
	ObsResourceState   uint8 = 0x05
	ObsSecurityState   uint8 = 0x06
	ObsDeviceOutput    uint8 = 0x07
	ObsIntentSigned    uint8 = 0x08
	ObsOutcomeSigned   uint8 = 0x09
	ObsChainEntry      uint8 = 0x0A
	ObsChainVerify     uint8 = 0x0B
	ObsIntentStored    uint8 = 0x0C
	ObsIntentFetched   uint8 = 0x0D
	ObsIntentExecuted  uint8 = 0x0E
)

// Observation scope
const (
	ScopeLocal    uint8 = 0x01
	ScopeAdjacent uint8 = 0x02
	ScopeMeasured uint8 = 0x03
)

// Proposal types
const (
	PropRouteInject    uint8 = 0x01
	PropRouteWithdraw  uint8 = 0x02
	PropMetricChange   uint8 = 0x03
	PropPolicyChange   uint8 = 0x04
	PropTopologyChange uint8 = 0x05
	PropConfigApply    uint8 = 0x06
)

// Proposal states
const (
	PstateProposed   uint8 = 0x01
	PstateApproved   uint8 = 0x02
	PstateActive     uint8 = 0x03
	PstateRejected   uint8 = 0x04
	PstateRolledBack uint8 = 0x05
	PstateExpired    uint8 = 0x06
)

// Approval types
const (
	ApprovalApprove  uint8 = 0x01
	ApprovalReject   uint8 = 0x02
	ApprovalEscalate uint8 = 0x03
)

// Approver class
const (
	ApproverAutomated  uint8 = 0x01
	ApproverHuman      uint8 = 0x02
	ApproverMultiHuman uint8 = 0x03
)

// Intent types
const (
	IntentReachability uint8 = 0x01
	IntentService      uint8 = 0x02
	IntentCapacity     uint8 = 0x03
	IntentConstraint   uint8 = 0x04
	IntentSLA          uint8 = 0x05
)

// Node types
const (
	NodeObserver  uint8 = 0x01
	NodeReasoning uint8 = 0x02
	NodeHybrid    uint8 = 0x03
)

// Error codes matching the C implementation
type Error int

const (
	OK                  Error = 0
	ErrNullPtr          Error = -1
	ErrBufferTooSmall   Error = -2
	ErrInvalidVersion   Error = -3
	ErrInvalidType      Error = -4
	ErrInvalidChannel   Error = -5
	ErrInvalidTier      Error = -6
	ErrInvalidLength    Error = -7
	ErrHMACFailed       Error = -8
	ErrChannelViolation Error = -9
	ErrTierViolation    Error = -10
	ErrReplayDetected   Error = -11
	ErrNoEvidence       Error = -12
	ErrStaleObservation Error = -13
	ErrKeyNotLoaded     Error = -14
	ErrMessageTooLarge  Error = -15
	ErrReservedNonZero  Error = -16
	ErrChainDB          Error = -17
	ErrChainBroken      Error = -18
	ErrChainSequence    Error = -19
	ErrIntentNotFound   Error = -24
	ErrIntentExpired    Error = -25
	ErrIntentExhausted  Error = -26
)

func (e Error) Error() string {
	switch e {
	case OK:
		return "OK"
	case ErrNullPtr:
		return "NULL pointer"
	case ErrBufferTooSmall:
		return "buffer too small"
	case ErrInvalidVersion:
		return "invalid version"
	case ErrInvalidType:
		return "invalid message type"
	case ErrInvalidChannel:
		return "invalid channel"
	case ErrInvalidTier:
		return "invalid tier"
	case ErrInvalidLength:
		return "invalid length"
	case ErrHMACFailed:
		return "HMAC verification failed"
	case ErrChannelViolation:
		return "channel-key binding violation"
	case ErrTierViolation:
		return "BLACK tier transmitted"
	case ErrNoEvidence:
		return "proposal has no supporting evidence"
	case ErrStaleObservation:
		return "referenced observation expired"
	case ErrKeyNotLoaded:
		return "signing key not loaded"
	case ErrMessageTooLarge:
		return "message exceeds maximum size"
	case ErrReservedNonZero:
		return "reserved field is non-zero"
	default:
		return fmt.Sprintf("unknown error (%d)", int(e))
	}
}

// Header is the 56-byte VIRP common header. Wire format is big-endian.
type Header struct {
	Version     uint8
	Type        uint8
	Length      uint16
	NodeID      uint32
	Channel     uint8
	Tier        uint8
	Reserved    uint16
	SeqNum      uint32
	TimestampNs uint64
	HMAC        [HMACSize]byte
}

// ObservationPayload is the parsed observation sub-header.
type ObservationPayload struct {
	ObsType  uint8
	ObsScope uint8
	Data     []byte
}

// ObsRef is an observation reference used in proposals.
type ObsRef struct {
	NodeID uint32
	SeqNum uint32
}

// HeartbeatPayload is parsed heartbeat data.
type HeartbeatPayload struct {
	UptimeSeconds      uint32
	OnodeOK            bool
	RnodeOK            bool
	ActiveObservations uint16
	ActiveProposals    uint32
}

// Human-readable helpers

func MsgTypeStr(t uint8) string {
	switch t {
	case MsgObservation:
		return "OBSERVATION"
	case MsgHello:
		return "HELLO"
	case MsgProposal:
		return "PROPOSAL"
	case MsgApproval:
		return "APPROVAL"
	case MsgIntentAdv:
		return "INTENT-ADVERTISE"
	case MsgIntentWd:
		return "INTENT-WITHDRAW"
	case MsgHeartbeat:
		return "HEARTBEAT"
	case MsgTeardown:
		return "TEARDOWN"
	default:
		return "UNKNOWN"
	}
}

func ChannelStr(c uint8) string {
	switch c {
	case ChannelOC:
		return "OBSERVATION"
	case ChannelIC:
		return "INTENT"
	default:
		return "UNKNOWN"
	}
}

func TierStr(t uint8) string {
	switch t {
	case TierGreen:
		return "GREEN (passive)"
	case TierYellow:
		return "YELLOW (active)"
	case TierRed:
		return "RED (critical)"
	case TierBlack:
		return "BLACK (forbidden)"
	default:
		return "UNKNOWN"
	}
}

func ObsTypeStr(t uint8) string {
	switch t {
	case ObsPrefixReachable:
		return "PREFIX_REACHABLE"
	case ObsLinkState:
		return "LINK_STATE"
	case ObsPeerState:
		return "PEER_STATE"
	case ObsForwardingState:
		return "FORWARDING_STATE"
	case ObsResourceState:
		return "RESOURCE_STATE"
	case ObsSecurityState:
		return "SECURITY_STATE"
	case ObsDeviceOutput:
		return "DEVICE_OUTPUT"
	case ObsIntentSigned:
		return "INTENT_SIGNED"
	case ObsOutcomeSigned:
		return "OUTCOME_SIGNED"
	case ObsChainEntry:
		return "CHAIN_ENTRY"
	case ObsChainVerify:
		return "CHAIN_VERIFY"
	case ObsIntentStored:
		return "INTENT_STORED"
	case ObsIntentFetched:
		return "INTENT_FETCHED"
	case ObsIntentExecuted:
		return "INTENT_EXECUTED"
	default:
		return "UNKNOWN"
	}
}
