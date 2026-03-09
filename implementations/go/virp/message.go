// Copyright (c) 2026 Third Level IT LLC. All rights reserved.
// VIRP -- Verified Infrastructure Response Protocol
// Message construction, parsing, and validation -- Go implementation
//
// Wire-compatible with the C implementation. All fields are big-endian.

package virp

import (
	"encoding/binary"
	"time"
)

// SerializeHeader writes a Header into exactly HeaderSize bytes (big-endian).
func SerializeHeader(hdr *Header, buf []byte) error {
	if len(buf) < HeaderSize {
		return ErrBufferTooSmall
	}
	buf[0] = hdr.Version
	buf[1] = hdr.Type
	binary.BigEndian.PutUint16(buf[2:4], hdr.Length)
	binary.BigEndian.PutUint32(buf[4:8], hdr.NodeID)
	buf[8] = hdr.Channel
	buf[9] = hdr.Tier
	buf[10] = 0 // reserved
	buf[11] = 0
	binary.BigEndian.PutUint32(buf[12:16], hdr.SeqNum)
	binary.BigEndian.PutUint64(buf[16:24], hdr.TimestampNs)
	copy(buf[24:56], hdr.HMAC[:])
	return nil
}

// DeserializeHeader reads a Header from at least HeaderSize bytes (big-endian).
func DeserializeHeader(buf []byte) (*Header, error) {
	if len(buf) < HeaderSize {
		return nil, ErrBufferTooSmall
	}
	hdr := &Header{
		Version:     buf[0],
		Type:        buf[1],
		Length:      binary.BigEndian.Uint16(buf[2:4]),
		NodeID:      binary.BigEndian.Uint32(buf[4:8]),
		Channel:     buf[8],
		Tier:        buf[9],
		Reserved:    uint16(buf[10])<<8 | uint16(buf[11]),
		SeqNum:      binary.BigEndian.Uint32(buf[12:16]),
		TimestampNs: binary.BigEndian.Uint64(buf[16:24]),
	}
	copy(hdr.HMAC[:], buf[24:56])
	return hdr, nil
}

// ValidateHeader checks structural validity of header fields.
// Does NOT verify HMAC -- use ValidateMessage for full validation.
func ValidateHeader(hdr *Header) error {
	if hdr.Version != Version {
		return ErrInvalidVersion
	}
	switch hdr.Type {
	case MsgObservation, MsgHello, MsgProposal, MsgApproval,
		MsgIntentAdv, MsgIntentWd, MsgHeartbeat, MsgTeardown:
	default:
		return ErrInvalidType
	}
	if hdr.Channel != ChannelOC && hdr.Channel != ChannelIC {
		return ErrInvalidChannel
	}
	if hdr.Tier == TierBlack {
		return ErrTierViolation
	}
	if hdr.Tier > TierRed {
		return ErrInvalidTier
	}
	if hdr.Reserved != 0 {
		return ErrReservedNonZero
	}
	if hdr.Length < HeaderSize {
		return ErrInvalidLength
	}
	return nil
}

// CheckChannelType enforces channel-message-type consistency.
func CheckChannelType(channel, msgType uint8) error {
	switch msgType {
	case MsgObservation, MsgHello, MsgHeartbeat:
		if channel != ChannelOC {
			return ErrChannelViolation
		}
	case MsgProposal, MsgApproval, MsgIntentAdv, MsgIntentWd:
		if channel != ChannelIC {
			return ErrChannelViolation
		}
	case MsgTeardown:
		// Both channels allowed
	default:
		return ErrInvalidType
	}
	return nil
}

// ValidateMessage performs the full validation pipeline:
// deserialize, validate fields, check channel-type, verify HMAC.
func ValidateMessage(msg []byte, sk *SigningKey) (*Header, error) {
	if len(msg) < HeaderSize {
		return nil, ErrBufferTooSmall
	}
	hdr, err := DeserializeHeader(msg)
	if err != nil {
		return nil, err
	}
	if err := ValidateHeader(hdr); err != nil {
		return nil, err
	}
	if err := CheckChannelType(hdr.Channel, hdr.Type); err != nil {
		return nil, err
	}
	if int(hdr.Length) > len(msg) {
		return nil, ErrInvalidLength
	}
	if err := Verify(msg[:hdr.Length], sk); err != nil {
		return nil, err
	}
	return hdr, nil
}

// timestampNs returns the current time as nanoseconds since Unix epoch.
func timestampNs() uint64 {
	return uint64(time.Now().UnixNano())
}

// buildAndSign constructs a complete VIRP message: header + payload, then signs it.
func buildAndSign(
	msgType, channel, tier uint8,
	nodeID, seqNum uint32,
	payload []byte,
	sk *SigningKey,
) ([]byte, error) {
	total := HeaderSize + len(payload)
	if total > MaxMessageSize {
		return nil, ErrMessageTooLarge
	}
	if tier == TierBlack {
		return nil, ErrTierViolation
	}

	hdr := &Header{
		Version:     Version,
		Type:        msgType,
		Length:      uint16(total),
		NodeID:      nodeID,
		Channel:     channel,
		Tier:        tier,
		Reserved:    0,
		SeqNum:      seqNum,
		TimestampNs: timestampNs(),
	}

	buf := make([]byte, total)
	if err := SerializeHeader(hdr, buf); err != nil {
		return nil, err
	}
	if len(payload) > 0 {
		copy(buf[HeaderSize:], payload)
	}
	if err := Sign(buf, sk); err != nil {
		return nil, err
	}
	return buf, nil
}

// BuildObservation constructs a signed OBSERVATION message on the OC.
func BuildObservation(
	nodeID, seqNum uint32,
	obsType, obsScope uint8,
	data []byte,
	sk *SigningKey,
) ([]byte, error) {
	dataLen := len(data)
	if dataLen > MaxPayloadSize-4 {
		dataLen = MaxPayloadSize - 4
	}

	payload := make([]byte, 4+dataLen)
	payload[0] = obsType
	payload[1] = obsScope
	binary.BigEndian.PutUint16(payload[2:4], uint16(dataLen))
	if dataLen > 0 {
		copy(payload[4:], data[:dataLen])
	}

	return buildAndSign(MsgObservation, ChannelOC, TierGreen, nodeID, seqNum, payload, sk)
}

// ParseObservation extracts the observation payload from a validated message.
func ParseObservation(payload []byte) (*ObservationPayload, error) {
	if len(payload) < 4 {
		return nil, ErrBufferTooSmall
	}
	dataLen := binary.BigEndian.Uint16(payload[2:4])
	obs := &ObservationPayload{
		ObsType:  payload[0],
		ObsScope: payload[1],
	}
	if int(dataLen) > 0 && len(payload) >= 4+int(dataLen) {
		obs.Data = payload[4 : 4+int(dataLen)]
	}
	return obs, nil
}

// BuildHeartbeat constructs a signed HEARTBEAT message on the OC.
func BuildHeartbeat(
	nodeID, seqNum, uptimeSeconds uint32,
	onodeOK, rnodeOK bool,
	activeObservations uint16,
	activeProposals uint32,
	sk *SigningKey,
) ([]byte, error) {
	payload := make([]byte, 12)
	binary.BigEndian.PutUint32(payload[0:4], uptimeSeconds)
	if onodeOK {
		payload[4] = 1
	}
	if rnodeOK {
		payload[5] = 1
	}
	binary.BigEndian.PutUint16(payload[6:8], activeObservations)
	binary.BigEndian.PutUint32(payload[8:12], activeProposals)

	return buildAndSign(MsgHeartbeat, ChannelOC, TierGreen, nodeID, seqNum, payload, sk)
}

// ParseHeartbeat extracts heartbeat data from a validated payload.
func ParseHeartbeat(payload []byte) (*HeartbeatPayload, error) {
	if len(payload) < 12 {
		return nil, ErrBufferTooSmall
	}
	return &HeartbeatPayload{
		UptimeSeconds:      binary.BigEndian.Uint32(payload[0:4]),
		OnodeOK:            payload[4] != 0,
		RnodeOK:            payload[5] != 0,
		ActiveObservations: binary.BigEndian.Uint16(payload[6:8]),
		ActiveProposals:    binary.BigEndian.Uint32(payload[8:12]),
	}, nil
}

// BuildProposal constructs a signed PROPOSAL message on the IC.
func BuildProposal(
	nodeID, seqNum, proposalID uint32,
	propType uint8,
	blastRadius uint16,
	obsRefs []ObsRef,
	propData []byte,
	sk *SigningKey,
) ([]byte, error) {
	if len(obsRefs) == 0 {
		return nil, ErrNoEvidence
	}
	if len(obsRefs) > MaxObsRefs {
		return nil, ErrMessageTooLarge
	}

	// Proposal header: id(4) + type(1) + state(1) + blast(2) + refcount(4) = 12
	payloadLen := 12 + len(obsRefs)*8 + len(propData)
	payload := make([]byte, payloadLen)
	off := 0
	binary.BigEndian.PutUint32(payload[off:], proposalID)
	off += 4
	payload[off] = propType
	off++
	payload[off] = PstateProposed
	off++
	binary.BigEndian.PutUint16(payload[off:], blastRadius)
	off += 2
	binary.BigEndian.PutUint32(payload[off:], uint32(len(obsRefs)))
	off += 4

	for _, ref := range obsRefs {
		binary.BigEndian.PutUint32(payload[off:], ref.NodeID)
		off += 4
		binary.BigEndian.PutUint32(payload[off:], ref.SeqNum)
		off += 4
	}

	if len(propData) > 0 {
		copy(payload[off:], propData)
	}

	return buildAndSign(MsgProposal, ChannelIC, TierYellow, nodeID, seqNum, payload, sk)
}

// BuildApproval constructs a signed APPROVAL message on the IC.
func BuildApproval(
	nodeID, seqNum, proposalID, approverNodeID uint32,
	approvalType, approverClass uint8,
	sk *SigningKey,
) ([]byte, error) {
	payload := make([]byte, 12)
	binary.BigEndian.PutUint32(payload[0:4], proposalID)
	binary.BigEndian.PutUint32(payload[4:8], approverNodeID)
	payload[8] = approvalType
	payload[9] = approverClass
	payload[10] = 0
	payload[11] = 0

	return buildAndSign(MsgApproval, ChannelIC, TierYellow, nodeID, seqNum, payload, sk)
}

// BuildIntentAdvertise constructs a signed INTENT-ADVERTISE message on the IC.
func BuildIntentAdvertise(
	nodeID, seqNum, intentID uint32,
	intentType, priority uint8,
	ttlSeconds uint16,
	proofs []ObsRef,
	intentData []byte,
	sk *SigningKey,
) ([]byte, error) {
	// Header: id(4) + type(1) + priority(1) + ttl(2) + proof_count(4) = 12
	payloadLen := 12 + len(proofs)*8 + len(intentData)
	payload := make([]byte, payloadLen)
	off := 0
	binary.BigEndian.PutUint32(payload[off:], intentID)
	off += 4
	payload[off] = intentType
	off++
	payload[off] = priority
	off++
	binary.BigEndian.PutUint16(payload[off:], ttlSeconds)
	off += 2
	binary.BigEndian.PutUint32(payload[off:], uint32(len(proofs)))
	off += 4

	for _, p := range proofs {
		binary.BigEndian.PutUint32(payload[off:], p.NodeID)
		off += 4
		binary.BigEndian.PutUint32(payload[off:], p.SeqNum)
		off += 4
	}

	if len(intentData) > 0 {
		copy(payload[off:], intentData)
	}

	return buildAndSign(MsgIntentAdv, ChannelIC, TierYellow, nodeID, seqNum, payload, sk)
}

// BuildIntentWithdraw constructs a signed INTENT-WITHDRAW message on the IC.
func BuildIntentWithdraw(
	nodeID, seqNum, intentID uint32,
	sk *SigningKey,
) ([]byte, error) {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload[0:4], intentID)
	return buildAndSign(MsgIntentWd, ChannelIC, TierYellow, nodeID, seqNum, payload, sk)
}

// BuildTeardown constructs a signed TEARDOWN message on either channel.
func BuildTeardown(
	nodeID, seqNum uint32,
	channel uint8,
	reason string,
	sk *SigningKey,
) ([]byte, error) {
	reasonBytes := []byte(reason)
	if len(reasonBytes) > 252 {
		reasonBytes = reasonBytes[:252]
	}
	payload := make([]byte, 2+len(reasonBytes))
	binary.BigEndian.PutUint16(payload[0:2], uint16(len(reasonBytes)))
	if len(reasonBytes) > 0 {
		copy(payload[2:], reasonBytes)
	}
	return buildAndSign(MsgTeardown, channel, TierGreen, nodeID, seqNum, payload, sk)
}

// BuildHello constructs a signed HELLO message on the OC.
func BuildHello(
	nodeID, seqNum uint32,
	nodeType, maxTier uint8,
	okey, rkey *SigningKey,
) ([]byte, error) {
	// Hello: magic(4) + version(1) + node_type(1) + max_tier(1) + reserved(1)
	//        + node_id(4) + okey_fp(32) + rkey_fp(32) = 76
	payload := make([]byte, 76)
	off := 0
	binary.BigEndian.PutUint32(payload[off:], Magic)
	off += 4
	payload[off] = Version
	off++
	payload[off] = nodeType
	off++
	payload[off] = maxTier
	off++
	payload[off] = 0 // reserved
	off++
	binary.BigEndian.PutUint32(payload[off:], nodeID)
	off += 4
	copy(payload[off:off+HMACSize], okey.Fingerprint[:])
	off += HMACSize
	if rkey != nil && rkey.Loaded {
		copy(payload[off:off+HMACSize], rkey.Fingerprint[:])
	}

	return buildAndSign(MsgHello, ChannelOC, TierGreen, nodeID, seqNum, payload, okey)
}
