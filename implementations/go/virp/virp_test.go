// Copyright (c) 2026 Third Level IT LLC. All rights reserved.
// VIRP -- Verified Infrastructure Response Protocol
// Tests -- crypto, message building, channel enforcement, O-Node interop

package virp

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// =========================================================================
// Crypto Tests
// =========================================================================

func TestKeyGenerate(t *testing.T) {
	sk, err := KeyGenerate(KeyTypeOKey)
	if err != nil {
		t.Fatalf("KeyGenerate: %v", err)
	}
	if !sk.Loaded {
		t.Fatal("key not marked as loaded")
	}
	if sk.Type != KeyTypeOKey {
		t.Fatalf("expected KeyTypeOKey, got %d", sk.Type)
	}
	// Fingerprint should be non-zero
	allZero := true
	for _, b := range sk.Fingerprint {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("fingerprint is all zeros")
	}
}

func TestKeyInitAndFingerprint(t *testing.T) {
	var keyBytes [KeySize]byte
	for i := range keyBytes {
		keyBytes[i] = byte(i)
	}
	sk := KeyInit(KeyTypeRKey, keyBytes)
	if !sk.Loaded || sk.Type != KeyTypeRKey {
		t.Fatal("key not properly initialized")
	}
	// Same bytes should produce same fingerprint
	sk2 := KeyInit(KeyTypeRKey, keyBytes)
	if sk.Fingerprint != sk2.Fingerprint {
		t.Fatal("same key bytes produced different fingerprints")
	}
}

func TestKeyLoadSaveFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.key")

	sk, _ := KeyGenerate(KeyTypeOKey)
	if err := KeySaveFile(sk, path); err != nil {
		t.Fatalf("KeySaveFile: %v", err)
	}

	loaded, err := KeyLoadFile(KeyTypeOKey, path)
	if err != nil {
		t.Fatalf("KeyLoadFile: %v", err)
	}
	if sk.Key != loaded.Key {
		t.Fatal("loaded key doesn't match saved key")
	}
	if sk.Fingerprint != loaded.Fingerprint {
		t.Fatal("loaded fingerprint doesn't match")
	}
}

func TestKeyDestroy(t *testing.T) {
	sk, _ := KeyGenerate(KeyTypeOKey)
	KeyDestroy(sk)
	if sk.Loaded {
		t.Fatal("key still marked loaded after destroy")
	}
	for _, b := range sk.Key {
		if b != 0 {
			t.Fatal("key not zeroed after destroy")
		}
	}
}

func TestHMACSHA256Deterministic(t *testing.T) {
	var key [KeySize]byte
	for i := range key {
		key[i] = 0xAA
	}
	data := []byte("VIRP test data")
	h1 := HMACSHA256(key, data)
	h2 := HMACSHA256(key, data)
	if h1 != h2 {
		t.Fatal("HMAC-SHA256 is not deterministic")
	}
	// Different data should produce different HMAC
	h3 := HMACSHA256(key, []byte("different"))
	if h1 == h3 {
		t.Fatal("different data produced same HMAC")
	}
}

// =========================================================================
// Channel-Key Binding Tests
// =========================================================================

func TestChannelKeyBinding_OKeyOnOC(t *testing.T) {
	sk, _ := KeyGenerate(KeyTypeOKey)
	msg, err := BuildObservation(1, 1, ObsDeviceOutput, ScopeLocal, []byte("test"), sk)
	if err != nil {
		t.Fatalf("OKey on OC should succeed: %v", err)
	}
	if err := Verify(msg, sk); err != nil {
		t.Fatalf("verification should succeed: %v", err)
	}
}

func TestChannelKeyBinding_RKeyOnOC_Rejected(t *testing.T) {
	rk, _ := KeyGenerate(KeyTypeRKey)
	_, err := BuildObservation(1, 1, ObsDeviceOutput, ScopeLocal, []byte("test"), rk)
	if err != ErrChannelViolation {
		t.Fatalf("expected ErrChannelViolation, got %v", err)
	}
}

func TestChannelKeyBinding_OKeyOnIC_Rejected(t *testing.T) {
	ok, _ := KeyGenerate(KeyTypeOKey)
	refs := []ObsRef{{NodeID: 1, SeqNum: 1}}
	_, err := BuildProposal(1, 1, 100, PropRouteInject, 5, refs, nil, ok)
	if err != ErrChannelViolation {
		t.Fatalf("expected ErrChannelViolation, got %v", err)
	}
}

func TestChannelKeyBinding_RKeyOnIC(t *testing.T) {
	rk, _ := KeyGenerate(KeyTypeRKey)
	refs := []ObsRef{{NodeID: 1, SeqNum: 1}}
	msg, err := BuildProposal(1, 1, 100, PropRouteInject, 5, refs, nil, rk)
	if err != nil {
		t.Fatalf("RKey on IC should succeed: %v", err)
	}
	if err := Verify(msg, rk); err != nil {
		t.Fatalf("verification should succeed: %v", err)
	}
}

// =========================================================================
// Trust Tier Tests
// =========================================================================

func TestBlackTierRejected(t *testing.T) {
	sk, _ := KeyGenerate(KeyTypeOKey)
	// Manually attempt to build with BLACK tier
	_, err := buildAndSign(MsgObservation, ChannelOC, TierBlack, 1, 1, nil, sk)
	if err != ErrTierViolation {
		t.Fatalf("expected ErrTierViolation, got %v", err)
	}
}

func TestValidTiers(t *testing.T) {
	sk, _ := KeyGenerate(KeyTypeOKey)
	for _, tier := range []uint8{TierGreen, TierYellow, TierRed} {
		_, err := buildAndSign(MsgHeartbeat, ChannelOC, tier, 1, 1, make([]byte, 12), sk)
		if err != nil {
			t.Fatalf("tier %s should be valid: %v", TierStr(tier), err)
		}
	}
}

// =========================================================================
// Header Serialization Tests (wire-compatible with C)
// =========================================================================

func TestHeaderSerializeDeserialize(t *testing.T) {
	hdr := &Header{
		Version:     Version,
		Type:        MsgObservation,
		Length:      HeaderSize + 10,
		NodeID:      0xDEADBEEF,
		Channel:     ChannelOC,
		Tier:        TierGreen,
		Reserved:    0,
		SeqNum:      42,
		TimestampNs: 1709000000000000000,
	}

	buf := make([]byte, HeaderSize)
	if err := SerializeHeader(hdr, buf); err != nil {
		t.Fatalf("serialize: %v", err)
	}

	// Verify big-endian encoding
	if buf[0] != Version {
		t.Fatalf("version byte: got %d, want %d", buf[0], Version)
	}
	if buf[1] != MsgObservation {
		t.Fatalf("type byte: got %d, want %d", buf[1], MsgObservation)
	}
	if binary.BigEndian.Uint32(buf[4:8]) != 0xDEADBEEF {
		t.Fatal("node_id not in big-endian")
	}
	if buf[8] != ChannelOC {
		t.Fatal("channel byte wrong")
	}
	if buf[9] != TierGreen {
		t.Fatal("tier byte wrong")
	}

	// Deserialize and compare
	hdr2, err := DeserializeHeader(buf)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if hdr2.Version != hdr.Version || hdr2.Type != hdr.Type ||
		hdr2.Length != hdr.Length || hdr2.NodeID != hdr.NodeID ||
		hdr2.Channel != hdr.Channel || hdr2.Tier != hdr.Tier ||
		hdr2.SeqNum != hdr.SeqNum || hdr2.TimestampNs != hdr.TimestampNs {
		t.Fatal("deserialized header doesn't match original")
	}
}

func TestHeaderValidation(t *testing.T) {
	// Good header
	hdr := &Header{
		Version: Version, Type: MsgObservation, Length: HeaderSize,
		Channel: ChannelOC, Tier: TierGreen,
	}
	if err := ValidateHeader(hdr); err != nil {
		t.Fatalf("valid header rejected: %v", err)
	}

	// Bad version
	hdr2 := *hdr
	hdr2.Version = 99
	if err := ValidateHeader(&hdr2); err != ErrInvalidVersion {
		t.Fatalf("expected ErrInvalidVersion, got %v", err)
	}

	// Bad type
	hdr3 := *hdr
	hdr3.Type = 0x99
	if err := ValidateHeader(&hdr3); err != ErrInvalidType {
		t.Fatalf("expected ErrInvalidType, got %v", err)
	}

	// Bad channel
	hdr4 := *hdr
	hdr4.Channel = 0x03
	if err := ValidateHeader(&hdr4); err != ErrInvalidChannel {
		t.Fatalf("expected ErrInvalidChannel, got %v", err)
	}

	// BLACK tier
	hdr5 := *hdr
	hdr5.Tier = TierBlack
	if err := ValidateHeader(&hdr5); err != ErrTierViolation {
		t.Fatalf("expected ErrTierViolation, got %v", err)
	}

	// Non-zero reserved
	hdr6 := *hdr
	hdr6.Reserved = 1
	if err := ValidateHeader(&hdr6); err != ErrReservedNonZero {
		t.Fatalf("expected ErrReservedNonZero, got %v", err)
	}

	// Length too small
	hdr7 := *hdr
	hdr7.Length = 10
	if err := ValidateHeader(&hdr7); err != ErrInvalidLength {
		t.Fatalf("expected ErrInvalidLength, got %v", err)
	}
}

// =========================================================================
// Message Building and Validation Tests
// =========================================================================

func TestBuildAndValidateObservation(t *testing.T) {
	sk, _ := KeyGenerate(KeyTypeOKey)
	data := []byte("show ip route output here")
	msg, err := BuildObservation(0x211, 1, ObsDeviceOutput, ScopeLocal, data, sk)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	hdr, err := ValidateMessage(msg, sk)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if hdr.Type != MsgObservation {
		t.Fatalf("expected OBSERVATION, got %s", MsgTypeStr(hdr.Type))
	}
	if hdr.Channel != ChannelOC {
		t.Fatal("observation not on OC")
	}
	if hdr.NodeID != 0x211 {
		t.Fatalf("node_id: got 0x%x, want 0x211", hdr.NodeID)
	}

	// Parse observation payload
	obs, err := ParseObservation(msg[HeaderSize:])
	if err != nil {
		t.Fatalf("parse observation: %v", err)
	}
	if obs.ObsType != ObsDeviceOutput {
		t.Fatalf("obs_type: got %d, want %d", obs.ObsType, ObsDeviceOutput)
	}
	if string(obs.Data) != string(data) {
		t.Fatalf("data mismatch: got %q", string(obs.Data))
	}
}

func TestBuildAndValidateHeartbeat(t *testing.T) {
	sk, _ := KeyGenerate(KeyTypeOKey)
	msg, err := BuildHeartbeat(0x211, 2, 3600, true, true, 42, 0, sk)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	hdr, err := ValidateMessage(msg, sk)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if hdr.Type != MsgHeartbeat {
		t.Fatal("wrong type")
	}

	hb, err := ParseHeartbeat(msg[HeaderSize:])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if hb.UptimeSeconds != 3600 || !hb.OnodeOK || !hb.RnodeOK {
		t.Fatalf("heartbeat fields wrong: %+v", hb)
	}
	if hb.ActiveObservations != 42 {
		t.Fatalf("active_observations: got %d, want 42", hb.ActiveObservations)
	}
}

func TestBuildAndValidateProposal(t *testing.T) {
	rk, _ := KeyGenerate(KeyTypeRKey)
	refs := []ObsRef{{NodeID: 0x211, SeqNum: 1}, {NodeID: 0x211, SeqNum: 2}}
	propData := []byte("ip route 10.0.0.0/24 via 10.0.10.1")
	msg, err := BuildProposal(0x300, 5, 1001, PropRouteInject, 3, refs, propData, rk)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	hdr, err := ValidateMessage(msg, rk)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if hdr.Type != MsgProposal {
		t.Fatal("wrong type")
	}
	if hdr.Channel != ChannelIC {
		t.Fatal("proposal not on IC")
	}
	if hdr.Tier != TierYellow {
		t.Fatal("proposal should default to YELLOW tier")
	}
}

func TestProposalRequiresEvidence(t *testing.T) {
	rk, _ := KeyGenerate(KeyTypeRKey)
	_, err := BuildProposal(1, 1, 100, PropRouteInject, 5, nil, nil, rk)
	if err != ErrNoEvidence {
		t.Fatalf("expected ErrNoEvidence, got %v", err)
	}
	_, err = BuildProposal(1, 1, 100, PropRouteInject, 5, []ObsRef{}, nil, rk)
	if err != ErrNoEvidence {
		t.Fatalf("expected ErrNoEvidence for empty refs, got %v", err)
	}
}

func TestBuildAndValidateApproval(t *testing.T) {
	rk, _ := KeyGenerate(KeyTypeRKey)
	msg, err := BuildApproval(0x300, 6, 1001, 0x400, ApprovalApprove, ApproverHuman, rk)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	hdr, err := ValidateMessage(msg, rk)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if hdr.Type != MsgApproval {
		t.Fatal("wrong type")
	}
}

func TestBuildAndValidateIntentAdv(t *testing.T) {
	rk, _ := KeyGenerate(KeyTypeRKey)
	proofs := []ObsRef{{NodeID: 1, SeqNum: 1}}
	intentData := []byte(`{"prefix":"10.0.0.0/24","guarantee":"99.9%"}`)
	msg, err := BuildIntentAdvertise(0x300, 7, 2001, IntentReachability, 128, 3600, proofs, intentData, rk)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	hdr, err := ValidateMessage(msg, rk)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if hdr.Type != MsgIntentAdv {
		t.Fatal("wrong type")
	}
}

func TestBuildAndValidateIntentWd(t *testing.T) {
	rk, _ := KeyGenerate(KeyTypeRKey)
	msg, err := BuildIntentWithdraw(0x300, 8, 2001, rk)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	hdr, err := ValidateMessage(msg, rk)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if hdr.Type != MsgIntentWd {
		t.Fatal("wrong type")
	}
}

func TestBuildAndValidateTeardown(t *testing.T) {
	sk, _ := KeyGenerate(KeyTypeOKey)
	msg, err := BuildTeardown(0x211, 9, ChannelOC, "administrative shutdown", sk)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	hdr, err := ValidateMessage(msg, sk)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if hdr.Type != MsgTeardown {
		t.Fatal("wrong type")
	}
}

func TestBuildAndValidateHello(t *testing.T) {
	ok, _ := KeyGenerate(KeyTypeOKey)
	rk, _ := KeyGenerate(KeyTypeRKey)
	msg, err := BuildHello(0x211, 10, NodeHybrid, TierRed, ok, rk)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	hdr, err := ValidateMessage(msg, ok)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if hdr.Type != MsgHello {
		t.Fatal("wrong type")
	}
}

// =========================================================================
// Tamper Detection Test
// =========================================================================

func TestTamperDetection(t *testing.T) {
	sk, _ := KeyGenerate(KeyTypeOKey)
	msg, _ := BuildObservation(1, 1, ObsDeviceOutput, ScopeLocal, []byte("real data"), sk)

	// Tamper with payload
	tampered := make([]byte, len(msg))
	copy(tampered, msg)
	tampered[len(tampered)-1] ^= 0xFF

	if err := Verify(tampered, sk); err != ErrHMACFailed {
		t.Fatalf("expected ErrHMACFailed for tampered message, got %v", err)
	}
}

func TestWrongKeyRejected(t *testing.T) {
	sk1, _ := KeyGenerate(KeyTypeOKey)
	sk2, _ := KeyGenerate(KeyTypeOKey)
	msg, _ := BuildObservation(1, 1, ObsDeviceOutput, ScopeLocal, []byte("data"), sk1)

	if err := Verify(msg, sk2); err != ErrHMACFailed {
		t.Fatalf("expected ErrHMACFailed for wrong key, got %v", err)
	}
}

// =========================================================================
// Channel-Type Consistency Tests
// =========================================================================

func TestCheckChannelType(t *testing.T) {
	// OC-only messages
	for _, mt := range []uint8{MsgObservation, MsgHello, MsgHeartbeat} {
		if err := CheckChannelType(ChannelOC, mt); err != nil {
			t.Fatalf("%s should be valid on OC: %v", MsgTypeStr(mt), err)
		}
		if err := CheckChannelType(ChannelIC, mt); err != ErrChannelViolation {
			t.Fatalf("%s should be rejected on IC", MsgTypeStr(mt))
		}
	}
	// IC-only messages
	for _, mt := range []uint8{MsgProposal, MsgApproval, MsgIntentAdv, MsgIntentWd} {
		if err := CheckChannelType(ChannelIC, mt); err != nil {
			t.Fatalf("%s should be valid on IC: %v", MsgTypeStr(mt), err)
		}
		if err := CheckChannelType(ChannelOC, mt); err != ErrChannelViolation {
			t.Fatalf("%s should be rejected on OC", MsgTypeStr(mt))
		}
	}
	// TEARDOWN on both
	if err := CheckChannelType(ChannelOC, MsgTeardown); err != nil {
		t.Fatal("TEARDOWN should be valid on OC")
	}
	if err := CheckChannelType(ChannelIC, MsgTeardown); err != nil {
		t.Fatal("TEARDOWN should be valid on IC")
	}
}

// =========================================================================
// Sequence Number Monotonicity Test
// =========================================================================

func TestSequenceMonotonicity(t *testing.T) {
	sk, _ := KeyGenerate(KeyTypeOKey)
	var lastSeq uint32
	for i := uint32(1); i <= 100; i++ {
		msg, err := BuildObservation(1, i, ObsDeviceOutput, ScopeLocal, []byte("x"), sk)
		if err != nil {
			t.Fatalf("build seq %d: %v", i, err)
		}
		hdr, _ := DeserializeHeader(msg)
		if hdr.SeqNum <= lastSeq {
			t.Fatalf("sequence not monotonic: %d <= %d", hdr.SeqNum, lastSeq)
		}
		lastSeq = hdr.SeqNum
	}
}

// =========================================================================
// O-Node Interop Test (Unix socket round-trip)
// =========================================================================

func TestONodeInterop(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "test-onode.sock")

	on, err := NewONode(0x211, "", socketPath)
	if err != nil {
		t.Fatalf("NewONode: %v", err)
	}
	defer on.Destroy()

	// Add test devices
	on.AddDevice(Device{Hostname: "R1", Host: "10.0.0.50", Vendor: "cisco_ios", NodeID: 0x50, Enabled: true})
	on.AddDevice(Device{Hostname: "FG", Host: "10.0.10.1", Vendor: "fortinet", NodeID: 0x101, Enabled: true})

	// Start O-Node in background
	started := make(chan struct{})
	go func() {
		close(started)
		on.Start()
	}()
	<-started
	// Wait for listener to be ready
	time.Sleep(50 * time.Millisecond)

	t.Run("heartbeat", func(t *testing.T) {
		resp, err := SendRequest(socketPath, &ONodeRequest{Action: "heartbeat"})
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		if len(resp) < HeaderSize {
			t.Fatalf("response too short: %d bytes", len(resp))
		}
		hdr, err := ValidateMessage(resp, on.OKey)
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		if hdr.Type != MsgHeartbeat {
			t.Fatalf("expected HEARTBEAT, got %s", MsgTypeStr(hdr.Type))
		}
		if hdr.Channel != ChannelOC {
			t.Fatal("heartbeat not on OC")
		}
		if hdr.NodeID != 0x211 {
			t.Fatalf("node_id: got 0x%x, want 0x211", hdr.NodeID)
		}
	})

	t.Run("list_devices", func(t *testing.T) {
		resp, err := SendRequest(socketPath, &ONodeRequest{Action: "list_devices"})
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		hdr, err := ValidateMessage(resp, on.OKey)
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		if hdr.Type != MsgObservation {
			t.Fatalf("expected OBSERVATION, got %s", MsgTypeStr(hdr.Type))
		}
		obs, _ := ParseObservation(resp[HeaderSize:])
		if obs.ObsType != ObsResourceState {
			t.Fatal("list_devices should be RESOURCE_STATE observation")
		}
		listing := string(obs.Data)
		if len(listing) == 0 {
			t.Fatal("empty device listing")
		}
		t.Logf("Device listing:\n%s", listing)
	})

	t.Run("execute", func(t *testing.T) {
		resp, err := SendRequest(socketPath, &ONodeRequest{
			Action:  "execute",
			Device:  "R1",
			Command: "show ip route",
		})
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		hdr, err := ValidateMessage(resp, on.OKey)
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		if hdr.Type != MsgObservation {
			t.Fatalf("expected OBSERVATION, got %s", MsgTypeStr(hdr.Type))
		}
		obs, _ := ParseObservation(resp[HeaderSize:])
		if obs.ObsType != ObsDeviceOutput {
			t.Fatal("execute should return DEVICE_OUTPUT")
		}
		t.Logf("Execute response: %s", string(obs.Data))
	})

	t.Run("execute_unknown_device", func(t *testing.T) {
		resp, err := SendRequest(socketPath, &ONodeRequest{
			Action:  "execute",
			Device:  "NONEXISTENT",
			Command: "show version",
		})
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		// Should still return a signed observation with error message
		hdr, err := ValidateMessage(resp, on.OKey)
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		if hdr.Type != MsgObservation {
			t.Fatal("error should still be wrapped in OBSERVATION")
		}
		obs, _ := ParseObservation(resp[HeaderSize:])
		if string(obs.Data) == "" {
			t.Fatal("expected error message in observation data")
		}
		t.Logf("Error observation: %s", string(obs.Data))
	})

	t.Run("sign_intent", func(t *testing.T) {
		resp, err := SendRequest(socketPath, &ONodeRequest{
			Action:  "sign_intent",
			Command: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		})
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		hdr, err := ValidateMessage(resp, on.OKey)
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		if hdr.Type != MsgObservation {
			t.Fatal("expected OBSERVATION")
		}
		obs, _ := ParseObservation(resp[HeaderSize:])
		if obs.ObsType != ObsIntentSigned {
			t.Fatalf("expected INTENT_SIGNED, got %s", ObsTypeStr(obs.ObsType))
		}
	})

	t.Run("bad_request", func(t *testing.T) {
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		conn.Write([]byte(`not json`))
		resp := make([]byte, 4)
		n, _ := conn.Read(resp)
		if n != 4 {
			t.Fatalf("expected 4-byte error code, got %d", n)
		}
		errCode := int32(binary.BigEndian.Uint32(resp[:4]))
		if Error(errCode) != ErrInvalidType {
			t.Fatalf("expected ErrInvalidType, got %d", errCode)
		}
	})

	t.Run("shutdown", func(t *testing.T) {
		data, _ := json.Marshal(&ONodeRequest{Action: "shutdown"})
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		conn.Write(data)
		conn.Close()
		time.Sleep(100 * time.Millisecond)
		if on.running.Load() {
			t.Fatal("O-Node should be stopped after shutdown")
		}
	})
}

// =========================================================================
// Interop: C-compatible wire format verification
// =========================================================================

func TestWireFormatCompatibility(t *testing.T) {
	// Build a message and verify its wire layout matches the C header format:
	// [0]     = version
	// [1]     = type
	// [2:4]   = length (big-endian)
	// [4:8]   = node_id (big-endian)
	// [8]     = channel
	// [9]     = tier
	// [10:12] = reserved (zero)
	// [12:16] = seq_num (big-endian)
	// [16:24] = timestamp_ns (big-endian)
	// [24:56] = hmac

	sk, _ := KeyGenerate(KeyTypeOKey)
	msg, err := BuildObservation(0x00000211, 7, ObsDeviceOutput, ScopeLocal, []byte("hello"), sk)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	// Header checks
	if msg[0] != 1 {
		t.Fatalf("wire[0] version: got %d", msg[0])
	}
	if msg[1] != MsgObservation {
		t.Fatalf("wire[1] type: got 0x%02x", msg[1])
	}
	wireLen := binary.BigEndian.Uint16(msg[2:4])
	if wireLen != uint16(len(msg)) {
		t.Fatalf("wire length: got %d, actual %d", wireLen, len(msg))
	}
	wireNodeID := binary.BigEndian.Uint32(msg[4:8])
	if wireNodeID != 0x211 {
		t.Fatalf("wire node_id: got 0x%x", wireNodeID)
	}
	if msg[8] != ChannelOC {
		t.Fatalf("wire channel: got 0x%02x", msg[8])
	}
	if msg[9] != TierGreen {
		t.Fatalf("wire tier: got 0x%02x", msg[9])
	}
	if msg[10] != 0 || msg[11] != 0 {
		t.Fatal("wire reserved not zero")
	}
	wireSeq := binary.BigEndian.Uint32(msg[12:16])
	if wireSeq != 7 {
		t.Fatalf("wire seq: got %d, want 7", wireSeq)
	}
	// Timestamp should be recent
	wireTS := binary.BigEndian.Uint64(msg[16:24])
	now := uint64(time.Now().UnixNano())
	if wireTS > now || wireTS < now-5_000_000_000 {
		t.Fatalf("wire timestamp looks wrong: %d (now: %d)", wireTS, now)
	}

	// Observation payload at [56:]
	// [56] = obs_type, [57] = obs_scope, [58:60] = data_len, [60:] = data
	if msg[56] != ObsDeviceOutput {
		t.Fatalf("obs_type: got 0x%02x", msg[56])
	}
	if msg[57] != ScopeLocal {
		t.Fatalf("obs_scope: got 0x%02x", msg[57])
	}
	obsDataLen := binary.BigEndian.Uint16(msg[58:60])
	if obsDataLen != 5 {
		t.Fatalf("obs_data_len: got %d, want 5", obsDataLen)
	}
	if string(msg[60:65]) != "hello" {
		t.Fatalf("obs_data: got %q", string(msg[60:65]))
	}
}

// =========================================================================
// Cross-channel forgery test
// =========================================================================

func TestCrossChannelForgery(t *testing.T) {
	// Verify that an R-Node cannot forge an observation by using its R-Key
	rk, _ := KeyGenerate(KeyTypeRKey)
	_, err := BuildObservation(1, 1, ObsDeviceOutput, ScopeLocal, []byte("forged"), rk)
	if err != ErrChannelViolation {
		t.Fatal("R-Key should not be able to sign observations")
	}

	// Verify that an O-Node cannot forge a proposal
	ok, _ := KeyGenerate(KeyTypeOKey)
	_, err = BuildProposal(1, 1, 100, PropRouteInject, 5,
		[]ObsRef{{1, 1}}, nil, ok)
	if err != ErrChannelViolation {
		t.Fatal("O-Key should not be able to sign proposals")
	}
}

// =========================================================================
// O-Node unit tests (non-socket)
// =========================================================================

func TestONodeSequenceIncrement(t *testing.T) {
	on, _ := NewONode(1, "", filepath.Join(t.TempDir(), "seq.sock"))
	defer on.Destroy()

	seqs := make(map[uint32]bool)
	for i := 0; i < 1000; i++ {
		s := on.NextSeq()
		if seqs[s] {
			t.Fatalf("duplicate sequence number: %d", s)
		}
		seqs[s] = true
	}
}

func TestONodeKeyPersistence(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "onode.key")

	// Create O-Node, save its key
	on1, _ := NewONode(1, "", filepath.Join(dir, "a.sock"))
	KeySaveFile(on1.OKey, keyPath)
	fp1 := on1.OKey.Fingerprint
	on1.Destroy()

	// Create another O-Node loading the same key
	on2, _ := NewONode(1, keyPath, filepath.Join(dir, "b.sock"))
	fp2 := on2.OKey.Fingerprint
	on2.Destroy()

	if fp1 != fp2 {
		t.Fatal("key persistence failed: fingerprints differ")
	}
}

// Ensure the O-Node socket file is cleaned up
func TestONodeSocketCleanup(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "cleanup.sock")
	on, _ := NewONode(1, "", socketPath)

	go on.Start()
	time.Sleep(50 * time.Millisecond)

	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Fatal("socket file should exist while running")
	}

	on.Destroy()
	time.Sleep(50 * time.Millisecond)

	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Fatal("socket file should be cleaned up after destroy")
	}
}
