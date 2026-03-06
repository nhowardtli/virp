// Copyright (c) 2026 Third Level IT LLC. All rights reserved.
// VIRP -- C/Go interop test
//
// Tests that messages built by the C implementation can be validated by Go,
// and messages built by Go can be validated by the C implementation.
// Also tests live round-trip with the running C O-Node daemon.
//
// Requires the C interop tool at /root/virp/build/test_interop_c
// and (optionally) a running C O-Node at /tmp/virp-onode.sock.

package virp

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const cInteropBin = "/root/virp/build/test_interop_c"

// writeMsgFile writes messages in the interop format: [4-byte BE length][message]
func writeMsgFile(path string, messages [][]byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, msg := range messages {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(msg)))
		if _, err := f.Write(lenBuf[:]); err != nil {
			return err
		}
		if _, err := f.Write(msg); err != nil {
			return err
		}
	}
	return nil
}

// readMsgFile reads messages from the interop format.
func readMsgFile(path string) ([][]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var msgs [][]byte
	off := 0
	for off+4 <= len(data) {
		msgLen := int(binary.BigEndian.Uint32(data[off : off+4]))
		off += 4
		if off+msgLen > len(data) {
			return nil, fmt.Errorf("truncated message at offset %d", off)
		}
		msg := make([]byte, msgLen)
		copy(msg, data[off:off+msgLen])
		msgs = append(msgs, msg)
		off += msgLen
	}
	return msgs, nil
}

// TestInterop_CGenerateGoValidate builds messages in C, validates in Go.
func TestInterop_CGenerateGoValidate(t *testing.T) {
	if _, err := os.Stat(cInteropBin); os.IsNotExist(err) {
		t.Skipf("C interop binary not found at %s", cInteropBin)
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "shared.key")
	msgPath := filepath.Join(dir, "c_messages.bin")

	// Generate a shared key
	sk, _ := KeyGenerate(KeyTypeOKey)
	if err := KeySaveFile(sk, keyPath); err != nil {
		t.Fatalf("save key: %v", err)
	}

	// Run C tool in generate mode
	cmd := exec.Command(cInteropBin, "generate", keyPath, msgPath)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("C generate failed: %v", err)
	}

	// Read C-generated messages
	msgs, err := readMsgFile(msgPath)
	if err != nil {
		t.Fatalf("read messages: %v", err)
	}
	if len(msgs) != 4 {
		t.Fatalf("expected 4 messages, got %d", len(msgs))
	}

	// Validate each in Go
	expectedTypes := []struct {
		msgType uint8
		name    string
	}{
		{MsgObservation, "OBSERVATION"},
		{MsgHeartbeat, "HEARTBEAT"},
		{MsgHello, "HELLO"},
		{MsgTeardown, "TEARDOWN"},
	}

	for i, msg := range msgs {
		t.Run(expectedTypes[i].name, func(t *testing.T) {
			hdr, err := ValidateMessage(msg, sk)
			if err != nil {
				t.Fatalf("Go validation of C message failed: %v", err)
			}
			if hdr.Type != expectedTypes[i].msgType {
				t.Fatalf("type: got %s, want %s",
					MsgTypeStr(hdr.Type), expectedTypes[i].name)
			}
			if hdr.NodeID != 0x211 {
				t.Fatalf("node_id: got 0x%x, want 0x211", hdr.NodeID)
			}
			if hdr.Channel != ChannelOC {
				t.Fatalf("channel: got %s, want OC", ChannelStr(hdr.Channel))
			}
			t.Logf("C->Go OK: %s, seq=%d, len=%d",
				MsgTypeStr(hdr.Type), hdr.SeqNum, hdr.Length)
		})
	}

	// Parse the observation payload specifically
	t.Run("parse_c_observation", func(t *testing.T) {
		obs, err := ParseObservation(msgs[0][HeaderSize:])
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if obs.ObsType != ObsDeviceOutput {
			t.Fatalf("obs_type: got %d, want DEVICE_OUTPUT", obs.ObsType)
		}
		if string(obs.Data) != "C-built observation payload" {
			t.Fatalf("data: got %q", string(obs.Data))
		}
		t.Logf("Parsed C observation data: %q", string(obs.Data))
	})

	// Parse the heartbeat payload
	t.Run("parse_c_heartbeat", func(t *testing.T) {
		hb, err := ParseHeartbeat(msgs[1][HeaderSize:])
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if hb.UptimeSeconds != 3600 {
			t.Fatalf("uptime: got %d, want 3600", hb.UptimeSeconds)
		}
		if !hb.OnodeOK || !hb.RnodeOK {
			t.Fatal("onode/rnode should be OK")
		}
		if hb.ActiveObservations != 42 {
			t.Fatalf("active_obs: got %d, want 42", hb.ActiveObservations)
		}
		t.Logf("Parsed C heartbeat: uptime=%d onode=%v active_obs=%d",
			hb.UptimeSeconds, hb.OnodeOK, hb.ActiveObservations)
	})
}

// TestInterop_GoGenerateCValidate builds messages in Go, validates in C.
func TestInterop_GoGenerateCValidate(t *testing.T) {
	if _, err := os.Stat(cInteropBin); os.IsNotExist(err) {
		t.Skipf("C interop binary not found at %s", cInteropBin)
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "shared.key")
	msgPath := filepath.Join(dir, "go_messages.bin")

	// Generate a shared key and save it
	sk, _ := KeyGenerate(KeyTypeOKey)
	if err := KeySaveFile(sk, keyPath); err != nil {
		t.Fatalf("save key: %v", err)
	}

	// Build messages in Go
	var msgs [][]byte

	// 1. OBSERVATION
	msg, err := BuildObservation(0x211, 1, ObsDeviceOutput, ScopeLocal,
		[]byte("Go-built observation payload"), sk)
	if err != nil {
		t.Fatalf("build observation: %v", err)
	}
	msgs = append(msgs, msg)

	// 2. HEARTBEAT
	msg, err = BuildHeartbeat(0x211, 2, 7200, true, true, 99, 0, sk)
	if err != nil {
		t.Fatalf("build heartbeat: %v", err)
	}
	msgs = append(msgs, msg)

	// 3. HELLO
	rk, _ := KeyGenerate(KeyTypeRKey)
	msg, err = BuildHello(0x211, 3, NodeHybrid, TierRed, sk, rk)
	if err != nil {
		t.Fatalf("build hello: %v", err)
	}
	msgs = append(msgs, msg)

	// 4. TEARDOWN
	msg, err = BuildTeardown(0x211, 4, ChannelOC, "Go interop teardown", sk)
	if err != nil {
		t.Fatalf("build teardown: %v", err)
	}
	msgs = append(msgs, msg)

	// Write to interop file
	if err := writeMsgFile(msgPath, msgs); err != nil {
		t.Fatalf("write messages: %v", err)
	}

	// Run C tool in validate mode
	cmd := exec.Command(cInteropBin, "validate", keyPath, msgPath)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("C validation of Go messages failed: %v\n%s", err, stderr.String())
	}
	t.Logf("C validation output:\n%s", stderr.String())

	// Verify all 4 passed
	output := stderr.String()
	if !strings.Contains(output, "4 passed") {
		t.Fatalf("not all messages passed C validation:\n%s", output)
	}
}

// TestInterop_BidirectionalRoundTrip does a full round-trip:
// Go builds → C validates → C builds → Go validates, same shared key.
func TestInterop_BidirectionalRoundTrip(t *testing.T) {
	if _, err := os.Stat(cInteropBin); os.IsNotExist(err) {
		t.Skipf("C interop binary not found at %s", cInteropBin)
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "rt.key")
	goMsgPath := filepath.Join(dir, "go.bin")
	cMsgPath := filepath.Join(dir, "c.bin")

	// Shared key
	sk, _ := KeyGenerate(KeyTypeOKey)
	KeySaveFile(sk, keyPath)

	// Go → file
	goMsgs := [][]byte{}
	for i := uint32(1); i <= 10; i++ {
		data := fmt.Sprintf("observation-%d-from-go", i)
		msg, _ := BuildObservation(0x211, i, ObsDeviceOutput, ScopeLocal, []byte(data), sk)
		goMsgs = append(goMsgs, msg)
	}
	writeMsgFile(goMsgPath, goMsgs)

	// C validates Go messages
	cmd := exec.Command(cInteropBin, "validate", keyPath, goMsgPath)
	var stderr1 strings.Builder
	cmd.Stderr = &stderr1
	if err := cmd.Run(); err != nil {
		t.Fatalf("C failed to validate Go messages: %v\n%s", err, stderr1.String())
	}
	if !strings.Contains(stderr1.String(), "10 passed") {
		t.Fatalf("C didn't pass all 10:\n%s", stderr1.String())
	}
	t.Logf("C validated 10 Go messages OK")

	// C generates messages with same key
	cmd = exec.Command(cInteropBin, "generate", keyPath, cMsgPath)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("C generate failed: %v", err)
	}

	// Go validates C messages
	cMsgs, err := readMsgFile(cMsgPath)
	if err != nil {
		t.Fatalf("read C messages: %v", err)
	}
	for i, msg := range cMsgs {
		hdr, err := ValidateMessage(msg, sk)
		if err != nil {
			t.Fatalf("Go validation of C message %d failed: %v", i+1, err)
		}
		t.Logf("Go validated C message %d: %s seq=%d",
			i+1, MsgTypeStr(hdr.Type), hdr.SeqNum)
	}
	t.Logf("Go validated %d C messages OK", len(cMsgs))
}

// TestInterop_LiveCONode talks to the running C O-Node daemon over its socket.
func TestInterop_LiveCONode(t *testing.T) {
	socketPath := "/tmp/virp-onode.sock"
	okeyPath := "/etc/virp/keys/onode.key"

	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Skip("C O-Node not running (no socket at /tmp/virp-onode.sock)")
	}

	// Load the C O-Node's key so we can verify signatures
	okey, err := KeyLoadFile(KeyTypeOKey, okeyPath)
	if err != nil {
		t.Skipf("Cannot load C O-Node key from %s: %v", okeyPath, err)
	}

	sendJSON := func(jsonStr string) []byte {
		t.Helper()
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		conn.Write([]byte(jsonStr))
		buf := make([]byte, MaxMessageSize)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		return buf[:n]
	}

	t.Run("heartbeat", func(t *testing.T) {
		resp := sendJSON(`{"action":"heartbeat"}`)
		if len(resp) < HeaderSize {
			t.Fatalf("response too short: %d bytes", len(resp))
		}
		hdr, err := ValidateMessage(resp, okey)
		if err != nil {
			t.Fatalf("Go failed to validate C O-Node heartbeat: %v", err)
		}
		if hdr.Type != MsgHeartbeat {
			t.Fatalf("expected HEARTBEAT, got %s", MsgTypeStr(hdr.Type))
		}
		hb, _ := ParseHeartbeat(resp[HeaderSize:])
		t.Logf("Live C O-Node heartbeat: uptime=%ds onode=%v obs=%d seq=%d",
			hb.UptimeSeconds, hb.OnodeOK, hb.ActiveObservations, hdr.SeqNum)
	})

	t.Run("list_devices", func(t *testing.T) {
		resp := sendJSON(`{"action":"list_devices"}`)
		hdr, err := ValidateMessage(resp, okey)
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		if hdr.Type != MsgObservation {
			t.Fatalf("expected OBSERVATION, got %s", MsgTypeStr(hdr.Type))
		}
		obs, _ := ParseObservation(resp[HeaderSize:])
		t.Logf("Live C O-Node device listing:\n%s", string(obs.Data))
	})

	t.Run("execute_fortigate", func(t *testing.T) {
		resp := sendJSON(`{"action":"execute","device":"FORTIGATE-200G","command":"get system status"}`)
		// Response may be a 4-byte error code if the device SSH session is stale
		if len(resp) == 4 {
			errCode := int32(binary.BigEndian.Uint32(resp))
			t.Logf("C O-Node returned error code %d (transient connection issue)", errCode)
			return
		}
		hdr, err := ValidateMessage(resp, okey)
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		if hdr.Type != MsgObservation {
			t.Fatalf("expected OBSERVATION, got %s", MsgTypeStr(hdr.Type))
		}
		obs, _ := ParseObservation(resp[HeaderSize:])
		output := string(obs.Data)
		if len(output) > 500 {
			output = output[:500] + "..."
		}
		t.Logf("Live execute on FORTIGATE-200G:\n%s", output)
	})

	t.Run("execute_cisco", func(t *testing.T) {
		resp := sendJSON(`{"action":"execute","device":"SW-3850","command":"show version"}`)
		if len(resp) == 4 {
			errCode := int32(binary.BigEndian.Uint32(resp))
			t.Logf("C O-Node returned error code %d (transient connection issue)", errCode)
			return
		}
		hdr, err := ValidateMessage(resp, okey)
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		if hdr.Type != MsgObservation {
			t.Fatalf("expected OBSERVATION, got %s", MsgTypeStr(hdr.Type))
		}
		obs, _ := ParseObservation(resp[HeaderSize:])
		output := string(obs.Data)
		if len(output) > 500 {
			output = output[:500] + "..."
		}
		t.Logf("Live execute on SW-3850:\n%s", output)
	})

	t.Run("sign_intent", func(t *testing.T) {
		resp := sendJSON(`{"action":"sign_intent","command":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}`)
		hdr, err := ValidateMessage(resp, okey)
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		obs, _ := ParseObservation(resp[HeaderSize:])
		if obs.ObsType != ObsIntentSigned {
			t.Fatalf("expected INTENT_SIGNED, got %s", ObsTypeStr(obs.ObsType))
		}
		t.Logf("Live sign_intent: type=%s seq=%d", ObsTypeStr(obs.ObsType), hdr.SeqNum)
	})
}
