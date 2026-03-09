// Copyright (c) 2026 Third Level IT LLC. All rights reserved.
// VIRP -- Verified Infrastructure Response Protocol
// O-Node Daemon -- the hardened observer process (Go implementation)
//
// The O-Node is the ONLY process that holds the O-Key.
// It listens on a Unix domain socket and accepts JSON requests.
// Responses are always binary VIRP messages (signed observations).

package virp

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultSocketPath  = "/tmp/virp-onode.sock"
	MaxDevices         = 64
	MaxClients         = 8
	RecvTimeoutSec     = 5
	MaxRequestSize     = 8192
	HeartbeatInterval  = 30 * time.Second
)

// ONodeRequest is the JSON request format over the Unix socket.
type ONodeRequest struct {
	Action  string `json:"action"`
	Device  string `json:"device,omitempty"`
	Command string `json:"command,omitempty"`

	// Chain fields
	SessionID    string `json:"session_id,omitempty"`
	ArtifactType string `json:"artifact_type,omitempty"`
	ArtifactID   string `json:"artifact_id,omitempty"`
	ArtifactHash string `json:"artifact_hash,omitempty"`
	FromSequence int64  `json:"from_sequence,omitempty"`
	ToSequence   int64  `json:"to_sequence,omitempty"`

	// Intent fields
	IntentID        string `json:"intent_id,omitempty"`
	IntentHash      string `json:"intent_hash,omitempty"`
	Confidence      string `json:"confidence,omitempty"`
	ExpiresAtNs     int64  `json:"expires_at_ns,omitempty"`
	MaxCommands     int32  `json:"max_commands,omitempty"`
	IntentJSON      string `json:"intent_json,omitempty"`
	ProposedActions string `json:"proposed_actions,omitempty"`
	Constraints     string `json:"constraints,omitempty"`
}

// Device describes a managed network device.
type Device struct {
	Hostname string `json:"hostname"`
	Host     string `json:"host"`
	Port     uint16 `json:"port"`
	Username string `json:"username"`
	Vendor   string `json:"vendor"`
	NodeID   uint32 `json:"node_id"`
	Enabled  bool   `json:"enabled"`
}

// ONode is the O-Node daemon state.
type ONode struct {
	NodeID     uint32
	OKey       *SigningKey
	SocketPath string

	devices []Device
	seqNum  atomic.Uint32

	listener net.Listener
	running  atomic.Bool
	mu       sync.Mutex

	uptimeStart      time.Time
	observationsSent atomic.Uint32
	errors           atomic.Uint32

	logger *log.Logger
}

// NewONode creates a new O-Node with the given node ID.
// If okeyPath is empty, a new key is generated.
// If socketPath is empty, DefaultSocketPath is used.
func NewONode(nodeID uint32, okeyPath, socketPath string) (*ONode, error) {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}

	on := &ONode{
		NodeID:      nodeID,
		SocketPath:  socketPath,
		uptimeStart: time.Now(),
		logger:      log.New(os.Stderr, "[O-Node] ", log.LstdFlags),
	}

	// Load or generate O-Key
	if okeyPath != "" {
		sk, err := KeyLoadFile(KeyTypeOKey, okeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load O-Key from %s: %w", okeyPath, err)
		}
		on.OKey = sk
		on.logger.Printf("Loaded O-Key from %s", okeyPath)
	} else {
		sk, err := KeyGenerate(KeyTypeOKey)
		if err != nil {
			return nil, fmt.Errorf("failed to generate O-Key: %w", err)
		}
		on.OKey = sk
		on.logger.Print("Generated new O-Key")
	}

	on.logger.Printf("Fingerprint: %x", on.OKey.Fingerprint)
	return on, nil
}

// AddDevice adds a device to the O-Node inventory.
func (on *ONode) AddDevice(dev Device) error {
	on.mu.Lock()
	defer on.mu.Unlock()
	if len(on.devices) >= MaxDevices {
		return ErrMessageTooLarge
	}
	on.devices = append(on.devices, dev)
	on.logger.Printf("Added device: %s (%s) node_id=0x%08x", dev.Hostname, dev.Host, dev.NodeID)
	return nil
}

// NextSeq returns the next monotonically increasing sequence number.
func (on *ONode) NextSeq() uint32 {
	return on.seqNum.Add(1)
}

// Start begins the O-Node event loop. Blocks until Shutdown is called.
func (on *ONode) Start() error {
	// Remove stale socket
	os.Remove(on.SocketPath)

	listener, err := net.Listen("unix", on.SocketPath)
	if err != nil {
		return fmt.Errorf("listen %s: %w", on.SocketPath, err)
	}
	on.listener = listener

	// Allow non-root users to connect
	os.Chmod(on.SocketPath, 0777)

	on.logger.Printf("Listening on %s", on.SocketPath)
	on.logger.Printf("Node ID: 0x%08x", on.NodeID)
	on.logger.Printf("Devices: %d", len(on.devices))
	on.logger.Print("Ready.")

	on.running.Store(true)

	// Heartbeat goroutine
	go on.heartbeatLoop()

	for on.running.Load() {
		conn, err := listener.Accept()
		if err != nil {
			if on.running.Load() {
				on.logger.Printf("accept: %v", err)
			}
			continue
		}
		go on.handleClient(conn)
	}

	on.logger.Print("Shutting down...")
	return nil
}

// Shutdown signals the O-Node to stop.
func (on *ONode) Shutdown() {
	on.running.Store(false)
	if on.listener != nil {
		on.listener.Close()
	}
}

// Destroy cleans up all resources.
func (on *ONode) Destroy() {
	on.Shutdown()
	os.Remove(on.SocketPath)
	KeyDestroy(on.OKey)
	on.logger.Printf("Destroyed. %d observations signed.", on.observationsSent.Load())
}

func (on *ONode) heartbeatLoop() {
	ticker := time.NewTicker(HeartbeatInterval)
	defer ticker.Stop()
	for on.running.Load() {
		<-ticker.C
		if !on.running.Load() {
			return
		}
		uptime := uint32(time.Since(on.uptimeStart).Seconds())
		on.logger.Printf("Heartbeat: uptime=%ds obs=%d seq=%d",
			uptime, on.observationsSent.Load(), on.seqNum.Load())
	}
}

func (on *ONode) handleClient(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(RecvTimeoutSec * time.Second))

	buf := make([]byte, MaxRequestSize)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}

	var req ONodeRequest
	if err := json.Unmarshal(buf[:n], &req); err != nil {
		on.sendErrorCode(conn, ErrInvalidType)
		return
	}

	switch req.Action {
	case "execute":
		on.handleExecute(conn, &req)
	case "health":
		on.handleHealth(conn, &req)
	case "heartbeat":
		on.handleHeartbeat(conn)
	case "list_devices":
		on.handleListDevices(conn)
	case "sign_intent":
		on.handleSignIntent(conn, &req)
	case "sign_outcome":
		on.handleSignOutcome(conn, &req)
	case "shutdown":
		on.logger.Print("Shutdown requested")
		on.Shutdown()
	default:
		on.sendErrorCode(conn, ErrInvalidType)
	}
}

func (on *ONode) sendErrorCode(conn net.Conn, code Error) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(int32(code)))
	conn.Write(buf[:])
}

func (on *ONode) handleExecute(conn net.Conn, req *ONodeRequest) {
	if req.Device == "" || req.Command == "" {
		on.sendErrorCode(conn, ErrNullPtr)
		return
	}

	dev := on.findDevice(req.Device)
	if dev == nil {
		errMsg := fmt.Sprintf("ERROR: device '%s' not found", req.Device)
		msg, err := BuildObservation(on.NodeID, on.NextSeq(),
			ObsDeviceOutput, ScopeLocal, []byte(errMsg), on.OKey)
		if err != nil {
			on.sendErrorCode(conn, ErrBufferTooSmall)
			return
		}
		conn.Write(msg)
		return
	}

	// In this Go implementation, we produce a signed observation
	// acknowledging the command. Real device execution would go through
	// a driver interface (SSH, REST) like the C implementation.
	output := fmt.Sprintf("[go-onode] execute on %s: %s (driver not connected)", dev.Hostname, req.Command)
	msg, err := BuildObservation(dev.NodeID, on.NextSeq(),
		ObsDeviceOutput, ScopeLocal, []byte(output), on.OKey)
	if err != nil {
		on.sendErrorCode(conn, ErrBufferTooSmall)
		return
	}
	on.observationsSent.Add(1)
	conn.Write(msg)
}

func (on *ONode) handleHealth(conn net.Conn, req *ONodeRequest) {
	if req.Device == "" {
		on.sendErrorCode(conn, ErrNullPtr)
		return
	}
	dev := on.findDevice(req.Device)
	if dev == nil {
		errMsg := fmt.Sprintf("ERROR: device '%s' not found", req.Device)
		msg, _ := BuildObservation(on.NodeID, on.NextSeq(),
			ObsDeviceOutput, ScopeLocal, []byte(errMsg), on.OKey)
		conn.Write(msg)
		return
	}
	output := fmt.Sprintf("[go-onode] health check: %s OK", dev.Hostname)
	msg, err := BuildObservation(dev.NodeID, on.NextSeq(),
		ObsDeviceOutput, ScopeLocal, []byte(output), on.OKey)
	if err != nil {
		on.sendErrorCode(conn, ErrBufferTooSmall)
		return
	}
	on.observationsSent.Add(1)
	conn.Write(msg)
}

func (on *ONode) handleHeartbeat(conn net.Conn) {
	uptime := uint32(time.Since(on.uptimeStart).Seconds())
	msg, err := BuildHeartbeat(on.NodeID, on.NextSeq(), uptime,
		true, true, uint16(on.observationsSent.Load()), 0, on.OKey)
	if err != nil {
		on.sendErrorCode(conn, ErrBufferTooSmall)
		return
	}
	conn.Write(msg)
}

func (on *ONode) handleListDevices(conn net.Conn) {
	on.mu.Lock()
	devs := make([]Device, len(on.devices))
	copy(devs, on.devices)
	on.mu.Unlock()

	listing := fmt.Sprintf("VIRP O-Node Device Inventory (%d devices)\n"+
		"%-16s %-16s %-12s %-8s\n"+
		"-----------------------------------------------------\n",
		len(devs), "Hostname", "Host", "Vendor", "NodeID")
	for _, d := range devs {
		listing += fmt.Sprintf("%-16s %-16s %-12s %08x\n",
			d.Hostname, d.Host, d.Vendor, d.NodeID)
	}

	msg, err := BuildObservation(on.NodeID, on.NextSeq(),
		ObsResourceState, ScopeLocal, []byte(listing), on.OKey)
	if err != nil {
		on.sendErrorCode(conn, ErrBufferTooSmall)
		return
	}
	on.observationsSent.Add(1)
	conn.Write(msg)
}

func (on *ONode) handleSignIntent(conn net.Conn, req *ONodeRequest) {
	if req.Command == "" {
		on.sendErrorCode(conn, ErrNullPtr)
		return
	}
	msg, err := BuildObservation(on.NodeID, on.NextSeq(),
		ObsIntentSigned, ScopeLocal, []byte(req.Command), on.OKey)
	if err != nil {
		on.sendErrorCode(conn, ErrBufferTooSmall)
		return
	}
	on.observationsSent.Add(1)
	conn.Write(msg)
}

func (on *ONode) handleSignOutcome(conn net.Conn, req *ONodeRequest) {
	if req.Command == "" {
		on.sendErrorCode(conn, ErrNullPtr)
		return
	}
	msg, err := BuildObservation(on.NodeID, on.NextSeq(),
		ObsOutcomeSigned, ScopeLocal, []byte(req.Command), on.OKey)
	if err != nil {
		on.sendErrorCode(conn, ErrBufferTooSmall)
		return
	}
	on.observationsSent.Add(1)
	conn.Write(msg)
}

func (on *ONode) findDevice(hostname string) *Device {
	on.mu.Lock()
	defer on.mu.Unlock()
	for i := range on.devices {
		if on.devices[i].Hostname == hostname {
			return &on.devices[i]
		}
	}
	return nil
}

// SendRequest sends a JSON request to the O-Node socket and returns the raw response.
// This is a client helper for interacting with a running O-Node.
func SendRequest(socketPath string, req *ONodeRequest) ([]byte, error) {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", socketPath, err)
	}
	defer conn.Close()

	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write(data); err != nil {
		return nil, err
	}

	// Read response — may arrive in multiple chunks for large messages.
	// First read gets the header; if we have a valid length, keep reading.
	resp := make([]byte, MaxMessageSize)
	total := 0
	for {
		n, err := conn.Read(resp[total:])
		if n > 0 {
			total += n
		}
		if err != nil {
			break
		}
		// If we have at least a header, check if we have the full message
		if total >= HeaderSize {
			msgLen := int(binary.BigEndian.Uint16(resp[2:4]))
			if msgLen >= HeaderSize && total >= msgLen {
				break
			}
		}
	}
	if total == 0 {
		return nil, fmt.Errorf("empty response from O-Node")
	}
	return resp[:total], nil
}
