// Copyright (c) 2026 Third Level IT LLC. All rights reserved.
//
// The Go port implements none of the approval flow (propose → approve →
// apply). Per the unknown-field standard set by the obs_version fix, an
// execute request carrying a proposal_id must be REFUSED with the
// mirrored C error code — never silently served as a plain execute.

package virp

import (
	"encoding/binary"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestExecuteWithProposalIDRefused(t *testing.T) {
	sock := fmt.Sprintf("%s/virp-go-approval-test.sock", os.TempDir())
	os.Remove(sock)

	on, err := NewONode(0x60606060, "", sock)
	if err != nil {
		t.Fatalf("NewONode: %v", err)
	}
	defer on.Destroy()

	on.AddDevice(Device{Hostname: "R-GO", Host: "10.255.0.9", Port: 22,
		Vendor: "mock", NodeID: 0x60606060, Enabled: true})

	go on.Start()
	// Wait for the socket to appear.
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	resp, err := SendRequest(sock, &ONodeRequest{
		Action:     "execute",
		Device:     "R-GO",
		Command:    "configure terminal",
		ProposalID: "00112233445566778899aabbccddeeff",
	})
	if err != nil {
		t.Fatalf("SendRequest: %v", err)
	}
	if len(resp) != 4 {
		t.Fatalf("expected 4-byte refusal, got %d bytes", len(resp))
	}
	code := Error(int32(binary.BigEndian.Uint32(resp)))
	if code != ErrApprovalNotFound {
		t.Fatalf("expected ErrApprovalNotFound (%d), got %d",
			ErrApprovalNotFound, code)
	}

	// Control: the same request WITHOUT a proposal reference is served.
	resp, err = SendRequest(sock, &ONodeRequest{
		Action:  "execute",
		Device:  "R-GO",
		Command: "show version",
	})
	if err != nil {
		t.Fatalf("SendRequest (control): %v", err)
	}
	if len(resp) <= HeaderSize {
		t.Fatalf("control execute not served: %d bytes", len(resp))
	}
}
