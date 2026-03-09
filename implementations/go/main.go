// Copyright (c) 2026 Third Level IT LLC. All rights reserved.
// VIRP -- Verified Infrastructure Response Protocol
// O-Node Daemon -- Go implementation entry point
//
// Usage:
//   virp-onode-go [flags]
//
// Flags:
//   -node-id     uint32  Node ID (default: 0x211)
//   -okey        string  Path to O-Key file (default: generate new)
//   -socket      string  Unix socket path (default: /tmp/virp-onode.sock)
//   -devices     string  Path to devices.json

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/nhowardtli/virp/implementations/go/virp"
)

func main() {
	nodeID := flag.Uint("node-id", 0x211, "VIRP node ID")
	okeyPath := flag.String("okey", "", "path to O-Key file (empty = generate)")
	socketPath := flag.String("socket", virp.DefaultSocketPath, "Unix socket path")
	devicesPath := flag.String("devices", "", "path to devices.json")
	flag.Parse()

	fmt.Fprintf(os.Stderr, "VIRP O-Node (Go) v%d\n", virp.Version)
	fmt.Fprintf(os.Stderr, "Copyright (c) 2026 Third Level IT LLC\n\n")

	on, err := virp.NewONode(uint32(*nodeID), *okeyPath, *socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
	defer on.Destroy()

	// Load devices from JSON if provided
	if *devicesPath != "" {
		if err := loadDevices(on, *devicesPath); err != nil {
			fmt.Fprintf(os.Stderr, "FATAL: load devices: %v\n", err)
			os.Exit(1)
		}
	}

	// Handle signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		fmt.Fprintf(os.Stderr, "\n[O-Node] Received %s, shutting down...\n", sig)
		on.Shutdown()
	}()

	if err := on.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
}

// devicesJSON matches the /etc/virp/devices.json format from the C implementation.
type devicesJSON struct {
	Devices []deviceEntry `json:"devices"`
}

type deviceEntry struct {
	Hostname string `json:"hostname"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Vendor   string `json:"vendor"`
	NodeID   uint32 `json:"node_id"`
	Enabled  bool   `json:"enabled"`
}

func loadDevices(on *virp.ONode, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var cfg devicesJSON
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}

	for _, d := range cfg.Devices {
		if !d.Enabled {
			continue
		}
		port := uint16(d.Port)
		if port == 0 {
			port = 22
		}
		dev := virp.Device{
			Hostname: d.Hostname,
			Host:     d.Host,
			Port:     port,
			Username: d.Username,
			Vendor:   d.Vendor,
			NodeID:   d.NodeID,
			Enabled:  true,
		}
		if err := on.AddDevice(dev); err != nil {
			return fmt.Errorf("add device %s: %w", d.Hostname, err)
		}
	}
	return nil
}
