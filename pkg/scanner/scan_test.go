package scanner

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/saixpereos-debug/parashu/internal/adaptive"
)

func TestScanner_Scan(t *testing.T) {
	// Start a local TCP server to test against
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().(*net.TCPAddr)
	port := addr.Port

	// Handler for the test server
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			fmt.Fprintf(conn, "SSH-2.0-TestServer\n")
			conn.Close()
		}
	}()

	s := NewScanner(adaptive.ProfileBalanced)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := s.Scan(ctx, "127.0.0.1", []int{port})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if len(res.Ports) != 1 {
		t.Errorf("expected 1 open port, got %d", len(res.Ports))
	}

	foundPort := res.Ports[0]
	if foundPort.Port != port {
		t.Errorf("expected port %d, got %d", port, foundPort.Port)
	}

	if foundPort.Service != "ssh" {
		t.Errorf("expected service ssh, got %s", foundPort.Service)
	}
}
