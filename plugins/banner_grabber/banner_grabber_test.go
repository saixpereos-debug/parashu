package banner_grabber

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestBannerGrabberPlugin_Execute(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().(*net.TCPAddr)
	port := addr.Port

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		fmt.Fprintf(conn, "Test-Banner\n")
		conn.Close()
	}()

	p := &BannerGrabberPlugin{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := p.Execute(ctx, "127.0.0.1", port)
	if err != nil {
		t.Fatalf("plugin execution failed: %v", err)
	}

	if res.Banner != "Test-Banner" {
		t.Errorf("expected banner Test-Banner, got %s", res.Banner)
	}
}
