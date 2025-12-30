package banner_grabber

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/saixpereos-debug/parashu/pkg/output"
	"github.com/saixpereos-debug/parashu/pkg/plugin"
)

type BannerGrabberPlugin struct{}

func (p *BannerGrabberPlugin) Name() string {
	return "Banner Grabber"
}

func (p *BannerGrabberPlugin) Description() string {
	return "Grabs service banners over TCP"
}

func (p *BannerGrabberPlugin) Version() string {
	return "1.0.0"
}

func (p *BannerGrabberPlugin) Execute(ctx context.Context, target string, port int) (output.PortResult, error) {
	address := net.JoinHostPort(target, fmt.Sprintf("%d", port))
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return output.PortResult{}, err
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	banner := ""
	if n > 0 {
		banner = strings.TrimSpace(string(buf[:n]))
	}

	return output.PortResult{
		Port:     port,
		Protocol: "tcp",
		Banner:   banner,
	}, nil
}

// Ensure it implements the interface
var _ plugin.ScannerPlugin = (*BannerGrabberPlugin)(nil)
