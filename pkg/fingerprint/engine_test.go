package fingerprint

import (
	"context"
	"testing"
	"time"
)

func TestEngine_Fingerprint(t *testing.T) {
	engine := NewEngine(1 * time.Second)
	ctx := context.Background()

	tests := []struct {
		name     string
		host     string
		port     int
		banner   string
		expected string
	}{
		{
			name:     "SSH Detection",
			host:     "127.0.0.1",
			port:     22,
			banner:   "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
			expected: "ssh",
		},
		{
			name:     "HTTP Detection",
			host:     "127.0.0.1",
			port:     80,
			banner:   "HTTP/1.1 200 OK",
			expected: "http",
		},
		{
			name:     "Port Fallback",
			host:     "127.0.0.1",
			port:     3306,
			banner:   "",
			expected: "mysql",
		},
		{
			name:     "Unknown Service",
			host:     "127.0.0.1",
			port:     9999,
			banner:   "",
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			details := engine.Fingerprint(ctx, tt.host, tt.port, tt.banner)
			if details.Service != tt.expected {
				t.Errorf("expected service %s, got %s", tt.expected, details.Service)
			}
		})
	}
}
