package fingerprint

import (
	"context"
	"strings"
	"time"
)

// ServiceDetails holds extended information about a discovered service
type ServiceDetails struct {
	Service string
	Version string
	CPE     string
	Extras  map[string]string
}

// Fingerprinter defines the interface for service detection
type Fingerprinter interface {
	Fingerprint(ctx context.Context, host string, port int) (*ServiceDetails, error)
}

// Engine implements the Fingerprinter interface
type Engine struct {
	Timeout time.Duration
}

// NewEngine creates a new fingerprinting engine
func NewEngine(timeout time.Duration) *Engine {
	return &Engine{Timeout: timeout}
}

// Fingerprint attempts to identify the service on a given port
// This is a modernized skeletal implementation that would support deeper inspection
func (e *Engine) Fingerprint(ctx context.Context, host string, port int, banner string) *ServiceDetails {
	// Basic heuristic based on banner + port
	// In the future, this would send probes over the connection

	details := &ServiceDetails{
		Service: "unknown",
		Version: "",
		Extras:  make(map[string]string),
	}

	// 1. Heuristic from Banner
	if banner != "" {
		if strings.Contains(strings.ToLower(banner), "ssh") {
			details.Service = "ssh"
			details.Version = strings.TrimSpace(banner)
			details.CPE = "cpe:/a:openssh:openssh" // Example guess
		} else if strings.Contains(strings.ToLower(banner), "http") {
			details.Service = "http"
			details.Version = strings.TrimSpace(banner)
		}
	}

	// 2. Port Fallback
	if details.Service == "unknown" {
		details.Service = guessServiceByPort(port)
	}

	return details
}

func guessServiceByPort(port int) string {
	services := map[int]string{
		21:   "ftp",
		22:   "ssh",
		23:   "telnet",
		25:   "smtp",
		53:   "dns",
		80:   "http",
		110:  "pop3",
		143:  "imap",
		443:  "https",
		3306: "mysql",
		5432: "postgresql",
		8080: "http-alt",
	}
	if v, ok := services[port]; ok {
		return v
	}
	return "unknown"
}
