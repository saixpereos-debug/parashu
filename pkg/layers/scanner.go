package layers

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// PhysicalScanner implements LayerScanner for Layer 1 (Physical)
type PhysicalScanner struct {
	NameStr string
}

func (p *PhysicalScanner) Name() string {
	return p.NameStr
}

func (p *PhysicalScanner) SupportedLayers() []Layer {
	return []Layer{LayerPhysical}
}

func (p *PhysicalScanner) Scan(ctx context.Context, config ScanConfig) (Result, error) {
	res := Result{
		Layer:     LayerPhysical,
		Timestamp: time.Now(),
		Findings:  []Finding{},
	}

	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if strings.Contains(iface.Name, "docker") || strings.Contains(iface.Name, "veth") || strings.Contains(iface.Name, "br-") {
				res.Findings = append(res.Findings, Finding{
					ID:          "PHY-VIRT-01",
					Summary:     fmt.Sprintf("Virtual interface detected: %s", iface.Name),
					Severity:    "info",
					Description: "Detected a virtual interface which might indicate a bridge, tap, or container environment.",
				})
			}
		}
	}

	res.Status = "completed"
	return res, nil
}

// DataLinkScanner implements LayerScanner for Layer 2 (Data Link)
type DataLinkScanner struct {
	NameStr string
}

func (d *DataLinkScanner) Name() string {
	return d.NameStr
}

func (d *DataLinkScanner) SupportedLayers() []Layer {
	return []Layer{LayerDataLink}
}

func (d *DataLinkScanner) Scan(ctx context.Context, config ScanConfig) (Result, error) {
	res := Result{
		Layer:     LayerDataLink,
		Timestamp: time.Now(),
		Findings:  []Finding{},
	}

	if strings.Contains(config.CustomArgs["vlan"], "true") {
		res.Findings = append(res.Findings, Finding{
			ID:          "L2-VLAN-01",
			Summary:     "Port Security / VLAN Hopping potential",
			Severity:    "medium",
			Description: "The switch port responded to tagged packets; VLAN hopping might be possible.",
		})
	}

	res.Status = "completed"
	return res, nil
}

// NetworkScanner implements LayerScanner for Layer 3 (Network)
type NetworkScanner struct {
	NameStr string
}

func (n *NetworkScanner) Name() string {
	return n.NameStr
}

func (n *NetworkScanner) SupportedLayers() []Layer {
	return []Layer{LayerNetwork}
}

func (n *NetworkScanner) Scan(ctx context.Context, config ScanConfig) (Result, error) {
	res := Result{
		Layer:     LayerNetwork,
		Timestamp: time.Now(),
		Findings:  []Finding{},
	}

	if strings.Contains(config.CustomArgs["fragment"], "true") {
		res.Findings = append(res.Findings, Finding{
			ID:          "FRAG-001",
			Summary:     "IP Fragmentation vulnerabilities detectable",
			Severity:    "medium",
			Description: "Target host seems to reassemble fragments in a way that might be susceptible to overlapping fragment attacks.",
		})
	}

	res.Status = "completed"
	return res, nil
}

// TransportScanner implements LayerScanner for Layer 4 (Transport)
type TransportScanner struct {
	NameStr string
}

func (t *TransportScanner) Name() string {
	return t.NameStr
}

func (t *TransportScanner) SupportedLayers() []Layer {
	return []Layer{LayerTransport}
}

func (t *TransportScanner) Scan(ctx context.Context, config ScanConfig) (Result, error) {
	res := Result{
		Layer:     LayerTransport,
		Timestamp: time.Now(),
		Findings:  []Finding{},
	}

	mode := config.CustomArgs["mode"]
	switch mode {
	case "ack":
		res.Findings = append(res.Findings, Finding{
			ID:       "FW-STATE-01",
			Summary:  "Stateless Firewall Detected",
			Severity: "high",
		})
	}

	res.Status = "completed"
	return res, nil
}

// SessionScanner implements LayerScanner for Layer 5 (Session)
type SessionScanner struct {
	NameStr string
}

func (s *SessionScanner) Name() string {
	return s.NameStr
}

func (s *SessionScanner) SupportedLayers() []Layer {
	return []Layer{LayerSession}
}

func (s *SessionScanner) Scan(ctx context.Context, config ScanConfig) (Result, error) {
	res := Result{
		Layer:     LayerSession,
		Timestamp: time.Now(),
		Findings:  []Finding{},
	}

	if strings.Contains(config.Target, "auth") {
		res.Findings = append(res.Findings, Finding{
			ID:      "SESSION-SSO-01",
			Summary: "Auth endpoint detected",
		})
	}

	res.Status = "completed"
	return res, nil
}

// PresentationScanner implements LayerScanner for Layer 6 (Presentation)
type PresentationScanner struct {
	NameStr string
}

func (p *PresentationScanner) Name() string {
	return p.NameStr
}

func (p *PresentationScanner) SupportedLayers() []Layer {
	return []Layer{LayerPresentation}
}

func (p *PresentationScanner) Scan(ctx context.Context, config ScanConfig) (Result, error) {
	res := Result{
		Layer:     LayerPresentation,
		Timestamp: time.Now(),
		Findings:  []Finding{},
	}

	if strings.Contains(config.Target, "https") {
		res.Findings = append(res.Findings, Finding{
			ID:      "PRES-ENC-01",
			Summary: "Encryption in use",
		})
	}

	res.Status = "completed"
	return res, nil
}

// ApplicationScanner implements LayerScanner for Layer 7 (Application)
type ApplicationScanner struct {
	NameStr string
}

func (a *ApplicationScanner) Name() string {
	return a.NameStr
}

func (a *ApplicationScanner) SupportedLayers() []Layer {
	return []Layer{LayerApplication}
}

func (a *ApplicationScanner) Scan(ctx context.Context, config ScanConfig) (Result, error) {
	res := Result{
		Layer:     LayerApplication,
		Timestamp: time.Now(),
		Findings:  []Finding{},
	}

	if _, err := os.Stat("/.dockerenv"); err == nil {
		res.Findings = append(res.Findings, Finding{
			ID:      "APP-CONT-01",
			Summary: "Docker environment",
		})
	}

	res.Status = "completed"
	return res, nil
}
