package layers

import (
	"context"
	"time"
)

// Layer represents an OSI layer
type Layer string

const (
	LayerPhysical     Layer = "physical"     // Layer 1
	LayerDataLink     Layer = "datalink"     // Layer 2
	LayerNetwork      Layer = "network"      // Layer 3
	LayerTransport    Layer = "transport"    // Layer 4
	LayerSession      Layer = "session"      // Layer 5
	LayerPresentation Layer = "presentation" // Layer 6
	LayerApplication  Layer = "application"  // Layer 7
)

// ScanConfig defines general configuration for layer-specific scans
type ScanConfig struct {
	Target       string
	Layer        Layer
	Timeout      time.Duration
	EvasionLevel int // 0: none, 1: basic, 2: advanced
	CustomArgs   map[string]string
}

// Result represents the outcome of a layer-specific scan
type Result struct {
	Layer     Layer
	Status    string                 // e.g., "vulnerable", "secure", "unknown"
	Findings  []Finding              // Specific discoveries
	RawOutput map[string]interface{} // For debugging or specialized tools
	Timestamp time.Time
}

// Finding represents a single discovery within a layer scan
type Finding struct {
	ID          string // e.g., "CVE-2024-XXXX" or "VLAN-HOPPING"
	Summary     string
	Severity    string // e.g., "high", "medium", "low", "info"
	Description string
	Remediation string
}

// LayerScanner is the interface that all layer-specific scanning modules must implement
type LayerScanner interface {
	Name() string
	SupportedLayers() []Layer
	Scan(ctx context.Context, config ScanConfig) (Result, error)
}
