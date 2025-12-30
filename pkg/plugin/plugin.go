package plugin

import (
	"context"
	"github.com/saixpereos-debug/parashu/pkg/output"
)

// Plugin represents a generic Parashu plugin
type Plugin interface {
	Name() string
	Description() string
	Version() string
}

// ScannerPlugin is an interface for plugins that perform scanning or banner grabbing
type ScannerPlugin interface {
	Plugin
	// Execute runs the plugin against a target and port
	Execute(ctx context.Context, target string, port int) (output.PortResult, error)
}
