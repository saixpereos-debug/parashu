package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/saixpereos-debug/parashu/pkg/layers"

	"github.com/spf13/cobra"
)

var scannerRegistry = map[string]layers.LayerScanner{
	"physical":     &layers.PhysicalScanner{NameStr: "HardwareEvasionSimulator"},
	"datalink":     &layers.DataLinkScanner{NameStr: "SwitchEvasionTester"},
	"network":      &layers.NetworkScanner{NameStr: "StandardNetworkScanner"},
	"transport":    &layers.TransportScanner{NameStr: "StandardTransportScanner"},
	"session":      &layers.SessionScanner{NameStr: "SessionHijackSimulator"},
	"presentation": &layers.PresentationScanner{NameStr: "DataFormatTester"},
	"application":  &layers.ApplicationScanner{NameStr: "AppLayerExploitationTester"},
}

var (
	layerNameFlag    string
	evasionLevelFlag int
	customArgsFlag   []string
)

var layerScanCmd = &cobra.Command{
	Use:   "layer-scan [target]",
	Short: "Perform layer-specific red team scans",
	Long: `Executes specialized scans targeted at specific OSI layers (Network, Data Link, etc.)
with advanced evasion and red teaming capabilities.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Error: target required")
			os.Exit(1)
		}
		target := args[0]

		fmt.Printf("Starting Red Team Layer Scan on %s (Layer: %s, Evasion: %d)...\n",
			target, layerNameFlag, evasionLevelFlag)

		cfg := layers.ScanConfig{
			Target:       target,
			Layer:        layers.Layer(layerNameFlag),
			Timeout:      5 * time.Second,
			EvasionLevel: evasionLevelFlag,
			CustomArgs:   make(map[string]string),
		}

		// Parse custom args
		for _, arg := range customArgsFlag {
			parts := splitArg(arg)
			if len(parts) == 2 {
				cfg.CustomArgs[parts[0]] = parts[1]
			}
		}

		// Find Scanner
		scanner, ok := scannerRegistry[layerNameFlag]
		if !ok {
			fmt.Printf("Error: No scanner implemented for layer %s yet.\n", layerNameFlag)
			return
		}

		result, err := scanner.Scan(cmd.Context(), cfg)
		if err != nil {
			fmt.Printf("Error during scan: %v\n", err)
			return
		}

		fmt.Printf("Scan completed with status: %s\n", result.Status)
		for _, finding := range result.Findings {
			fmt.Printf("[%s] %s: %s\n", finding.Severity, finding.ID, finding.Summary)
		}
	},
}

func splitArg(arg string) []string {
	// Simple key=value split
	idx := findChar(arg, '=')
	if idx == -1 {
		return nil
	}
	return []string{arg[:idx], arg[idx+1:]}
}

func findChar(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func init() {
	rootCmd.AddCommand(layerScanCmd)

	layerScanCmd.Flags().StringVar(&layerNameFlag, "layer", "network", "Target OSI layer (network, transport, datalink, etc.)")
	layerScanCmd.Flags().IntVar(&evasionLevelFlag, "evasion", 1, "Evasion sophistication (0-2)")
	layerScanCmd.Flags().StringSliceVar(&customArgsFlag, "arg", []string{}, "Custom arguments for the layer module (key=value)")
}
