package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	portsFlag       string
	timeoutFlag     time.Duration
	rateLimitFlag   int
	outputFlag      string
	outputFileFlag  string
	bannersOnlyFlag bool
	onlineFallback  bool
	apiKey          string
	excludeFlag     string
	excludeFileFlag string
	targetFileFlag  string
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Start a vulnerability scan",
	Long: `Scans the specified target (IP, CIDR, or Hostname) for open ports, 
detects services, and identifies vulnerabilities using the local offline database.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Input Validation
		if len(args) == 0 && targetFileFlag == "" {
			fmt.Println("Error: No target specified. Use [target] or --file <path>")
			cmd.Help()
			os.Exit(1)
		}
		if len(args) > 0 && targetFileFlag != "" {
			fmt.Println("Error: Cannot specify both [target] and --file")
			os.Exit(1)
		}

		if outputFlag == "html" && outputFileFlag == "" {
			fmt.Println("Error: --output-file is required when --output is html")
			os.Exit(1)
		}

		// Conflict Checks
		if bannersOnlyFlag && onlineFallback {
			fmt.Println("Warning: --banners-only implied, ignoring --online-fallback")
			onlineFallback = false
		}

		// Prepare Scan Options (Placeholder for now)
		fmt.Println("Starting Parashu Scan...")
		fmt.Printf("Targets: %v (File: %s)\n", args, targetFileFlag)
		fmt.Printf("Ports: %s\n", portsFlag)
		fmt.Printf("Rate Limit: %d\n", rateLimitFlag)
		fmt.Printf("Timeout: %s\n", timeoutFlag)
		fmt.Printf("Output: %s (File: %s)\n", outputFlag, outputFileFlag)

		// TODO: Parse Targets
		// TODO: Parse Ports
		// TODO: Initialize Scanner
		// TODO: Run Scan
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	// Define Flags
	scanCmd.Flags().StringVar(&portsFlag, "ports", "top1000", "Ports to scan (top1000, common, all, range 1-65535, or list 22,80)")
	scanCmd.Flags().DurationVar(&timeoutFlag, "timeout", 2*time.Second, "Timeout per port scan")
	scanCmd.Flags().IntVar(&rateLimitFlag, "rate-limit", 100, "Concurrent connections limit")
	scanCmd.Flags().StringVar(&outputFlag, "output", "table", "Output format (table, json, html)")
	scanCmd.Flags().StringVar(&outputFileFlag, "output-file", "", "Write output to file")

	scanCmd.Flags().BoolVar(&bannersOnlyFlag, "banners-only", false, "Scan for banners only, skip CVE lookup")
	scanCmd.Flags().BoolVar(&onlineFallback, "online-fallback", false, "Query online APIs if local DB miss")
	scanCmd.Flags().StringVar(&apiKey, "api-key", "", "API Key for online enrichment")

	scanCmd.Flags().StringVar(&excludeFlag, "exclude", "", "Comma-separated IPs/CIDRs to exclude")
	scanCmd.Flags().StringVar(&excludeFileFlag, "exclude-file", "", "File containing IPs to exclude")
	scanCmd.Flags().StringVarP(&targetFileFlag, "file", "f", "", "File containing targets to scan")

	// Bind flags to viper for config precedence
	viper.BindPFlag("ports", scanCmd.Flags().Lookup("ports"))
	viper.BindPFlag("timeout", scanCmd.Flags().Lookup("timeout"))
	viper.BindPFlag("rate-limit", scanCmd.Flags().Lookup("rate-limit"))
	viper.BindPFlag("online-fallback", scanCmd.Flags().Lookup("online-fallback"))
	viper.BindPFlag("api-key", scanCmd.Flags().Lookup("api-key"))
}
