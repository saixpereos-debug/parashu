package cmd

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/saixpereos-debug/parashu/internal/adaptive"
	"github.com/saixpereos-debug/parashu/pkg/exploit"
	"github.com/saixpereos-debug/parashu/pkg/output"
	"github.com/saixpereos-debug/parashu/pkg/scanner"
	"github.com/saixpereos-debug/parashu/pkg/vuln"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	portsFlag       string
	profileFlag     string // New flag for adaptive profile
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

	// Stealth & Evasion Flags
	noPingFlag     bool
	proxiesFlag    string
	dataLengthFlag int
	scanDelayFlag  string

	// Shorthand Timing
	t0Flag bool
	t1Flag bool
	t2Flag bool
	t3Flag bool
	t4Flag bool
	t5Flag bool

	exploitMatchFlag bool
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

		// Initialize Output Writer
		writer, err := output.NewWriter(outputFlag)
		if err != nil {
			fmt.Printf("Error initializing output: %v\n", err)
			os.Exit(1)
		}

		var outWriter = os.Stdout
		if outputFileFlag != "" {
			f, err := os.Create(outputFileFlag)
			if err != nil {
				fmt.Printf("Error creating output file: %v\n", err)
				os.Exit(1)
			}
			defer f.Close()
			outWriter = f
		}

		// Parse Targets
		targets, err := parseTargets(args, targetFileFlag)
		if err != nil {
			fmt.Printf("Error parsing targets: %v\n", err)
			os.Exit(1)
		}

		// Parse Ports
		ports, err := parsePorts(portsFlag)
		if err != nil {
			fmt.Printf("Error parsing ports: %v\n", err)
			os.Exit(1)
		}

		// Determine Profile
		profile := profileFlag
		if t0Flag {
			profile = "0"
		} else if t1Flag {
			profile = "1"
		} else if t2Flag {
			profile = "2"
		} else if t3Flag {
			profile = "3"
		} else if t4Flag {
			profile = "4"
		} else if t5Flag {
			profile = "5"
		}

		fmt.Printf("Starting Parashu Scan on %d targets with %d ports (Profile: %s)...\n", len(targets), len(ports), profile)

		// Initialize Scanner with Profile
		srv := scanner.NewScanner(adaptive.ProfileName(profile))

		// Apply Stealth Overrides
		srv.NoPing = noPingFlag
		if dataLengthFlag > 0 {
			srv.DataLength = dataLengthFlag
		}
		if proxiesFlag != "" {
			srv.Proxies = strings.Split(proxiesFlag, ",")
		}
		if scanDelayFlag != "" {
			d, err := time.ParseDuration(scanDelayFlag)
			if err == nil {
				srv.Engine.Config.ScanDelay = d
			}
		}

		fullResult := &output.ScanResult{
			ScanID:    fmt.Sprintf("scan-%d", time.Now().Unix()),
			Timestamp: time.Now(),
			Targets:   targets,
			Results:   []output.HostResult{},
		}

		// Run Scan
		// TODO: Parallelize hosts if needed? For now, sequential host scan, concurrent ports.
		start := time.Now()
		for _, target := range targets {
			res, err := srv.Scan(cmd.Context(), target, ports)
			if err != nil {
				fmt.Printf("Error scanning %s: %v\n", target, err)
				continue
			}
			// Only append if ports were found? Or always?
			// Usually report even if down? But Scan assumes up.
			if len(res.Ports) > 0 {
				fullResult.Results = append(fullResult.Results, res)
			}
		}

		// Fill Summary
		fullResult.Summary = output.ScanSummary{
			HostsScanned: len(targets),
			OpenPorts:    countOpenPorts(fullResult.Results),
		}

		// Write Output
		if err := writer.Write(fullResult, outWriter); err != nil {
			fmt.Printf("Error writing output: %v\n", err)
		}

		// Match exploits if requested
		if exploitMatchFlag {
			fmt.Println("\n[+] Matching discovered vulnerabilities with known exploits...")
			db, err := vuln.NewDB()
			if err == nil {
				defer db.Close()
				matcher := exploit.NewExploitMatcher(db)
				for _, hostRes := range fullResult.Results {
					matches, _ := matcher.MatchExploits(hostRes)
					if len(matches) > 0 {
						fmt.Printf("\nExploit Matches for %s:\n", hostRes.IP)
						for _, m := range matches {
							fmt.Printf("  - %s (Priority: %d, Match: %s)\n", m.Exploit.Title, m.Priority, m.Match.Evidence)
						}
					}
				}
			}
		}

		fmt.Printf("\nScan completed in %s\n", time.Since(start))
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	// Define Flags
	scanCmd.Flags().StringVar(&portsFlag, "ports", "top1000", "Ports to scan (top1000, common, all, range 1-65535, or list 22,80)")
	scanCmd.Flags().StringVar(&profileFlag, "profile", "balanced", "Scan profile (stealth, balanced, aggressive)")
	scanCmd.Flags().DurationVar(&timeoutFlag, "timeout", 2*time.Second, "Timeout per port scan (Override by profile usually)")
	scanCmd.Flags().IntVar(&rateLimitFlag, "rate-limit", 100, "Concurrent connections limit (Override by profile usually)")
	scanCmd.Flags().StringVar(&outputFlag, "output", "table", "Output format (table, json, html)")
	scanCmd.Flags().StringVar(&outputFileFlag, "output-file", "", "Write output to file")

	scanCmd.Flags().BoolVar(&bannersOnlyFlag, "banners-only", false, "Scan for banners only, skip CVE lookup")
	scanCmd.Flags().BoolVar(&onlineFallback, "online-fallback", false, "Query online APIs if local DB miss")
	scanCmd.Flags().StringVar(&apiKey, "api-key", "", "API Key for online enrichment")

	scanCmd.Flags().StringVar(&excludeFlag, "exclude", "", "Comma-separated IPs/CIDRs to exclude")
	scanCmd.Flags().StringVar(&excludeFileFlag, "exclude-file", "", "File containing IPs to exclude")
	scanCmd.Flags().StringVarP(&targetFileFlag, "file", "f", "", "File containing targets to scan")

	// Stealth Flags
	scanCmd.Flags().BoolVarP(&noPingFlag, "no-ping", "n", false, "Suppress ping/host discovery (Pn)")
	scanCmd.Flags().StringVar(&proxiesFlag, "proxies", "", "Comma-separated list of SOCKS5 proxies")
	scanCmd.Flags().IntVar(&dataLengthFlag, "data-length", 0, "Append random data to sent packets")
	scanCmd.Flags().StringVar(&scanDelayFlag, "scan-delay", "", "Delay between probes (e.g. 10ms, 1s)")

	// Timing Shorthands
	scanCmd.Flags().BoolVar(&t0Flag, "T0", false, "Paranoid timing")
	scanCmd.Flags().BoolVar(&t1Flag, "T1", false, "Sneaky timing")
	scanCmd.Flags().BoolVar(&t2Flag, "T2", false, "Polite timing")
	scanCmd.Flags().BoolVar(&t3Flag, "T3", false, "Normal timing")
	scanCmd.Flags().BoolVar(&t4Flag, "T4", false, "Aggressive timing")
	scanCmd.Flags().BoolVar(&t5Flag, "T5", false, "Insane timing")

	// Bind flags to viper for config precedence
	viper.BindPFlag("ports", scanCmd.Flags().Lookup("ports"))
	viper.BindPFlag("timeout", scanCmd.Flags().Lookup("timeout"))
	viper.BindPFlag("rate-limit", scanCmd.Flags().Lookup("rate-limit"))
	viper.BindPFlag("online-fallback", scanCmd.Flags().Lookup("online-fallback"))
	viper.BindPFlag("api-key", scanCmd.Flags().Lookup("api-key"))

	scanCmd.Flags().BoolVar(&exploitMatchFlag, "exploit-match", false, "Match vulnerabilities with known exploits")
}

// Helpers

func parseTargets(args []string, file string) ([]string, error) {
	var targets []string

	// From Args
	for _, arg := range args {
		if strings.Contains(arg, "/") {
			// CIDR (v4 or v6)
			ip, ipnet, err := net.ParseCIDR(arg)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %s: %v", arg, err)
			}

			// For simplicity in REDTEAM expansion, we only expand small ranges automatically
			// Large v6 ranges are not expanded here.
			ones, bits := ipnet.Mask.Size()
			if bits-ones > 10 { // Limit to 1024 hosts per range for safety
				fmt.Printf("Warning: Skipping massive CIDR expansion for %s (too many hosts)\n", arg)
				continue
			}

			for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
				targets = append(targets, ip.String())
			}
		} else {
			// Single IP (v4/v6) or Host
			targets = append(targets, arg)
		}
	}

	// From File
	if file != "" {
		content, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				targets = append(targets, line)
			}
		}
	}

	return targets, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func parsePorts(desc string) ([]int, error) {
	if desc == "top1000" {
		// Mock implementation - real list is long
		return []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080}, nil
	}
	if desc == "all" {
		var ports []int
		for i := 1; i <= 65535; i++ {
			ports = append(ports, i)
		}
		return ports, nil
	}

	var ports []int
	parts := strings.Split(desc, ",")
	for _, part := range parts {
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			start, err := strconv.Atoi(rangeParts[0])
			if err != nil {
				return nil, err
			}
			end, err := strconv.Atoi(rangeParts[1])
			if err != nil {
				return nil, err
			}
			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, err
			}
			ports = append(ports, p)
		}
	}
	return ports, nil
}

func countOpenPorts(results []output.HostResult) int {
	count := 0
	for _, h := range results {
		count += len(h.Ports) // Assuming only open ports are in the list
	}
	return count
}
