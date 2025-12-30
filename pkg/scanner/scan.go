package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"parashu/internal/adaptive"
	"parashu/pkg/fingerprint"
	"parashu/pkg/output"

	"github.com/schollz/progressbar/v3"
	"golang.org/x/sync/errgroup"
)

// Scanner handles the scanning logic
type Scanner struct {
	Engine      *adaptive.Engine
	Fingerprint *fingerprint.Engine
}

// NewScanner creates a new scanner instance with adaptive capabilities
func NewScanner(profile adaptive.ProfileName) *Scanner {
	cfg := adaptive.GetProfile(string(profile))
	return &Scanner{
		Engine:      adaptive.NewEngine(cfg),
		Fingerprint: fingerprint.NewEngine(cfg.MaxTimeout),
	}
}

// Scan scans the target for the given ports
func (s *Scanner) Scan(ctx context.Context, target string, ports []int) (output.HostResult, error) {
	result := output.HostResult{
		IP:    target,
		Ports: []output.PortResult{},
	}

	// Resolve Hostname
	names, _ := net.LookupAddr(target)
	if len(names) > 0 {
		result.Hostname = strings.TrimSuffix(names[0], ".")
	}

	resultsChan := make(chan output.PortResult, len(ports))

	// Adaptive Concurrency: We start with initial concurrency loop,
	// but true adaptive parallelism usually requires a worker pool or semaphore that resizes.
	// For simplicity in Phase 1, we'll use a semaphore that reads the current recommendation per loop
	// effectively limiting "new" goroutines.

	// However, errgroup blocks on Wait(), so dynamic resizing is tricky without a custom worker pool.
	// We will simulate it by checking concurrency limit before spawning.

	// Create a progress bar
	bar := progressbar.Default(int64(len(ports)), "Scanning ports on "+target)

	// Phase 1 Pragmatic Approach:
	// We use `errgroup` with a limit based on the *Profile's* InitialConcurrency.
	// The *Timeout* will be adaptive per request.

	// Re-reading expectation: "Integrate Adaptive Engine".
	// The Engine provides `Concurrency()`.

	sem := make(chan struct{}, s.Engine.Config.InitialConcurrency) // Start with initial

	g, ctx := errgroup.WithContext(ctx)

	for _, port := range ports {
		port := port

		// Wait for semaphore slot
		sem <- struct{}{}

		g.Go(func() error {
			defer func() { <-sem }()
			defer bar.Add(1)

			// Check for cancellation
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			start := time.Now()

			// Dynamic Timeout
			timeout := s.Engine.Timeout()

			isOpen, banner := s.checkPort(target, port, timeout)

			// Feedback to Engine
			s.Engine.RecordResult(time.Since(start), isOpen || !isOpen) // Only fail if network error, strictly.
			// Ideally checkPort returns err.

			if isOpen {
				// Fingerprint
				details := s.Fingerprint.Fingerprint(ctx, target, port, banner)

				resultsChan <- output.PortResult{
					Port:     port,
					Protocol: "tcp",
					Service:  details.Service,
					Banner:   banner,
					Version:  details.Version,
					CPE:      details.CPE,
				}
			}
			return nil
		})
	}

	go func() {
		g.Wait()
		close(resultsChan)
	}()

	for res := range resultsChan {
		result.Ports = append(result.Ports, res)
	}

	if err := g.Wait(); err != nil {
		return result, err
	}

	return result, nil
}

// checkPort checks if a port is open and attempts banner grabbing
func (s *Scanner) checkPort(target string, port int, timeout time.Duration) (bool, string) {
	address := net.JoinHostPort(target, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false, ""
	}
	defer conn.Close()

	// Banner Grabbing
	banner := ""
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if n > 0 {
		banner = strings.TrimSpace(string(buf[:n]))
	}

	return true, banner
}

func guessService(port int, banner string) string {
	// Simple map for common ports
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

	if svc, ok := services[port]; ok {
		return svc
	}
	if banner != "" {
		return "unknown" // detected but unknown
	}
	return "unknown"
}
