package scanner

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/sync/errgroup"
)

// Result represents a scan result
type Result struct {
	Port    int
	State   string
	Service string
}

// Scanner handles the scanning logic
type Scanner struct {
	Concurrency int
	Timeout     time.Duration
}

// NewScanner creates a new scanner instance
func NewScanner(concurrency int, timeout time.Duration) *Scanner {
	if concurrency <= 0 {
		concurrency = 100
	}
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	return &Scanner{
		Concurrency: concurrency,
		Timeout:     timeout,
	}
}

// Scan scans the target for the given ports
func (s *Scanner) Scan(ctx context.Context, target string, ports []int) ([]Result, error) {
	var results []Result
	resultsChan := make(chan Result, len(ports))
	sem := make(chan struct{}, s.Concurrency)

	g, ctx := errgroup.WithContext(ctx)

	for _, port := range ports {
		port := port // capture loop variable
		g.Go(func() error {
			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				if s.isOpen(target, port) {
					resultsChan <- Result{
						Port:  port,
						State: "Open",
						// TODO: Service detection
					}
				}
			}
			return nil
		})
	}

	// Wait for all goroutines to finish
	if err := g.Wait(); err != nil {
		return nil, err
	}
	close(resultsChan)

	for res := range resultsChan {
		results = append(results, res)
	}

	return results, nil
}

func (s *Scanner) isOpen(target string, port int) bool {
	address := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", address, s.Timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
