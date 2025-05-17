package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// Custom error type for scan failures
type ScanError struct {
	Host    string
	Port    int
	Message string
	Err     error
}

// Standard error interface implementation
func (e *ScanError) Error() string {
	return fmt.Sprintf("scan error for %s:%d: %s: %v",
		e.Host, e.Port, e.Message, e.Err)
}

// Unwrap for error chain support
func (e *ScanError) Unwrap() error {
	return e.Err
}

// Main scanner struct
type Scanner struct {
	target       string
	startPort    int
	endPort      int
	threads      int
	timeout      time.Duration
	showProgress bool
	ctx          context.Context
}

// For configuring scanner options
type ScannerOption func(*Scanner)

// Sets target host
func WithTarget(target string) ScannerOption {
	return func(s *Scanner) {
		s.target = target
	}
}

// Sets port range to scan
func WithPortRange(start, end int) ScannerOption {
	return func(s *Scanner) {
		s.startPort = start
		s.endPort = end
	}
}

// Controls parallelism
func WithThreads(n int) ScannerOption {
	return func(s *Scanner) {
		s.threads = n
	}
}

// Connection timeout per port
func WithTimeout(d time.Duration) ScannerOption {
	return func(s *Scanner) {
		s.timeout = d
	}
}

// Toggle progress display
func WithProgress(show bool) ScannerOption {
	return func(s *Scanner) {
		s.showProgress = show
	}
}

// Add cancelation support
func WithContext(ctx context.Context) ScannerOption {
	return func(s *Scanner) {
		s.ctx = ctx
	}
}

// Creates a new scanner with sensible defaults
func NewScanner(options ...ScannerOption) *Scanner {
	// Set defaults
	s := &Scanner{
		target:       "localhost",
		startPort:    1,
		endPort:      1024,
		threads:      100,
		timeout:      time.Second,
		showProgress: true,
		ctx:          context.Background(),
	}

	// Apply any provided options
	for _, option := range options {
		option(s)
	}

	return s
}

// Main scanning function
func (s *Scanner) Scan() ([]int, error) {
	// Setup channels for work distribution
	portCount := s.endPort - s.startPort + 1
	ports := make(chan int, min(portCount, 1000))   // Work queue
	results := make(chan int, min(portCount, 1000)) // Results collector
	done := make(chan struct{})                     // Completion signal

	// Handle progress display
	progressDone := make(chan bool)
	if s.showProgress {
		go displayProgress(progressDone, portCount)
	}

	// Sync for all worker goroutines
	var wg sync.WaitGroup

	// Fire up workers
	for i := 0; i < s.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for {
				select {
				case <-s.ctx.Done():
					// Bail if canceled
					return
				case port, ok := <-ports:
					if !ok {
						// No more work
						return
					}

					// Try connecting
					isOpen, err := isPortOpen(s.ctx, s.target, port, s.timeout)
					if err != nil {
						// Skip errors
						continue
					}

					if isOpen {
						// Found an open port
						select {
						case results <- port:
							// Sent to results
						case <-s.ctx.Done():
							// Canceled during send
							return
						}
					}
				}
			}
		}()
	}

	// Clean up when workers finish
	go func() {
		wg.Wait()
		close(results)
		close(done)
	}()

	// Feed ports to workers
	go func() {
		defer close(ports)

		for port := s.startPort; port <= s.endPort; port++ {
			select {
			case <-s.ctx.Done():
				return
			case ports <- port:
				// Sent for checking
			}
		}
	}()

	// Collect and process results
	openPorts := []int{}
	for port := range results {
		openPorts = append(openPorts, port)
		service := getServiceName(port)
		banner, _ := grabBanner(s.ctx, s.target, port, s.timeout)
		if banner != "" {
			fmt.Printf("Port %d is open (%s): %s\n", port, service, banner)
		} else {
			fmt.Printf("Port %d is open (%s)\n", port, service)
		}
	}

	// Wait till everything's done
	<-done

	// Stop progress display
	if s.showProgress {
		progressDone <- true
	}

	// Handle cancellation
	select {
	case <-s.ctx.Done():
		return openPorts, fmt.Errorf("scan cancelled: %w", s.ctx.Err())
	default:
		return openPorts, nil
	}
}

// Check if a single port is open
func isPortOpen(ctx context.Context, host string, port int, timeout time.Duration) (bool, error) {
	// Setup dialer with timeout
	var d net.Dialer
	d.Timeout = timeout

	// Try to connect
	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := d.DialContext(ctx, "tcp", address)

	if err != nil {
		// Handle different error types
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return false, nil // Just closed/filtered
		}

		// Check for cancellation
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return false, err
		}

		return false, nil // Other errors = closed port
	}

	// Clean up connection
	defer conn.Close()
	return true, nil
}

// Quick host availability check
func isHostAlive(ctx context.Context, host string, timeout time.Duration) bool {
	// Check common ports
	for _, port := range []int{80, 443, 22, 3389} {
		isOpen, _ := isPortOpen(ctx, host, port, timeout)
		if isOpen {
			return true
		}
	}

	return false
}

// Simple helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
