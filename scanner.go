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

// ----- GO'S ERROR HANDLING WITH CUSTOM ERROR TYPES -----
// ScanError represents an error that occurred during scanning
type ScanError struct {
	Host    string
	Port    int
	Message string
	Err     error
}

// Error method implementation - Go's interface implementation
func (e *ScanError) Error() string {
	return fmt.Sprintf("scan error for %s:%d: %s: %v",
		e.Host, e.Port, e.Message, e.Err)
}

// Unwrap method for error nesting - Go 1.13+ error wrapping
func (e *ScanError) Unwrap() error {
	return e.Err
}

// ----- GO'S STRUCT FOR DATA ORGANIZATION -----
// Scanner handles the port scanning process
type Scanner struct {
	target       string
	startPort    int
	endPort      int
	threads      int
	timeout      time.Duration
	showProgress bool
	ctx          context.Context
}

// ----- GO'S FUNCTIONAL OPTIONS PATTERN -----
// ScannerOption defines a functional option for the Scanner
type ScannerOption func(*Scanner)

// WithTarget sets the target to scan
func WithTarget(target string) ScannerOption {
	return func(s *Scanner) {
		s.target = target
	}
}

// WithPortRange sets the port range to scan
func WithPortRange(start, end int) ScannerOption {
	return func(s *Scanner) {
		s.startPort = start
		s.endPort = end
	}
}

// WithThreads sets the number of concurrent scanning threads
func WithThreads(n int) ScannerOption {
	return func(s *Scanner) {
		s.threads = n
	}
}

// WithTimeout sets the timeout for port connection attempts
func WithTimeout(d time.Duration) ScannerOption {
	return func(s *Scanner) {
		s.timeout = d
	}
}

// WithProgress enables/disables progress display
func WithProgress(show bool) ScannerOption {
	return func(s *Scanner) {
		s.showProgress = show
	}
}

// WithContext provides a context for cancellation
func WithContext(ctx context.Context) ScannerOption {
	return func(s *Scanner) {
		s.ctx = ctx
	}
}

// NewScanner creates a new scanner with the given options - demonstrates Go's flexibility
func NewScanner(options ...ScannerOption) *Scanner {
	// Default values - Go's approach to default parameters
	s := &Scanner{
		target:       "localhost",
		startPort:    1,
		endPort:      1024,
		threads:      100,
		timeout:      time.Second,
		showProgress: true,
		ctx:          context.Background(),
	}

	// Apply all options - Go's functional approach
	for _, option := range options {
		option(s)
	}

	return s
}

// ----- GO'S CONCURRENCY MODEL WITH GOROUTINES AND CHANNELS -----
// Scan starts the scanning process and returns open ports
func (s *Scanner) Scan() ([]int, error) {
	// Create buffered channels for work distribution and result collection
	// Go's approach to concurrent communication
	portCount := s.endPort - s.startPort + 1
	ports := make(chan int, min(portCount, 1000))   // Buffered channel for work
	results := make(chan int, min(portCount, 1000)) // Buffered channel for results
	done := make(chan struct{})                     // Signal channel for completion

	// Start the progress display if enabled
	progressDone := make(chan bool)
	if s.showProgress {
		go displayProgress(progressDone, portCount)
	}

	// ----- GO'S WAITGROUP FOR COORDINATION -----
	// Use WaitGroup to track worker goroutines
	var wg sync.WaitGroup

	// Start worker goroutines - Go's lightweight threads
	for i := 0; i < s.threads; i++ {
		wg.Add(1)
		// Anonymous function with closure - Go idiom for concurrent workers
		go func() {
			defer wg.Done() // Ensure WaitGroup is decremented when goroutine exits

			for {
				// ----- GO'S SELECT STATEMENT FOR CHANNEL OPERATIONS -----
				// Select statement to handle multiple channel operations
				select {
				case <-s.ctx.Done():
					// Context cancelled, exit worker
					return
				case port, ok := <-ports:
					if !ok {
						// Channel closed, exit worker
						return
					}

					// Check if port is open
					isOpen, err := isPortOpen(s.ctx, s.target, port, s.timeout)
					if err != nil {
						// Error checking port - could log here
						continue
					}

					if isOpen {
						// Send open port through results channel
						select {
						case results <- port:
							// Result sent successfully
						case <-s.ctx.Done():
							// Context cancelled during send
							return
						}
					}
				}
			}
		}()
	}

	// Start a goroutine to close results channel when all workers are done
	go func() {
		wg.Wait()
		close(results)
		close(done)
	}()

	// Start a goroutine to feed ports to workers
	go func() {
		defer close(ports) // Ensure ports channel is closed even if context is cancelled

		// ----- GO'S RANGE LOOP FOR ITERATION -----
		for port := s.startPort; port <= s.endPort; port++ {
			select {
			case <-s.ctx.Done():
				return
			case ports <- port:
				// Port sent for checking
			}
		}
	}()

	// Collect results using channel range - idiomatic Go
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

	// Wait for all scanning to complete
	<-done

	// Stop the progress display
	if s.showProgress {
		progressDone <- true
	}

	// Check if the scan was cancelled
	select {
	case <-s.ctx.Done():
		return openPorts, fmt.Errorf("scan cancelled: %w", s.ctx.Err())
	default:
		return openPorts, nil
	}
}

// ----- GO'S MULTIPLE RETURN VALUES AND ERROR HANDLING -----
// isPortOpen checks if a port is open with context cancellation support
func isPortOpen(ctx context.Context, host string, port int, timeout time.Duration) (bool, error) {
	// Create a custom dialer with timeout
	var d net.Dialer
	d.Timeout = timeout

	// Use DialContext to respect cancellation - Go's context pattern
	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := d.DialContext(ctx, "tcp", address)

	if err != nil {
		// Check for specific network errors - Go's type assertion
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return false, nil // Not considered an error, just closed/filtered
		}

		// Check if context was cancelled
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return false, err
		}

		return false, nil // Other errors treated as closed port
	}

	// Use defer for cleanup - Go's resource management
	defer conn.Close()
	return true, nil
}

// isHostAlive checks if a host is reachable
func isHostAlive(ctx context.Context, host string, timeout time.Duration) bool {
	// Try connecting to common ports
	for _, port := range []int{80, 443, 22, 3389} {
		isOpen, _ := isPortOpen(ctx, host, port, timeout)
		if isOpen {
			return true
		}
	}

	return false
}

// min returns the smaller of two integers - utility function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
