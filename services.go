package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Map of common ports to their services
var commonPorts = map[int]string{
	20:    "FTP Data",
	21:    "FTP Control",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	115:   "SFTP",
	143:   "IMAP",
	194:   "IRC",
	443:   "HTTPS",
	445:   "SMB",
	1433:  "MSSQL",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5900:  "VNC",
	8080:  "HTTP-Alt",
	27017: "MongoDB",
}

// Interface for pluggable service detection
type ServiceDetector interface {
	Detect(host string, port int) (string, bool)
	Name() string
}

// HTTP service detector implementation
type HTTPDetector struct{}

func (d HTTPDetector) Detect(host string, port int) (string, bool) {
	// Quick check for standard ports
	if port == 80 {
		return "HTTP", true
	}
	if port == 443 {
		return "HTTPS", true
	}

	// Try non-standard ports by banner grab
	banner, err := grabBanner(context.Background(), host, port, 2*time.Second)
	if err != nil {
		return "", false
	}

	if strings.Contains(banner, "HTTP") {
		return "HTTP", true
	}

	return "", false
}

func (d HTTPDetector) Name() string {
	return "HTTP Detector"
}

// SSH service detector
type SSHDetector struct{}

func (d SSHDetector) Detect(host string, port int) (string, bool) {
	if port == 22 {
		return "SSH", true
	}

	banner, err := grabBanner(context.Background(), host, port, 2*time.Second)
	if err != nil {
		return "", false
	}

	if strings.Contains(banner, "SSH") {
		return "SSH", true
	}

	return "", false
}

func (d SSHDetector) Name() string {
	return "SSH Detector"
}

// List of available detectors
var detectors = []ServiceDetector{
	HTTPDetector{},
	SSHDetector{},
	// Can add more detectors here later
}

// Lookup service name by port number
func getServiceName(port int) string {
	// Check our known ports first
	if service, exists := commonPorts[port]; exists {
		return service
	}

	// Fall back to generic label
	return "Unknown"
}

// Try to grab service banner from the port
func grabBanner(ctx context.Context, host string, port int, timeout time.Duration) (string, error) {
	// Setup connection with timeout
	var d net.Dialer
	d.Timeout = timeout

	// Connect to target
	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return "", err
	}

	// Make sure we close the connection
	defer conn.Close()

	// Set timeout for I/O
	deadline := time.Now().Add(timeout)
	err = conn.SetDeadline(deadline)
	if err != nil {
		return "", err
	}

	// Send appropriate probe for common protocols
	switch port {
	case 80, 8080:
		// Simple HTTP request
		_, err = fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
		if err != nil {
			return "", err
		}
	case 21:
		// FTP banner comes automatically
	case 22:
		// SSH banner comes automatically
	case 25, 587:
		// SMTP banner comes automatically
	}

	// Read the response
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", err
	}

	// Format the banner nicely
	banner := string(buffer[:n])
	// Clean up newlines
	banner = strings.ReplaceAll(banner, "\r\n", " ")
	banner = strings.ReplaceAll(banner, "\n", " ")

	// Truncate long responses
	if len(banner) > 100 {
		banner = banner[:100] + "..."
	}

	return banner, nil
}

// Convert IP range (192.168.1.1-192.168.1.10) to list of IPs
func expandIPRange(ipRange string) ([]string, error) {
	// Parse the range format
	parts := strings.Split(ipRange, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid IP range format (use: 192.168.1.1-192.168.1.10)")
	}

	startIP := strings.TrimSpace(parts[0])
	endIP := strings.TrimSpace(parts[1])

	// Check start IP format
	startIPParts := strings.Split(startIP, ".")
	if len(startIPParts) != 4 {
		return nil, fmt.Errorf("invalid start IP address")
	}

	// Check end IP format
	endIPParts := strings.Split(endIP, ".")
	if len(endIPParts) != 4 {
		return nil, fmt.Errorf("invalid end IP address")
	}

	// Get the last octet numbers
	startOctet, err := strconv.Atoi(startIPParts[3])
	if err != nil {
		return nil, fmt.Errorf("invalid start IP address")
	}

	endOctet, err := strconv.Atoi(endIPParts[3])
	if err != nil {
		return nil, fmt.Errorf("invalid end IP address")
	}

	// Check subnet match
	if startIPParts[0] != endIPParts[0] || startIPParts[1] != endIPParts[1] || startIPParts[2] != endIPParts[2] {
		return nil, fmt.Errorf("IP range must be in the same /24 subnet")
	}

	// Make sure range is valid
	if startOctet > endOctet {
		return nil, fmt.Errorf("start IP must be less than or equal to end IP")
	}

	// Generate all IPs in range
	baseIP := fmt.Sprintf("%s.%s.%s.", startIPParts[0], startIPParts[1], startIPParts[2])
	var ips []string

	for i := startOctet; i <= endOctet; i++ {
		ips = append(ips, baseIP+strconv.Itoa(i))
	}

	return ips, nil
}

// Try to identify OS based on open port patterns
func guessOS(openPorts []int) string {
	// Helper to check if port exists in list
	contains := func(ports []int, port int) bool {
		for _, p := range ports {
			if p == port {
				return true
			}
		}
		return false
	}

	// Windows signature ports
	hasPort445 := contains(openPorts, 445)
	hasPort3389 := contains(openPorts, 3389)
	hasPort135 := contains(openPorts, 135)

	// Linux/Unix signature ports
	hasPort22 := contains(openPorts, 22)
	hasPort111 := contains(openPorts, 111)

	// Web server ports
	hasPort80 := contains(openPorts, 80)
	hasPort443 := contains(openPorts, 443)

	// Fingerprint analysis
	if hasPort445 || hasPort3389 || hasPort135 {
		return "Likely Windows"
	}

	if hasPort22 && hasPort111 {
		return "Likely Linux/Unix"
	}

	if hasPort22 && !hasPort445 {
		return "Likely Linux/Unix or Network Device"
	}

	if (hasPort80 || hasPort443) && !hasPort22 && !hasPort445 {
		return "Likely Network Device or Appliance"
	}

	return "Unknown OS"
}
