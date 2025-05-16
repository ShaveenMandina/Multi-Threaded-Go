package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// ----- GO'S MAP FOR DATA LOOKUPS -----
// Map of common port numbers to service names - Go's built-in hash table
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

// ----- GO'S INTERFACE-BASED DESIGN -----
// ServiceDetector interface for extensible service detection
type ServiceDetector interface {
	Detect(host string, port int) (string, bool)
	Name() string
}

// HTTPDetector implements service detection for HTTP/HTTPS
type HTTPDetector struct{}

func (d HTTPDetector) Detect(host string, port int) (string, bool) {
	// Simple detection based on port number
	if port == 80 {
		return "HTTP", true
	}
	if port == 443 {
		return "HTTPS", true
	}

	// Try to detect HTTP on non-standard ports by banner
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

// SSHDetector implements detection for SSH
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

// ----- GO'S SLICE FOR COLLECTIONS -----
// detectors is a slice of ServiceDetector implementations
var detectors = []ServiceDetector{
	HTTPDetector{},
	SSHDetector{},
	// Additional detectors can be added here
}

// getServiceName returns the service name for a given port
func getServiceName(port int) string {
	// First check for common ports in our map
	if service, exists := commonPorts[port]; exists {
		return service
	}

	// For unknown ports, return "Unknown"
	return "Unknown"
}

// grabBanner attempts to retrieve the service banner from a port
func grabBanner(ctx context.Context, host string, port int, timeout time.Duration) (string, error) {
	// Create a dialer with timeout
	var d net.Dialer
	d.Timeout = timeout

	// Connect to the port
	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return "", err
	}

	// ----- GO'S DEFER FOR RESOURCE CLEANUP -----
	// Ensure connection is closed when function returns
	defer conn.Close()

	// Set deadlines for read/write operations
	deadline := time.Now().Add(timeout)
	err = conn.SetDeadline(deadline)
	if err != nil {
		return "", err
	}

	// For certain common ports, send appropriate requests
	switch port {
	case 80, 8080:
		// For HTTP, send a simple request
		_, err = fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
		if err != nil {
			return "", err
		}
	case 21:
		// FTP usually sends a banner automatically, no need to send anything
	case 22:
		// SSH usually sends a banner automatically, no need to send anything
	case 25, 587:
		// SMTP usually sends a banner automatically, no need to send anything
	}

	// Read the response
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", err
	}

	// Clean up the banner
	banner := string(buffer[:n])
	// Replace newlines with spaces for display
	banner = strings.ReplaceAll(banner, "\r\n", " ")
	banner = strings.ReplaceAll(banner, "\n", " ")

	// Truncate if too long
	if len(banner) > 100 {
		banner = banner[:100] + "..."
	}

	return banner, nil
}

// ----- GO'S STRING HANDLING -----
// expandIPRange expands an IP range string into individual IP addresses
func expandIPRange(ipRange string) ([]string, error) {
	// Split on the hyphen to get start and end IPs
	parts := strings.Split(ipRange, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid IP range format (use: 192.168.1.1-192.168.1.10)")
	}

	startIP := strings.TrimSpace(parts[0])
	endIP := strings.TrimSpace(parts[1])

	// Parse the start IP
	startIPParts := strings.Split(startIP, ".")
	if len(startIPParts) != 4 {
		return nil, fmt.Errorf("invalid start IP address")
	}

	// Parse the end IP
	endIPParts := strings.Split(endIP, ".")
	if len(endIPParts) != 4 {
		return nil, fmt.Errorf("invalid end IP address")
	}

	// Convert the last octet to integers
	startOctet, err := strconv.Atoi(startIPParts[3])
	if err != nil {
		return nil, fmt.Errorf("invalid start IP address")
	}

	endOctet, err := strconv.Atoi(endIPParts[3])
	if err != nil {
		return nil, fmt.Errorf("invalid end IP address")
	}

	// Check if the first three octets match
	if startIPParts[0] != endIPParts[0] || startIPParts[1] != endIPParts[1] || startIPParts[2] != endIPParts[2] {
		return nil, fmt.Errorf("IP range must be in the same /24 subnet")
	}

	// Check if the range is valid
	if startOctet > endOctet {
		return nil, fmt.Errorf("start IP must be less than or equal to end IP")
	}

	// Generate the IP addresses
	baseIP := fmt.Sprintf("%s.%s.%s.", startIPParts[0], startIPParts[1], startIPParts[2])
	var ips []string

	for i := startOctet; i <= endOctet; i++ {
		ips = append(ips, baseIP+strconv.Itoa(i))
	}

	return ips, nil
}

// guessOS attempts to determine the operating system based on open ports
func guessOS(openPorts []int) string {
	// ----- GO'S CLOSURE FOR HELPER FUNCTIONS -----
	// Helper function to check if a slice contains a value
	contains := func(ports []int, port int) bool {
		for _, p := range ports {
			if p == port {
				return true
			}
		}
		return false
	}

	// Check for common Windows ports
	hasPort445 := contains(openPorts, 445)
	hasPort3389 := contains(openPorts, 3389)
	hasPort135 := contains(openPorts, 135)

	// Check for common Linux/Unix ports
	hasPort22 := contains(openPorts, 22)
	hasPort111 := contains(openPorts, 111)

	// Check for web server ports
	hasPort80 := contains(openPorts, 80)
	hasPort443 := contains(openPorts, 443)

	// Make a determination
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
