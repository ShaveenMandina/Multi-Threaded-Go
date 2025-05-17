package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Exports scan results to CSV file
func saveToCSV(filename string, results map[string][]int) error {
	// Create output file
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating CSV file: %w", err)
	}
	defer file.Close()

	// Setup CSV writer
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Add header row
	header := []string{"Host", "Port", "Service", "Timestamp"}
	err = writer.Write(header)
	if err != nil {
		return fmt.Errorf("error writing CSV header: %w", err)
	}

	// Write each host/port combination
	timestamp := time.Now().Format(time.RFC3339)
	for host, ports := range results {
		for _, port := range ports {
			service := getServiceName(port)
			row := []string{
				host,
				strconv.Itoa(port),
				service,
				timestamp,
			}
			err = writer.Write(row)
			if err != nil {
				return fmt.Errorf("error writing CSV row: %w", err)
			}
		}
	}

	return nil
}

// Formats time duration to be human-readable
func formatDuration(d time.Duration) string {
	// Round to seconds for display
	d = d.Round(time.Second)

	h := d / time.Hour
	d -= h * time.Hour

	m := d / time.Minute
	d -= m * time.Minute

	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// Creates a one-line summary of scan results
func formatResultSummary(host string, openPorts []int) string {
	// No open ports case
	if len(openPorts) == 0 {
		return fmt.Sprintf("No open ports found on %s", host)
	}

	// Show all ports if 10 or fewer
	if len(openPorts) <= 10 {
		summary := fmt.Sprintf("%d open ports on %s: ", len(openPorts), host)
		for i, port := range openPorts {
			service := getServiceName(port)
			if i > 0 {
				summary += ", "
			}
			summary += fmt.Sprintf("%d (%s)", port, service)
		}
		return summary
	}

	// Truncate if too many ports
	summary := fmt.Sprintf("%d open ports on %s including: ", len(openPorts), host)
	for i := 0; i < 5; i++ {
		service := getServiceName(openPorts[i])
		if i > 0 {
			summary += ", "
		}
		summary += fmt.Sprintf("%d (%s)", openPorts[i], service)
	}
	summary += ", ..."
	return summary
}

// Builds a complete text report of scan findings
func generateScanReport(results map[string][]int, startTime time.Time) string {
	duration := time.Since(startTime)

	// Get stats
	hostCount := len(results)
	portCount := 0
	for _, ports := range results {
		portCount += len(ports)
	}

	// Header section
	report := fmt.Sprintf("PORT SCANNER REPORT\n")
	report += fmt.Sprintf("=================\n\n")
	report += fmt.Sprintf("Scan completed at: %s\n", time.Now().Format(time.RFC1123))
	report += fmt.Sprintf("Duration: %s\n", formatDuration(duration))
	report += fmt.Sprintf("Hosts scanned: %d\n", hostCount)
	report += fmt.Sprintf("Open ports found: %d\n\n", portCount)

	// Results section
	report += fmt.Sprintf("DETAILED RESULTS\n")
	report += fmt.Sprintf("----------------\n\n")

	for host, ports := range results {
		report += fmt.Sprintf("Host: %s\n", host)
		report += fmt.Sprintf("Open ports: %d\n", len(ports))

		// Try to identify OS
		if len(ports) > 0 {
			report += fmt.Sprintf("OS Detection: %s\n", guessOS(ports))
		}

		// List ports and services
		if len(ports) > 0 {
			report += "PORT\tSERVICE\n"
			report += "----\t-------\n"
			for _, port := range ports {
				service := getServiceName(port)
				report += fmt.Sprintf("%d\t%s\n", port, service)
			}
		} else {
			report += "No open ports found\n"
		}

		report += "\n"
	}

	// Footer
	report += "Scan completed successfully\n"
	return report
}

// Writes report to text file
func saveReportToFile(filename string, report string) error {
	// Create file
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating report file: %w", err)
	}
	defer file.Close()

	// Save report content
	_, err = file.WriteString(report)
	if err != nil {
		return fmt.Errorf("error writing report: %w", err)
	}

	return nil
}
