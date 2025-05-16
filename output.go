package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"time"
)

// ----- GO'S CSV ENCODING/DECODING -----
// saveToCSV saves scan results to a CSV file
func saveToCSV(filename string, results map[string][]int) error {
	// Create the file
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating CSV file: %w", err)
	}
	// ----- GO'S DEFER FOR CLEANUP -----
	defer file.Close()

	// Create CSV writer
	writer := csv.NewWriter(file)
	// Ensure all data is written before function returns
	defer writer.Flush()

	// Write header
	header := []string{"Host", "Port", "Service", "Timestamp"}
	err = writer.Write(header)
	if err != nil {
		return fmt.Errorf("error writing CSV header: %w", err)
	}

	// ----- GO'S RANGE LOOP FOR MAPS -----
	// Write data rows - iterate through hosts and ports
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

// formatDuration formats a duration as a human-readable string
func formatDuration(d time.Duration) string {
	// ----- GO'S TIME PACKAGE -----
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

// formatResultSummary creates a summary string of scan results
func formatResultSummary(host string, openPorts []int) string {
	// When no ports are open
	if len(openPorts) == 0 {
		return fmt.Sprintf("No open ports found on %s", host)
	}

	// Create a summary for a few ports
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

	// For many ports, just show the count and first few
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

// generateScanReport creates a detailed report of scan results
func generateScanReport(results map[string][]int, startTime time.Time) string {
	duration := time.Since(startTime)

	// Count total hosts and ports
	hostCount := len(results)
	portCount := 0
	for _, ports := range results {
		portCount += len(ports)
	}

	// ----- GO'S STRING FORMATTING -----
	// Generate the report using Go's string formatting
	report := fmt.Sprintf("PORT SCANNER REPORT\n")
	report += fmt.Sprintf("=================\n\n")
	report += fmt.Sprintf("Scan completed at: %s\n", time.Now().Format(time.RFC1123))
	report += fmt.Sprintf("Duration: %s\n", formatDuration(duration))
	report += fmt.Sprintf("Hosts scanned: %d\n", hostCount)
	report += fmt.Sprintf("Open ports found: %d\n\n", portCount)

	// Include details for each host
	report += fmt.Sprintf("DETAILED RESULTS\n")
	report += fmt.Sprintf("----------------\n\n")

	for host, ports := range results {
		report += fmt.Sprintf("Host: %s\n", host)
		report += fmt.Sprintf("Open ports: %d\n", len(ports))

		// Guess OS based on open ports
		if len(ports) > 0 {
			report += fmt.Sprintf("OS Detection: %s\n", guessOS(ports))
		}

		// List open ports and services
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

	// Add footer
	report += "Scan completed successfully\n"
	return report
}

// saveReportToFile saves a scan report to a text file
func saveReportToFile(filename string, report string) error {
	// Create the file
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating report file: %w", err)
	}
	defer file.Close()

	// Write the report
	_, err = file.WriteString(report)
	if err != nil {
		return fmt.Errorf("error writing report: %w", err)
	}

	return nil
}
