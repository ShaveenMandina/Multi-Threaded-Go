package main

import (
	"bufio"
	"context"
	"fmt"
	"math"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"
)

// Shows a progress bar during scan
func displayProgress(done chan bool, total int) {
	start := time.Now()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	counter := 0
	barWidth := 40

	for {
		select {
		case <-done:
			// Finish with 100% bar
			printProgressBar(barWidth, 100, time.Since(start), total, total)
			fmt.Println()
			return
		case <-ticker.C:
			counter++
			// Estimate progress based on typical scan time
			elapsed := time.Since(start)
			estimatedTotal := 5 * time.Second
			if total > 1000 {
				estimatedTotal = 30 * time.Second
			} else if total > 100 {
				estimatedTotal = 15 * time.Second
			}

			// Keep progress under 100% until we're actually done
			progress := float64(elapsed) / float64(estimatedTotal)
			if progress > 0.99 {
				progress = 0.99
			}

			// Calculate estimated ports done
			portsCompleted := int(float64(total) * progress)

			// Update the bar
			printProgressBar(barWidth, progress*100, elapsed, portsCompleted, total)
		}
	}
}

// Draws the actual progress bar UI
func printProgressBar(width int, percent float64, elapsed time.Duration, completed, total int) {
	// Calculate filled positions
	filled := int(percent / 100 * float64(width))
	if filled > width {
		filled = width
	}

	// Create the visual bar
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)

	// Calculate speed
	portsPerSecond := float64(completed) / math.Max(elapsed.Seconds(), 0.001)
	if math.IsNaN(portsPerSecond) || math.IsInf(portsPerSecond, 0) {
		portsPerSecond = 0
	}

	// Estimate time remaining
	var remaining string
	if percent < 100 {
		remainingPorts := total - completed
		remainingTime := time.Duration(float64(remainingPorts)/math.Max(portsPerSecond, 0.001)) * time.Second
		remaining = fmt.Sprintf(", ~%s remaining", formatDuration(remainingTime))
	} else {
		remaining = ", done!"
	}

	// Print everything
	fmt.Printf("\r[%s] %.1f%% (%d/%d ports, %.1f ports/sec%s)    ",
		bar, percent, completed, total, portsPerSecond, remaining)
}

// Main CLI interface
func runInteractiveMode() {
	scanner := bufio.NewScanner(os.Stdin)

	// Start with help
	printUIHelp()

	// Main command loop
	for {
		fmt.Print("\nportscanner> ")
		if !scanner.Scan() {
			break
		}

		input := scanner.Text()
		args := strings.Fields(input)

		if len(args) == 0 {
			continue
		}

		command := strings.ToLower(args[0])

		switch command {
		case "exit", "quit":
			fmt.Println("Exiting port scanner. Goodbye!")
			return

		case "help":
			printUIHelp()

		case "scan":
			handleUIScanCommand(args)

		case "ping":
			handleUIPingCommand(args)

		case "banner":
			handleUIBannerCommand(args)

		case "range":
			handleUIRangeCommand(args)

		case "web":
			fmt.Println("Starting web interface at http://localhost:8080")
			fmt.Println("Press Ctrl+C to exit")
			startWebServer()

		default:
			fmt.Printf("Unknown command: %s\nType 'help' for available commands\n", command)
		}
	}
}

// Shows available commands
func printUIHelp() {
	help := `
Available Commands:
------------------
  scan <host> [start] [end] [threads] [timeout]
      Scan a host for open ports
      Example: scan google.com 1 1000 100 500
      
  ping <host>
      Check if a host is alive
      Example: ping 192.168.1.1
      
  banner <host> <port>
      Grab a service banner from a specific port
      Example: banner example.com 80
      
  range <start-end> [start] [end] [threads]
      Scan an IP range
      Example: range 192.168.1.1-192.168.1.10 1 100
      
  web
      Start the web interface on port 8080
      
  clear
      Clear the screen
      
  help
      Show this help menu
      
  exit, quit
      Exit the program
      
Go Features Showcased:
---------------------
* Goroutines - Lightweight threads for concurrent scanning
* Channels - Communication between concurrent operations
* Select - Elegant handling of multiple events
* Context - Clean cancellation and timeouts
* Interfaces - Extensible service detection
* Defer - Resource cleanup guarantees
* Error handling - Explicit error checking and propagation
`
	fmt.Println(help)
}

// Handles the scan command
func handleUIScanCommand(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: scan <host> [start] [end] [threads] [timeout]")
		return
	}

	host := args[1]
	startPort := 1
	endPort := 1000
	threads := 100
	timeout := 500

	// Parse optional args
	if len(args) >= 3 {
		var err error
		startPort, err = strconv.Atoi(args[2])
		if err != nil {
			fmt.Println("Invalid start port, using default (1)")
			startPort = 1
		}
	}

	if len(args) >= 4 {
		var err error
		endPort, err = strconv.Atoi(args[3])
		if err != nil {
			fmt.Println("Invalid end port, using default (1000)")
			endPort = 1000
		}
	}

	if len(args) >= 5 {
		var err error
		threads, err = strconv.Atoi(args[4])
		if err != nil {
			fmt.Println("Invalid thread count, using default (100)")
			threads = 100
		}
	}

	if len(args) >= 6 {
		var err error
		timeout, err = strconv.Atoi(args[5])
		if err != nil {
			fmt.Println("Invalid timeout, using default (500ms)")
			timeout = 500
		}
	}

	// Sanity checks
	if startPort < 1 || startPort > 65535 {
		fmt.Println("Start port must be between 1 and 65535")
		return
	}

	if endPort < 1 || endPort > 65535 || endPort < startPort {
		fmt.Println("End port must be between start port and 65535")
		return
	}

	fmt.Printf("\nStarting port scan on host %s (ports %d-%d)\n", host, startPort, endPort)
	fmt.Printf("Using %d threads with %dms timeout\n\n", threads, timeout)

	// Support cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Ctrl+C handler
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt)
		<-sigChan
		fmt.Println("\nCancelling scan...")
		cancel()
	}()

	// Create and configure scanner
	scanner := NewScanner(
		WithTarget(host),
		WithPortRange(startPort, endPort),
		WithThreads(threads),
		WithTimeout(time.Duration(timeout)*time.Millisecond),
		WithProgress(true),
		WithContext(ctx),
	)

	// Run the scan
	openPorts, err := scanner.Scan()
	if err != nil {
		fmt.Printf("\nScan error: %v\n", err)
		return
	}

	// Show results
	fmt.Printf("\nScan completed for %s: %d open ports found\n", host, len(openPorts))
	if len(openPorts) > 0 {
		fmt.Printf("Open ports on %s: ", host)
		for i, port := range openPorts {
			service := getServiceName(port)
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Printf("%d (%s)", port, service)
		}
		fmt.Println()

		// Try to identify OS
		fmt.Printf("OS Detection: %s\n", guessOS(openPorts))
	}
}

// Handles the ping command
func handleUIPingCommand(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: ping <host>")
		return
	}

	host := args[1]
	fmt.Printf("Pinging %s... ", host)

	ctx := context.Background()
	if isHostAlive(ctx, host, 2*time.Second) {
		fmt.Println("Host is up!")
	} else {
		fmt.Println("Host appears to be down.")
	}
}

// Handles the banner grab command
func handleUIBannerCommand(args []string) {
	if len(args) < 3 {
		fmt.Println("Usage: banner <host> <port>")
		return
	}

	host := args[1]
	port, err := strconv.Atoi(args[2])
	if err != nil || port < 1 || port > 65535 {
		fmt.Println("Port must be a number between 1 and 65535")
		return
	}

	fmt.Printf("Grabbing banner from %s:%d...\n", host, port)
	ctx := context.Background()
	banner, err := grabBanner(ctx, host, port, 5*time.Second)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	if banner != "" {
		fmt.Printf("Banner: %s\n", banner)
	} else {
		fmt.Println("Could not retrieve banner (port may be closed or no banner available)")
	}
}

// Handles the IP range scanning command
func handleUIRangeCommand(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: range <start-end> [start] [end] [threads]")
		return
	}

	ipRange := args[1]
	startPort := 1
	endPort := 100
	threads := 100

	// Parse optional args
	if len(args) >= 3 {
		var err error
		startPort, err = strconv.Atoi(args[2])
		if err != nil {
			fmt.Println("Invalid start port, using default (1)")
			startPort = 1
		}
	}

	if len(args) >= 4 {
		var err error
		endPort, err = strconv.Atoi(args[3])
		if err != nil {
			fmt.Println("Invalid end port, using default (100)")
			endPort = 100
		}
	}

	if len(args) >= 5 {
		var err error
		threads, err = strconv.Atoi(args[4])
		if err != nil {
			fmt.Println("Invalid thread count, using default (100)")
			threads = 100
		}
	}

	// Get list of IPs from range
	hosts, err := expandIPRange(ipRange)
	if err != nil {
		fmt.Printf("Error expanding IP range: %v\n", err)
		return
	}

	fmt.Printf("Scanning %d hosts in range %s (ports %d-%d)\n",
		len(hosts), ipRange, startPort, endPort)

	// Support cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Ctrl+C handler
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt)
		<-sigChan
		fmt.Println("\nCancelling scan...")
		cancel()
	}()

	// Scan each host
	for _, host := range hosts {
		// Check if canceled
		select {
		case <-ctx.Done():
			fmt.Println("Scan cancelled.")
			return
		default:
			// Continue
		}

		// Check if host is alive first
		fmt.Printf("\nChecking if %s is alive... ", host)
		if !isHostAlive(ctx, host, 500*time.Millisecond) {
			fmt.Println("Host appears to be down, skipping.")
			continue
		}
		fmt.Println("Host is up!")

		// Configure scanner
		scanner := NewScanner(
			WithTarget(host),
			WithPortRange(startPort, endPort),
			WithThreads(threads),
			WithTimeout(500*time.Millisecond),
			WithProgress(true),
			WithContext(ctx),
		)

		// Run the scan
		fmt.Printf("Scanning %s (ports %d-%d)...\n", host, startPort, endPort)
		openPorts, err := scanner.Scan()
		if err != nil {
			fmt.Printf("Scan error: %v\n", err)
			continue
		}

		// Show results
		if len(openPorts) > 0 {
			fmt.Printf("Open ports on %s: ", host)
			for i, port := range openPorts {
				service := getServiceName(port)
				if i > 0 {
					fmt.Print(", ")
				}
				fmt.Printf("%d (%s)", port, service)
			}
			fmt.Println()
		} else {
			fmt.Printf("No open ports found on %s\n", host)
		}
	}
}
