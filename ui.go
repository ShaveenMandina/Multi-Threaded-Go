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

// ----- GO'S TERMINAL UI FUNCTIONALITY -----
// displayProgress shows a progress bar during scanning
func displayProgress(done chan bool, total int) {
	// ----- GO'S TIME PACKAGE -----
	start := time.Now()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	counter := 0
	barWidth := 40

	for {
		// ----- GO'S SELECT FOR CHANNEL OPERATIONS -----
		select {
		case <-done:
			// Final progress update at 100%
			printProgressBar(barWidth, 100, time.Since(start), total, total)
			fmt.Println()
			return
		case <-ticker.C:
			counter++
			// Calculate progress based on time and typical scan rates
			elapsed := time.Since(start)
			estimatedTotal := 5 * time.Second
			if total > 1000 {
				estimatedTotal = 30 * time.Second
			} else if total > 100 {
				estimatedTotal = 15 * time.Second
			}

			// Adjust progress between 0 and 99% until done
			progress := float64(elapsed) / float64(estimatedTotal)
			if progress > 0.99 {
				progress = 0.99 // Cap at 99% until truly done
			}

			// Estimate ports completed
			portsCompleted := int(float64(total) * progress)

			// Print the progress bar
			printProgressBar(barWidth, progress*100, elapsed, portsCompleted, total)
		}
	}
}

// printProgressBar displays a progress bar with the given width and percentage
func printProgressBar(width int, percent float64, elapsed time.Duration, completed, total int) {
	// Calculate the number of filled positions
	filled := int(percent / 100 * float64(width))
	if filled > width {
		filled = width
	}

	// Build the progress bar
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)

	// Calculate ports per second (simple estimate)
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

	// Print the progress bar with percentage and time elapsed
	fmt.Printf("\r[%s] %.1f%% (%d/%d ports, %.1f ports/sec%s)    ",
		bar, percent, completed, total, portsPerSecond, remaining)
}

// ----- GO'S INTERACTIVE CONSOLE MODE -----
// runInteractiveMode provides a terminal user interface for scanning
func runInteractiveMode() {
	scanner := bufio.NewScanner(os.Stdin)

	// Show help menu
	printUIHelp()

	// Main interaction loop
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

// printUIHelp prints the help menu with available commands
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

// handleUIScanCommand processes the scan command in interactive mode
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

	// Parse optional parameters
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

	// Validate inputs
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

	// Create a cancellable context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle user interruption
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt)
		<-sigChan
		fmt.Println("\nCancelling scan...")
		cancel()
	}()

	// Create scanner with functional options
	scanner := NewScanner(
		WithTarget(host),
		WithPortRange(startPort, endPort),
		WithThreads(threads),
		WithTimeout(time.Duration(timeout)*time.Millisecond),
		WithProgress(true),
		WithContext(ctx),
	)

	// Perform the scan
	openPorts, err := scanner.Scan()
	if err != nil {
		fmt.Printf("\nScan error: %v\n", err)
		return
	}

	// Print results
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

		// Simple OS detection based on open ports
		fmt.Printf("OS Detection: %s\n", guessOS(openPorts))
	}
}

// handleUIPingCommand processes the ping command in interactive mode
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

// handleUIBannerCommand processes the banner command in interactive mode
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

// handleUIRangeCommand processes the range command in interactive mode
func handleUIRangeCommand(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: range <start-end> [start] [end] [threads]")
		return
	}

	ipRange := args[1]
	startPort := 1
	endPort := 100
	threads := 100

	// Parse optional parameters
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

	// Expand the IP range
	hosts, err := expandIPRange(ipRange)
	if err != nil {
		fmt.Printf("Error expanding IP range: %v\n", err)
		return
	}

	fmt.Printf("Scanning %d hosts in range %s (ports %d-%d)\n",
		len(hosts), ipRange, startPort, endPort)

	// Create context for cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle user interruption
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt)
		<-sigChan
		fmt.Println("\nCancelling scan...")
		cancel()
	}()

	// Scan each host
	for _, host := range hosts {
		// Check if context is cancelled
		select {
		case <-ctx.Done():
			fmt.Println("Scan cancelled.")
			return
		default:
			// Continue with scan
		}

		// Check if host is alive
		fmt.Printf("\nChecking if %s is alive... ", host)
		if !isHostAlive(ctx, host, 500*time.Millisecond) {
			fmt.Println("Host appears to be down, skipping.")
			continue
		}
		fmt.Println("Host is up!")

		// Create scanner with functional options
		scanner := NewScanner(
			WithTarget(host),
			WithPortRange(startPort, endPort),
			WithThreads(threads),
			WithTimeout(500*time.Millisecond),
			WithProgress(true),
			WithContext(ctx),
		)

		// Perform the scan
		fmt.Printf("Scanning %s (ports %d-%d)...\n", host, startPort, endPort)
		openPorts, err := scanner.Scan()
		if err != nil {
			fmt.Printf("Scan error: %v\n", err)
			continue
		}

		// Print results
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
