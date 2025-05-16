package main

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// scanInProgress tracks if there's an ongoing scan
var scanInProgress bool
var scanMutex sync.Mutex

// startWebServer starts a web server on port 8080
func startWebServer() {
	// Define the HTML template using Go's template package
	tmpl := template.Must(template.New("index").Parse(`
<!DOCTYPE html>
<html>
<head>
    <title>Port Scanner</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin-bottom: 20px;
        }
        th, td {
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
            font-weight: bold;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .scan-form {
            background-color: #f9f9f9;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .scan-form input, .scan-form button {
            padding: 8px;
            margin: 5px;
        }
        .scan-form button, .action-button {
            background-color: #3498db;
            color: white;
            border: none;
            cursor: pointer;
            padding: 10px 15px;
        }
        .scan-form button:hover, .action-button:hover {
            background-color: #2980b9;
        }
        .clear-button {
            background-color: #e74c3c;
            color: white;
            border: none;
            cursor: pointer;
            padding: 10px 15px;
            margin-left: 10px;
        }
        .clear-button:hover {
            background-color: #c0392b;
        }
        .actions-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .timestamp {
            color: #7f8c8d;
            font-size: 0.9em;
        }
        .banner {
            font-family: monospace;
            word-break: break-all;
        }
        .help-text {
            background-color: #eaf5fb;
            padding: 15px;
            border-left: 4px solid #3498db;
            margin-bottom: 20px;
            border-radius: 0 5px 5px 0;
        }
        .field-description {
            color: #666;
            font-size: 0.9em;
            margin-top: 3px;
            margin-left: 5px;
        }
        .parameter-group {
            margin-bottom: 15px;
        }
        .parameter-label {
            display: block;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .info-icon {
            display: inline-block;
            width: 16px;
            height: 16px;
            background-color: #3498db;
            color: white;
            border-radius: 50%;
            text-align: center;
            font-size: 12px;
            line-height: 16px;
            margin-left: 5px;
            cursor: help;
        }
        .no-results-message {
            background-color: #fcf8e3;
            padding: 15px;
            border-left: 4px solid #f39c12;
            margin-top: 15px;
            border-radius: 0 5px 5px 0;
        }
        .go-features {
            background-color: #e8f6e8;
            padding: 15px;
            border-left: 4px solid #27ae60;
            margin: 20px 0;
            border-radius: 0 5px 5px 0;
        }
        .go-features h3 {
            color: #27ae60;
            margin-top: 0;
        }
        .go-features ul {
            margin-bottom: 0;
        }
        #scan-status {
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
            font-weight: bold;
            text-align: center;
            display: none;
        }
        .scan-in-progress {
            background-color: #3498db;
            color: white;
        }
        .scan-complete {
            background-color: #27ae60;
            color: white;
        }
        .scan-error {
            background-color: #e74c3c;
            color: white;
        }
        .refresh-button {
            background-color: #2ecc71;
            color: white;
            border: none;
            cursor: pointer;
            padding: 10px 15px;
            margin-left: 10px;
        }
        .refresh-button:hover {
            background-color: #27ae60;
        }
    </style>
</head>
<body>
    <h1>Port Scanner</h1>
    
    <div class="go-features">
        <h3>Go Features Showcased in This Application</h3>
        <ul>
            <li><strong>Goroutines:</strong> Lightweight threads allowing thousands of concurrent port checks</li>
            <li><strong>Channels:</strong> Type-safe communication between scan workers</li>
            <li><strong>Select Statement:</strong> Handling multiple concurrent operations elegantly</li>
            <li><strong>Context Package:</strong> Clean cancellation and timeout handling</li>
            <li><strong>WaitGroup:</strong> Coordination of concurrent goroutines</li>
            <li><strong>Defer:</strong> Guaranteed resource cleanup</li>
            <li><strong>Interfaces:</strong> Extensible service detection plugins</li>
        </ul>
    </div>
    
    <div class="help-text">
        <h3>How to Use This Scanner</h3>
        <p>This tool checks which ports are open on a target computer or website. Open ports can tell you what services are running.</p>
        <ul>
            <li><strong>Host:</strong> Enter a website (like example.com) or an IP address (like 192.168.1.1)</li>
            <li><strong>Start/End Port:</strong> Choose which port numbers to check (common range: 1-1000)</li>
            <li><strong>Timeout:</strong> How long to wait for a response (higher values work better for distant servers)</li>
            <li><strong>Threads:</strong> How many checks to run at once (higher values = faster scanning)</li>
        </ul>
        <p><strong>Note:</strong> Major websites like Google often block port scans. Try scanning your router (usually 192.168.1.1) to see results.</p>
    </div>
    
    <div class="scan-form">
        <h2>New Scan</h2>
        <form method="post" action="/scan">
            <div class="parameter-group">
                <label class="parameter-label" for="host">Host:</label>
                <input type="text" id="host" name="host" required placeholder="e.g., example.com or 192.168.1.1">
                <div class="field-description">The website or IP address you want to scan</div>
            </div>
            
            <div class="parameter-group">
                <label class="parameter-label" for="start">Start Port:</label>
                <input type="number" id="start" name="start" value="1" min="1" max="65535">
                <div class="field-description">The first port number to check (usually 1)</div>
                
                <label class="parameter-label" for="end">End Port:</label>
                <input type="number" id="end" name="end" value="1000" min="1" max="65535">
                <div class="field-description">The last port number to check (common values: 1000, 10000)</div>
            </div>
            
            <div class="parameter-group">
                <label class="parameter-label" for="timeout">Timeout (ms):</label>
                <input type="number" id="timeout" name="timeout" value="500" min="100" max="10000">
                <div class="field-description">How long to wait for responses in milliseconds (try 2000 for remote servers)</div>
                
                <label class="parameter-label" for="threads">Threads:</label>
                <input type="number" id="threads" name="threads" value="100" min="10" max="500">
                <div class="field-description">Number of simultaneous connections (higher = faster)</div>
            </div>
            
            <button type="submit" id="scan-button">Start Scan</button>
        </form>
    </div>
    
    <div id="scan-status"></div>
    
    <div class="actions-bar">
        <h2>Scan Results</h2>
        <div>
            <button id="refresh-button" class="refresh-button">Refresh Results</button>
            <form method="post" action="/clear" style="display: inline;">
                <button type="submit" class="clear-button">Clear All Results</button>
            </form>
        </div>
    </div>
    
    {{if .}}
        {{range .}}
            <h3>{{.Host}} <span class="timestamp">({{.Timestamp.Format "Jan 02, 2006 15:04:05"}} - Duration: {{.Duration}})</span></h3>
            <table>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Banner</th>
                </tr>
                {{range .Ports}}
                <tr>
                    <td>{{.Port}}</td>
                    <td>{{.Service}}</td>
                    <td class="banner">{{.Banner}}</td>
                </tr>
                {{else}}
                <tr>
                    <td colspan="3">No open ports found</td>
                </tr>
                {{end}}
            </table>
            
            {{if not .Ports}}
            <div class="no-results-message">
                <h4>Why No Results?</h4>
                <p>Several reasons why no open ports may be found:</p>
                <ul>
                    <li><strong>Security Measures:</strong> Large websites use firewalls that block port scans</li>
                    <li><strong>ISP Filtering:</strong> Your internet provider might be blocking scanning traffic</li>
                    <li><strong>Try Different Settings:</strong> Use a longer timeout (2000ms) or scan a different host</li>
                    <li><strong>Recommended Test:</strong> Try scanning your router (usually 192.168.1.1) or "scanme.nmap.org"</li>
                </ul>
            </div>
            {{end}}
        {{end}}
    {{else}}
        <p>No scans have been performed yet.</p>
    {{end}}
    
    <script>
        // Enhanced JavaScript for better user experience
        document.addEventListener('DOMContentLoaded', function() {
            const scanButton = document.querySelector('#scan-button');
            const scanForm = document.querySelector('.scan-form form');
            const scanStatus = document.querySelector('#scan-status');
            const refreshButton = document.querySelector('#refresh-button');
            
            // Add "scanning..." indicator when form is submitted
            scanForm.addEventListener('submit', function(e) {
                e.preventDefault(); // Prevent normal form submission
                
                // Show scanning status
                scanStatus.textContent = 'Scanning in progress... This may take a few moments.';
                scanStatus.className = 'scan-in-progress';
                scanStatus.style.display = 'block';
                
                // Disable scan button
                scanButton.textContent = 'Scanning...';
                scanButton.disabled = true;
                
                // Submit form via fetch API
                fetch('/scan', {
                    method: 'POST',
                    body: new FormData(this)
                })
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Scan request failed');
                    }
                    return response.text();
                })
                .then(() => {
                    // Start polling for scan completion
                    checkScanStatus();
                })
                .catch(error => {
                    scanStatus.textContent = 'Error: ' + error.message;
                    scanStatus.className = 'scan-error';
                    scanButton.textContent = 'Start Scan';
                    scanButton.disabled = false;
                });
            });
            
            // Refresh button functionality
            refreshButton.addEventListener('click', function() {
                window.location.reload();
            });
            
            // Function to check if scan is complete
            function checkScanStatus() {
                fetch('/scan-status')
                .then(response => response.json())
                .then(data => {
                    if (data.inProgress) {
                        // Still scanning, check again in a second
                        setTimeout(checkScanStatus, 1000);
                    } else {
                        // Scan complete, update UI
                        scanStatus.textContent = 'Scan complete! Refreshing results...';
                        scanStatus.className = 'scan-complete';
                        
                        // Re-enable scan button
                        scanButton.textContent = 'Start Scan';
                        scanButton.disabled = false;
                        
                        // Reload page to show results
                        setTimeout(() => {
                            window.location.reload();
                        }, 1000);
                    }
                })
                .catch(error => {
                    scanStatus.textContent = 'Error checking scan status: ' + error.message;
                    scanStatus.className = 'scan-error';
                    scanButton.textContent = 'Start Scan';
                    scanButton.disabled = false;
                });
            }
        });
    </script>
</body>
</html>
`))

	// ----- GO'S HTTP REQUEST HANDLING -----
	// Define HTTP handlers

	// Main page handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Use read lock for thread safety when reading results
		resultsMutex.RLock()
		defer resultsMutex.RUnlock()

		// Execute the template with scan results
		err := tmpl.Execute(w, scanResults)
		if err != nil {
			http.Error(w, fmt.Sprintf("Template error: %v", err), http.StatusInternalServerError)
		}
	})

	// Handler for scan requests
	http.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Check if a scan is already in progress
		scanMutex.Lock()
		if scanInProgress {
			scanMutex.Unlock()
			http.Error(w, "A scan is already in progress", http.StatusConflict)
			return
		}
		scanInProgress = true
		scanMutex.Unlock()

		// Parse form
		err := r.ParseForm()
		if err != nil {
			scanMutex.Lock()
			scanInProgress = false
			scanMutex.Unlock()
			http.Error(w, fmt.Sprintf("Form error: %v", err), http.StatusBadRequest)
			return
		}

		// Get form values with validation
		host := r.FormValue("host")
		if host == "" {
			scanMutex.Lock()
			scanInProgress = false
			scanMutex.Unlock()
			http.Error(w, "Host is required", http.StatusBadRequest)
			return
		}

		// ----- GO'S STRING CONVERSION -----
		// Parse numeric values with error handling - typical Go pattern
		startPort, err := strconv.Atoi(r.FormValue("start"))
		if err != nil || startPort < 1 || startPort > 65535 {
			startPort = 1
		}

		endPort, err := strconv.Atoi(r.FormValue("end"))
		if err != nil || endPort < 1 || endPort > 65535 || endPort < startPort {
			endPort = startPort + 1000
			if endPort > 65535 {
				endPort = 65535
			}
		}

		timeout, err := strconv.Atoi(r.FormValue("timeout"))
		if err != nil || timeout < 100 || timeout > 10000 {
			timeout = 500
		}

		threads, err := strconv.Atoi(r.FormValue("threads"))
		if err != nil || threads < 10 || threads > 500 {
			threads = 100
		}

		// ----- GO'S GOROUTINES FOR ASYNC PROCESSING -----
		// Start a scan in a goroutine to avoid blocking the HTTP response
		go func() {
			defer func() {
				// Ensure scanInProgress is set to false when done
				scanMutex.Lock()
				scanInProgress = false
				scanMutex.Unlock()
			}()

			// Create a cancellable context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			// Record start time for duration calculation
			startTime := time.Now()

			// Create scanner with options
			scanner := NewScanner(
				WithTarget(host),
				WithPortRange(startPort, endPort),
				WithThreads(threads),
				WithTimeout(time.Duration(timeout)*time.Millisecond),
				WithProgress(false), // No progress bar in web mode
				WithContext(ctx),
			)

			// Run the scan
			openPorts, err := scanner.Scan()
			scanDuration := time.Since(startTime)

			// Prepare results
			portInfos := []PortInfo{}

			if err == nil {
				// Collect information about each open port
				for _, port := range openPorts {
					banner, _ := grabBanner(ctx, host, port, time.Duration(timeout)*time.Millisecond)
					portInfos = append(portInfos, PortInfo{
						Port:    port,
						Service: getServiceName(port),
						Banner:  banner,
					})
				}
			}

			// Create a result object
			result := ScanResult{
				Host:      host,
				Ports:     portInfos,
				Timestamp: time.Now(),
				Duration:  scanDuration,
			}

			// Add to results with write lock for thread safety
			resultsMutex.Lock()
			scanResults = append([]ScanResult{result}, scanResults...)
			resultsMutex.Unlock()
		}()

		// Send a success response
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte("Scan started"))
	})

	// Handler for checking scan status
	http.HandleFunc("/scan-status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		scanMutex.Lock()
		status := scanInProgress
		scanMutex.Unlock()

		w.Write([]byte(fmt.Sprintf(`{"inProgress": %t}`, status)))
	})

	// Handler for clearing results
	http.HandleFunc("/clear", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Clear results with write lock
		resultsMutex.Lock()
		scanResults = []ScanResult{}
		resultsMutex.Unlock()

		// Redirect back to the main page
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	// Start the HTTP server
	fmt.Println("Web server running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
