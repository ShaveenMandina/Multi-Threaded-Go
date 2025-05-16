package main

import (
	"sync"
	"time"
)

// ----- GO'S STRUCT TYPES FOR DATA MODELING -----
// ScanResult represents the result of a port scan
type ScanResult struct {
	Host      string
	Ports     []PortInfo
	Timestamp time.Time
	Duration  time.Duration
}

// PortInfo represents information about an open port
type PortInfo struct {
	Port    int
	Service string
	Banner  string
}

// ----- GO'S SYNCHRONIZATION PRIMITIVES -----
// Global variables for storing scan results with mutex for thread safety
var (
	scanResults  []ScanResult
	resultsMutex sync.RWMutex
)

// Port status enumeration using iota (Go's auto-incrementing constant)
type PortStatus int

const (
	StatusOpen PortStatus = iota
	StatusClosed
	StatusFiltered
	StatusError
)

// String method for PortStatus - Go's approach to enums with methods
func (s PortStatus) String() string {
	return [...]string{"Open", "Closed", "Filtered", "Error"}[s]
}
