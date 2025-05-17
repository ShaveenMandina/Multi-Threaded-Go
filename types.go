package main

import (
	"sync"
	"time"
)

// Stores scan results
type ScanResult struct {
	Host      string
	Ports     []PortInfo
	Timestamp time.Time
	Duration  time.Duration
}

// Info about an open port
type PortInfo struct {
	Port    int
	Service string
	Banner  string
}

// Thread-safe global results storage
var (
	scanResults  []ScanResult
	resultsMutex sync.RWMutex
)

// Possible port states
type PortStatus int

const (
	StatusOpen PortStatus = iota
	StatusClosed
	StatusFiltered
	StatusError
)

// Convert status to string
func (s PortStatus) String() string {
	return [...]string{"Open", "Closed", "Filtered", "Error"}[s]
}
