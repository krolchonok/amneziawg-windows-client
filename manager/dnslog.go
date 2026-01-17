package manager

import (
	"fmt"
	"sync"
	"time"
)

// DNSLogEntry represents a single DNS query log entry
type DNSLogEntry struct {
	Timestamp   time.Time
	Domain      string
	QueryType   string
	Target      string // "tunnel", "direct", or "default"
	ResponseIPs []string
	Latency     time.Duration
	Error       string
}

func (e DNSLogEntry) String() string {
	ts := e.Timestamp.Format("15:04:05.000")
	ips := ""
	if len(e.ResponseIPs) > 0 {
		ips = fmt.Sprintf(" -> %v", e.ResponseIPs)
	}
	errStr := ""
	if e.Error != "" {
		errStr = fmt.Sprintf(" [ERROR: %s]", e.Error)
	}
	return fmt.Sprintf("[%s] %s (%s) via %s%s (%v)%s",
		ts, e.Domain, e.QueryType, e.Target, ips, e.Latency, errStr)
}

// DNSLogger manages DNS query logging
type DNSLogger struct {
	mu       sync.RWMutex
	entries  []DNSLogEntry
	maxSize  int
	enabled  bool
	onChange func()
}

var dnsLogger = &DNSLogger{
	entries: make([]DNSLogEntry, 0, 1000),
	maxSize: 1000,
	enabled: true,
}

// GetDNSLogger returns the global DNS logger
func GetDNSLogger() *DNSLogger {
	return dnsLogger
}

// Log adds a new entry to the log
func (l *DNSLogger) Log(entry DNSLogEntry) {
	if !l.enabled {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	l.entries = append(l.entries, entry)

	// Trim if exceeds max size
	if len(l.entries) > l.maxSize {
		l.entries = l.entries[len(l.entries)-l.maxSize:]
	}

	if l.onChange != nil {
		go l.onChange()
	}
}

// GetEntries returns all log entries
func (l *DNSLogger) GetEntries() []DNSLogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	result := make([]DNSLogEntry, len(l.entries))
	copy(result, l.entries)
	return result
}

// GetEntriesSince returns entries since given timestamp
func (l *DNSLogger) GetEntriesSince(since time.Time) []DNSLogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var result []DNSLogEntry
	for _, e := range l.entries {
		if e.Timestamp.After(since) {
			result = append(result, e)
		}
	}
	return result
}

// Clear removes all entries
func (l *DNSLogger) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = l.entries[:0]
}

// SetEnabled enables or disables logging
func (l *DNSLogger) SetEnabled(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.enabled = enabled
}

// IsEnabled returns whether logging is enabled
func (l *DNSLogger) IsEnabled() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.enabled
}

// SetOnChange sets callback for when new entries are added
func (l *DNSLogger) SetOnChange(fn func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.onChange = fn
}

// Count returns number of entries
func (l *DNSLogger) Count() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}
