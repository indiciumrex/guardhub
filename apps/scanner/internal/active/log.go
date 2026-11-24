package active

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// Outcomes of one request in the log (ADR-0008 §7).
const (
	OutcomeSent    = "sent"
	OutcomeScope   = "scope_refused"
	OutcomeKilled  = "killed"
	OutcomeBudget  = "budget"
	OutcomeBreaker = "breaker"
	OutcomeError   = "error" // sent, but no answer (network)
)

// LogEntry is one row of the request log. It never holds the response body,
// nor the payload itself (the catalogue does): only its id and SHA-256.
type LogEntry struct {
	At          time.Time `json:"at"`
	Module      string    `json:"module"`
	PayloadID   string    `json:"payload_id"` // "baseline" for an unmodified request
	PayloadHash string    `json:"payload_sha256,omitempty"`
	Method      string    `json:"method"`
	Path        string    `json:"path"`
	Param       string    `json:"param,omitempty"`
	Session     string    `json:"session,omitempty"` // consented test account name, never its cookie
	Status      int       `json:"status,omitempty"`
	Length      int       `json:"length,omitempty"`
	LatencyMS   int64     `json:"latency_ms,omitempty"`
	Outcome     string    `json:"outcome"`
}

// RequestLog collects the entries of one active scan, in order.
type RequestLog struct {
	mu      sync.Mutex
	entries []LogEntry
}

func (l *RequestLog) add(e LogEntry) {
	l.mu.Lock()
	l.entries = append(l.entries, e)
	l.mu.Unlock()
}

// Entries returns a copy of the log.
func (l *RequestLog) Entries() []LogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]LogEntry(nil), l.entries...)
}

// Count returns the number of entries with outcome.
func (l *RequestLog) Count(outcome string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, e := range l.entries {
		if e.Outcome == outcome {
			n++
		}
	}
	return n
}

func payloadHash(v string) string {
	if v == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}
