package queue

import (
	"context"
	"errors"
	"testing"

	"github.com/hksolutions/guardhub/apps/scanner/internal/checks"
	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
)

// The lab path skips the ownership proof, so it must be impossible to aim it
// at anything but a lab container (§9.2).
func TestScanLabOriginRefusesNonLabTargets(t *testing.T) {
	calls := 0
	s := &Service{Registry: checks.Default(), NewScanProbe: func() *probe.Client {
		calls++
		return probe.New(probe.Options{})
	}}
	cases := []struct {
		origin  string
		allowed []string
	}{
		{"https://example.com", []string{"example.com"}},            // real domain, even if allow-listed
		{"https://juice-shop.lab.test", nil},                        // lab domain but not allow-listed
		{"https://juice-shop.lab.test", []string{"other.lab.test"}}, // a different lab host
		{"https://lab.test.example.com", []string{"lab.test.example.com"}},
		{"https://evil.lab.test.example.com", []string{"evil.lab.test.example.com"}},
	}
	for _, c := range cases {
		_, _, err := s.ScanLabOrigin(context.Background(), c.origin, c.allowed)
		if !errors.Is(err, ErrNotALabTarget) {
			t.Errorf("%s (allowed %v): want ErrNotALabTarget, got %v", c.origin, c.allowed, err)
		}
	}
	if calls != 0 {
		t.Errorf("no probe client may be created for a refused target (%d created)", calls)
	}
}
