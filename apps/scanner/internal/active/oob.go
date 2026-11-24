package active

// Out-of-band (OOB) collaborator (ADR-0008 §6). Blind SSRF is proven only
// when the target itself fetches a unique URL GuardHub handed it: the
// collaborator records every hit on /t/<token>, and the scanner asks it,
// for its own tokens only, whether one arrived.
//
// The lab runs one at http://oob.lab.test (cmd/laboob). A real-target
// collaborator needs a domain and server the founder controls (DNS
// delegation for DNS-only interactions); until then SSRF is lab-only.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Collaborator hands out per-probe URLs and reports interactions with them.
type Collaborator interface {
	// URL returns the unique URL for token.
	URL(token string) string
	// Seen reports whether the collaborator recorded a hit for token.
	Seen(ctx context.Context, token string) (bool, error)
}

// NewToken returns a random, unguessable 32-hex-digit token.
func NewToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// HTTPCollaborator talks to a cmd/laboob-compatible collaborator:
// hits are GET <Base>/t/<token>, queries GET <Base>/interactions/<token> ->
// {"token": "...", "hits": N}.
type HTTPCollaborator struct {
	Base string       // e.g. "http://oob.lab.test" (no trailing slash)
	HTTP *http.Client // guarded transport (the collaborator is not the target)
}

// URL implements Collaborator.
func (c HTTPCollaborator) URL(token string) string {
	return strings.TrimRight(c.Base, "/") + "/t/" + url.PathEscape(token)
}

// Seen implements Collaborator.
func (c HTTPCollaborator) Seen(ctx context.Context, token string) (bool, error) {
	hc := c.HTTP
	if hc == nil {
		return false, errors.New("active: collaborator has no HTTP client")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.Base, "/")+"/interactions/"+url.PathEscape(token), nil)
	if err != nil {
		return false, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("active: collaborator answered HTTP %d", resp.StatusCode)
	}
	var out struct {
		Token string `json:"token"`
		Hits  int    `json:"hits"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&out); err != nil {
		return false, err
	}
	return out.Token == token && out.Hits > 0, nil
}

// WaitSeen polls Seen until a hit, the deadline, or ctx ends.
func WaitSeen(ctx context.Context, c Collaborator, token string, wait, every time.Duration) (bool, error) {
	deadline := time.Now().Add(wait)
	for {
		seen, err := c.Seen(ctx, token)
		if err != nil || seen {
			return seen, err
		}
		if time.Now().After(deadline) {
			return false, nil
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(every):
		}
	}
}
