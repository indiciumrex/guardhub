package deps

// OSV API client (https://google.github.io/osv.dev/api/): /v1/querybatch to
// find advisory ids for exact package versions, /v1/vulns/{id} for details.
// Only package names and versions are sent (ADR-0006 §7).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// DefaultOSVURL is the production OSV API base.
const DefaultOSVURL = "https://api.osv.dev"

const (
	osvBatchSize    = 500 // the API accepts up to 1000 queries per batch
	osvMaxPages     = 5   // next_page_token rounds per batch (each page: 1000 ids)
	osvBodyCap      = 16 << 20
	osvVulnBodyCap  = 2 << 20
	osvConcurrency  = 4
	osvUserAgent    = "GuardHub-Scanner/1.0 (+https://guardhub.dev/scanner)"
	osvRetryBackoff = 500 * time.Millisecond
)

// ErrOSV wraps every OSV failure (unreachable, bad answer).
var ErrOSV = errors.New("OSV query failed")

// ErrTooManyAdvisories means more advisories matched than the per-scan cap
// allows fetching; findings for the fetched ones are still reported.
var ErrTooManyAdvisories = errors.New("too many advisories for one scan")

// OSV is an OSV API client.
type OSV struct {
	Base     string // without trailing slash
	HTTP     *http.Client
	MaxVulns int // advisory detail fetches per scan
}

// NewOSV builds a client on transport.
func NewOSV(base string, transport http.RoundTripper, timeout time.Duration, maxVulns int) *OSV {
	if base == "" {
		base = DefaultOSVURL
	}
	return &OSV{
		Base:     strings.TrimRight(base, "/"),
		HTTP:     &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: noRedirects},
		MaxVulns: maxVulns,
	}
}

func noRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// Vuln is the part of an OSV record GuardHub uses.
type Vuln struct {
	ID               string     `json:"id"`
	Aliases          []string   `json:"aliases"`
	Withdrawn        string     `json:"withdrawn"`
	Severity         []Severity `json:"severity"`
	Affected         []Affected `json:"affected"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// Severity is one OSV severity entry (type + vector).
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Affected is one affected package of a record.
type Affected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Ranges   []Range  `json:"ranges"`
	Versions []string `json:"versions"`
}

// Range is an OSV range with its events.
type Range struct {
	Type   string              `json:"type"`
	Events []map[string]string `json:"events"`
}

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version   string `json:"version"`
	PageToken string `json:"page_token,omitempty"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	} `json:"results"`
}

// Matches returns, for each package, the ids of the advisories OSV lists
// for its exact version (same order as pkgs).
func (o *OSV) Matches(ctx context.Context, pkgs []Package) ([][]string, error) {
	out := make([][]string, len(pkgs))
	for start := 0; start < len(pkgs); start += osvBatchSize {
		end := min(start+osvBatchSize, len(pkgs))
		pending := make([]int, 0, end-start)
		tokens := map[int]string{}
		for i := start; i < end; i++ {
			pending = append(pending, i)
		}
		for page := 0; len(pending) > 0; page++ {
			if page >= osvMaxPages {
				return out, fmt.Errorf("%w: paging did not end", ErrTooManyAdvisories)
			}
			queries := make([]osvQuery, len(pending))
			for qi, i := range pending {
				queries[qi].Package.Name = pkgs[i].Name
				queries[qi].Package.Ecosystem = pkgs[i].Ecosystem
				queries[qi].Version = pkgs[i].Version
				queries[qi].PageToken = tokens[i]
			}
			var resp osvBatchResponse
			if err := o.post(ctx, "/v1/querybatch", map[string]any{"queries": queries}, &resp); err != nil {
				return out, err
			}
			if len(resp.Results) != len(pending) {
				return out, fmt.Errorf("%w: querybatch returned %d results for %d queries", ErrOSV, len(resp.Results), len(pending))
			}
			var next []int
			for qi, r := range resp.Results {
				i := pending[qi]
				for _, v := range r.Vulns {
					if validVulnID(v.ID) {
						out[i] = append(out[i], v.ID)
					}
				}
				if r.NextPageToken != "" {
					tokens[i] = r.NextPageToken
					next = append(next, i)
				}
			}
			pending = next
		}
	}
	return out, nil
}

var vulnIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{1,99}$`)

func validVulnID(id string) bool { return vulnIDRe.MatchString(id) }

// Vulns fetches the records of ids (deduplicated), at most MaxVulns of them.
// It returns what it fetched plus ErrTooManyAdvisories when the cap cut it.
func (o *OSV) Vulns(ctx context.Context, ids []string) (map[string]*Vuln, error) {
	seen := map[string]bool{}
	var uniq []string
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			uniq = append(uniq, id)
		}
	}
	var capErr error
	if o.MaxVulns > 0 && len(uniq) > o.MaxVulns {
		uniq, capErr = uniq[:o.MaxVulns], ErrTooManyAdvisories
	}
	out := make(map[string]*Vuln, len(uniq))
	var mu sync.Mutex
	var firstErr error
	sem := make(chan struct{}, osvConcurrency)
	var wg sync.WaitGroup
	for _, id := range uniq {
		wg.Add(1)
		sem <- struct{}{}
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()
			v, err := o.vuln(ctx, id)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			out[id] = v
		}(id)
	}
	wg.Wait()
	if firstErr != nil {
		return out, firstErr
	}
	return out, capErr
}

func (o *OSV) vuln(ctx context.Context, id string) (*Vuln, error) {
	var v Vuln
	if err := o.get(ctx, "/v1/vulns/"+url.PathEscape(id), &v); err != nil {
		return nil, err
	}
	if v.ID == "" {
		return nil, fmt.Errorf("%w: empty record for %s", ErrOSV, id)
	}
	return &v, nil
}

func (o *OSV) post(ctx context.Context, p string, body, into any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return o.do(ctx, http.MethodPost, p, raw, osvBodyCap, into)
}

func (o *OSV) get(ctx context.Context, p string, into any) error {
	return o.do(ctx, http.MethodGet, p, nil, osvVulnBodyCap, into)
}

// do sends one request with a single retry on a transport error or 5xx/429.
func (o *OSV) do(ctx context.Context, method, p string, body []byte, bodyCap int64, into any) error {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(osvRetryBackoff):
			}
		}
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, o.Base+p, rd)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", osvUserAgent)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := o.HTTP.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			lastErr = fmt.Errorf("%w: %w", ErrOSV, err)
			continue
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, bodyCap+1))
		_ = resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			lastErr = fmt.Errorf("%w: %s %s: HTTP %d", ErrOSV, method, p, resp.StatusCode)
			continue
		case resp.StatusCode != http.StatusOK:
			return fmt.Errorf("%w: %s %s: HTTP %d", ErrOSV, method, p, resp.StatusCode)
		case readErr != nil:
			return fmt.Errorf("%w: %w", ErrOSV, readErr)
		case int64(len(raw)) > bodyCap:
			return fmt.Errorf("%w: answer too large", ErrOSV)
		}
		if err := json.Unmarshal(raw, into); err != nil {
			return fmt.Errorf("%w: %w", ErrOSV, err)
		}
		return nil
	}
	return lastErr
}
