package active

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
)

// UserAgent marks every active request (the request log and the target's
// own logs can tell them apart from passive scans).
const UserAgent = "GuardHub-Active/1.0 (+https://guardhub.dev/scanner)"

const (
	bodyCap      = 256 << 10
	maxRedirects = 3
)

// Request is one active request. It can only be built by this package's
// constructors, from the catalogue: modules cannot send arbitrary bytes.
type Request struct {
	module  string
	payload Payload // zero for a baseline (unmodified) request
	control bool    // send the payload's Control instead of its Value
	target  *url.URL
	param   string
	oob     string   // OOB name substituted for {oob}
	session *Session // nil: anonymous (session.go)
}

// Baseline is an unmodified GET of target (a page with its own query).
func Baseline(module string, target *url.URL) Request {
	return Request{module: module, target: target}
}

// Probe puts payload p (from the catalogue) into query parameter param of
// target. It panics on a payload not in the catalogue or of another module:
// that is a programming error, caught by tests.
func Probe(module string, target *url.URL, param string, p Payload) Request {
	mustCatalogued(module, p)
	return Request{module: module, payload: p, target: target, param: param}
}

// ControlProbe is Probe with the payload's harmless control value.
func ControlProbe(module string, target *url.URL, param string, p Payload) Request {
	r := Probe(module, target, param, p)
	r.control = true
	return r
}

// OOBProbe is Probe for an OOB payload: {oob} becomes the collaborator's URL
// for this probe's token (oob.go).
func OOBProbe(module string, target *url.URL, param string, p Payload, oobURL string) Request {
	r := Probe(module, target, param, p)
	r.oob = oobURL
	return r
}

func mustCatalogued(module string, p Payload) {
	c, ok := PayloadByID(p.ID)
	if !ok || c != p || c.Module != module {
		panic(fmt.Sprintf("active: payload %q is not a catalogued payload of %s", p.ID, module))
	}
}

func (r Request) value() string {
	v := r.payload.Value
	if r.control {
		v = r.payload.Control
	}
	return strings.ReplaceAll(v, OOBPlaceholder, r.oob)
}

func (r Request) payloadID() string {
	switch {
	case r.payload.ID == "":
		return "baseline"
	case r.control:
		return r.payload.ID + "#control"
	}
	return r.payload.ID
}

// url builds the request URL (query placement) without touching other params.
func (r Request) url() *url.URL {
	u := *r.target
	if r.payload.ID != "" && r.payload.In == InQuery {
		q := u.Query()
		q.Set(r.param, r.value())
		u.RawQuery = q.Encode()
	}
	u.Fragment = ""
	return &u
}

// Response is what a module sees of an answer.
type Response struct {
	Status   int
	Header   http.Header
	Body     []byte // up to 256 KiB
	URL      *url.URL
	Location string // the Location header of a redirect that was not followed
	Latency  time.Duration
}

// Client sends active requests for one scan (ADR-0008).
type Client struct {
	scope   Scope
	kill    KillSwitch
	limits  Limits
	log     *RequestLog
	http    *http.Client
	limiter *rate.Limiter
	brk     *breaker

	mu       sync.Mutex
	sent     int
	byModule map[string]int
}

// Options configure a Client.
type Options struct {
	Scope             Scope
	Kill              KillSwitch
	Limits            Limits
	Log               *RequestLog
	Timeout           time.Duration // per request (default 10s)
	AllowPrivateHosts []string      // lab only (exact hostnames), as probe.Options
	InsecureTLS       bool          // certificate problems are passive checks' business
}

// NewClient builds a Client. Kill and Log are required.
func NewClient(o Options) (*Client, error) {
	if o.Kill == nil || o.Log == nil || o.Scope.origin == nil {
		return nil, errors.New("active: scope, kill switch and request log are required")
	}
	if o.Limits == (Limits{}) {
		o.Limits = DefaultLimits()
	}
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           probe.GuardedDialer(o.Timeout, o.AllowPrivateHosts),
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: o.InsecureTLS}, //nolint:gosec // findings, not trust, are judged here
		TLSHandshakeTimeout:   o.Timeout,
		ResponseHeaderTimeout: o.Timeout,
		MaxIdleConns:          2,
		DisableCompression:    false,
	}
	return &Client{
		scope:  o.Scope,
		kill:   o.Kill,
		limits: o.Limits,
		log:    o.Log,
		http: &http.Client{Transport: tr, Timeout: o.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		limiter:  rate.NewLimiter(rate.Limit(o.Limits.RPS), 1),
		brk:      &breaker{lim: o.Limits},
		byModule: map[string]int{},
	}, nil
}

// Send sends r through every fence, following at most 3 same-origin
// redirects (each hop is scope-checked, logged and budgeted). Cross-origin
// redirects are returned unfollowed with Location set.
func (c *Client) Send(ctx context.Context, r Request) (*Response, error) {
	u := r.url()
	for hop := 0; ; hop++ {
		resp, err := c.one(ctx, r, u)
		if err != nil || resp.Location == "" || hop == maxRedirects {
			return resp, err
		}
		next, perr := u.Parse(resp.Location)
		if perr != nil || c.scope.Check(next) != nil {
			return resp, nil // a redirect elsewhere is a fact for the module, never followed
		}
		u = next
		r = AsSession(Baseline(r.module, next), r.session) // later hops: no payload, same session (same origin only)
	}
}

func (c *Client) one(ctx context.Context, r Request, u *url.URL) (*Response, error) {
	entry := LogEntry{At: time.Now().UTC(), Module: r.module, PayloadID: r.payloadID(), PayloadHash: payloadHash(r.value()),
		Method: http.MethodGet, Path: u.EscapedPath(), Param: r.param}
	if r.session != nil {
		entry.Session = r.session.Name // never the cookie
	}
	if r.payload.ID == "" {
		entry.PayloadHash = ""
	}
	refuse := func(outcome string, err error) error {
		entry.Outcome = outcome
		c.log.add(entry)
		return err
	}
	if ctx.Err() != nil || c.kill.Killed(ctx) {
		return nil, refuse(OutcomeKilled, ErrKilled)
	}
	if err := c.scope.Check(u); err != nil {
		return nil, refuse(OutcomeScope, err)
	}
	if c.brk.isTripped() {
		return nil, refuse(OutcomeBreaker, ErrBreaker)
	}
	if err := c.reserve(r.module); err != nil {
		return nil, refuse(OutcomeBudget, err)
	}
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, refuse(OutcomeKilled, ErrKilled)
	}
	if c.kill.Killed(ctx) { // the wait may have been long: check again
		return nil, refuse(OutcomeKilled, ErrKilled)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, refuse(OutcomeScope, ErrOutOfScope)
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.8")
	if r.session != nil {
		if err := r.session.Validate(); err != nil {
			return nil, refuse(OutcomeScope, err)
		}
		req.Header.Set("Cookie", r.session.Cookie)
	}
	if r.payload.ID != "" && r.payload.In == InOrigin {
		req.Header.Set("Origin", r.value())
	}
	start := time.Now()
	entry.At = start.UTC() // a sent request is logged at the moment it left (after the rate limiter)
	hr, err := c.http.Do(req)
	lat := time.Since(start)
	entry.LatencyMS = lat.Milliseconds()
	if err != nil {
		entry.Outcome = OutcomeError
		c.log.add(entry)
		if errors.Is(err, probe.ErrBlockedAddress) || strings.Contains(err.Error(), "destination address is not allowed") {
			return nil, probe.ErrBlockedAddress
		}
		if c.brk.observe(0, lat) {
			return nil, ErrBreaker
		}
		return nil, err
	}
	defer func() { _ = hr.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(hr.Body, bodyCap))
	entry.Status, entry.Length, entry.Outcome = hr.StatusCode, len(body), OutcomeSent
	c.log.add(entry)
	resp := &Response{Status: hr.StatusCode, Header: hr.Header, Body: body, URL: u, Latency: lat}
	if hr.StatusCode >= 300 && hr.StatusCode < 400 {
		resp.Location = hr.Header.Get("Location")
	}
	if hr.StatusCode == http.StatusTooManyRequests || hr.StatusCode == http.StatusServiceUnavailable {
		ra, _ := strconv.Atoi(strings.TrimSpace(hr.Header.Get("Retry-After")))
		wait := time.Duration(ra) * time.Second
		if wait > c.limits.MaxRetryAfter {
			c.brk.trip()
			return resp, ErrBreaker
		}
		c.limiter.SetLimit(c.limiter.Limit() / 2) // slow down for the rest of the scan
		select {
		case <-ctx.Done():
			return resp, ErrKilled
		case <-time.After(max(wait, time.Second)):
		}
	}
	if c.brk.observe(hr.StatusCode, lat) {
		return resp, ErrBreaker
	}
	return resp, nil
}

// reserve counts one request against the scan's and the module's budget:
// ErrBudget when the scan's is spent, ErrModuleBudget when only the module's is.
func (c *Client) reserve(module string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sent >= c.limits.ScanBudget {
		return ErrBudget
	}
	if c.byModule[module] >= c.limits.ModuleBudget {
		return ErrModuleBudget
	}
	c.sent++
	c.byModule[module]++
	return nil
}

// Sent returns the number of requests that passed every fence.
func (c *Client) Sent() int { c.mu.Lock(); defer c.mu.Unlock(); return c.sent }
