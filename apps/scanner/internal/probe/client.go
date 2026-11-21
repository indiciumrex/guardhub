// Package probe is the ONLY way scanner code touches the network. It
// enforces the do-no-harm safety envelope from docs/architecture.md §3:
// GET/HEAD only, fixed User-Agent, per-request timeout, bounded retries,
// per-host token-bucket rate limit, per-scan request budget, same-host
// redirect limit, body cap and a dial-time IP guard (anti-SSRF and
// anti-DNS-rebinding). It never sends cookies, credentials or request bodies.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// UserAgent is sent on every request.
const UserAgent = "GuardHub-Scanner/1.0 (+https://guardhub.dev/scanner)"

// Defaults from docs/architecture.md §3.
const (
	DefaultTimeout       = 10 * time.Second
	DefaultHostRPS       = 4.0
	DefaultHostBurst     = 2
	DefaultMaxRequests   = 80
	DefaultMaxRetries    = 2
	DefaultBackoffBase   = 500 * time.Millisecond
	DefaultMaxRetryAfter = 5 * time.Second
	DefaultMaxRedirects  = 3
	DefaultBodyCap       = 256 << 10
)

// Errors returned by the client. They are returned INSTEAD of sending a
// request: a refused request never reaches the network.
var (
	ErrMethodNotAllowed   = errors.New("probe: only GET and HEAD are allowed")
	ErrBudgetExceeded     = errors.New("probe: per-scan request budget exceeded")
	ErrTooManyRedirects   = errors.New("probe: too many redirects")
	ErrUnsupportedScheme  = errors.New("probe: only http and https URLs are allowed")
	ErrCredentialsInURL   = errors.New("probe: URLs with credentials are not allowed")
	ErrUnresolvableTarget = errors.New("probe: target host could not be resolved")
)

// Resolver is the DNS surface the client needs (*net.Resolver satisfies it).
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Options configures a Client. Zero values take the defaults above.
type Options struct {
	Timeout       time.Duration
	HostRPS       float64
	HostBurst     int
	MaxRequests   int
	MaxRetries    int // 0 means default (2); use -1 for no retries
	BackoffBase   time.Duration
	MaxRetryAfter time.Duration
	MaxRedirects  int
	BodyCap       int64

	// AllowPrivateHosts lists exact hostnames (case-insensitive) that bypass
	// the IP guard. Production leaves it empty except for the local e2e demo
	// target; tests use it for httptest servers on 127.0.0.1.
	AllowPrivateHosts []string

	// InsecureSkipVerify disables certificate verification for content
	// probes. Scans set it: certificate problems are reported by the
	// tls_cert check, and the other checks must still be able to look at a
	// site whose certificate is broken. Ownership verification leaves it off.
	InsecureSkipVerify bool
	// RootCAs overrides the system roots when verification is on (tests).
	RootCAs *x509.CertPool

	// Limiters is shared by all clients of a process so the per-host rate
	// limit holds across concurrent scans. Nil means a private set.
	Limiters *Limiters
	// Resolver overrides DNS (tests). Nil means net.DefaultResolver.
	Resolver Resolver
	// DNSServer is the recursive resolver ("host:port") for DNS record checks
	// (dns_email). Empty means the first nameserver in /etc/resolv.conf.
	DNSServer string
	// DNSPort is the port queries to a zone's nameservers go to (default
	// "53"; tests use a high port).
	DNSPort string
}

func (o *Options) withDefaults() {
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.HostRPS <= 0 {
		o.HostRPS = DefaultHostRPS
	}
	if o.HostBurst <= 0 {
		o.HostBurst = DefaultHostBurst
	}
	if o.MaxRequests <= 0 {
		o.MaxRequests = DefaultMaxRequests
	}
	switch {
	case o.MaxRetries == 0:
		o.MaxRetries = DefaultMaxRetries
	case o.MaxRetries < 0:
		o.MaxRetries = 0
	}
	if o.MaxRetries > DefaultMaxRetries {
		o.MaxRetries = DefaultMaxRetries
	}
	if o.BackoffBase <= 0 {
		o.BackoffBase = DefaultBackoffBase
	}
	if o.MaxRetryAfter <= 0 {
		o.MaxRetryAfter = DefaultMaxRetryAfter
	}
	if o.MaxRedirects <= 0 {
		o.MaxRedirects = DefaultMaxRedirects
	}
	if o.BodyCap <= 0 {
		o.BodyCap = DefaultBodyCap
	}
	if o.Limiters == nil {
		o.Limiters = NewLimiters(o.HostRPS, o.HostBurst)
	}
	if o.Resolver == nil {
		o.Resolver = net.DefaultResolver
	}
}

// Response is a fully read (and capped) HTTP response. It is shared between
// checks through the per-scan GET cache, so callers must treat it as
// read-only.
type Response struct {
	// URL is the final URL after followed redirects.
	URL        *url.URL
	StatusCode int
	Header     http.Header
	Body       []byte
	// Truncated is true when the body was longer than the cap.
	Truncated bool
	// Redirects is the list of followed hop URLs (excluding the final one).
	Redirects []string
	// RedirectRefused is set when the server redirected to another host;
	// the redirect response itself is returned unfollowed.
	RedirectRefused bool
}

// Client is a per-scan probe client. Create one per scan or verify job (the
// request budget is per client) and Close it afterwards.
type Client struct {
	opts      Options
	allow     map[string]bool
	transport *http.Transport
	hc        *http.Client
	used      atomic.Int64

	cacheMu sync.Mutex
	cache   map[string]*cacheEntry
}

type cacheEntry struct {
	done chan struct{}
	resp *Response
	err  error
}

// New builds a Client.
func New(opts Options) *Client {
	opts.withDefaults()
	c := &Client{
		opts:  opts,
		allow: make(map[string]bool, len(opts.AllowPrivateHosts)),
		cache: make(map[string]*cacheEntry),
	}
	for _, h := range opts.AllowPrivateHosts {
		c.allow[strings.ToLower(strings.TrimSpace(h))] = true
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if opts.InsecureSkipVerify {
		// Certificate validity is reported by the tls_cert check; content
		// probes must still work on sites with broken certificates. We never
		// send secrets, so this cannot leak anything.
		tlsCfg.InsecureSkipVerify = true
		// Same reasoning for legacy protocols: a TLS 1.0-only site is still
		// scanned (tls_cert reports the legacy protocol).
		tlsCfg.MinVersion = tls.VersionTLS10
		tlsCfg.CipherSuites = allCipherSuites()
	} else if opts.RootCAs != nil {
		tlsCfg.RootCAs = opts.RootCAs
	}
	c.transport = &http.Transport{
		Proxy:                  nil, // never route through env proxies: the guard must see the real peer
		DialContext:            c.dialContext,
		TLSClientConfig:        tlsCfg,
		TLSHandshakeTimeout:    opts.Timeout,
		ResponseHeaderTimeout:  opts.Timeout,
		MaxResponseHeaderBytes: 64 << 10,
		MaxIdleConnsPerHost:    2,
		IdleConnTimeout:        30 * time.Second,
		DisableCompression:     false,
	}
	c.hc = &http.Client{
		Transport: methodGuard{c.transport},
		Timeout:   opts.Timeout,
		// Redirects are followed manually so every hop is budgeted,
		// rate-limited and host-checked.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return c
}

// Close releases idle connections.
func (c *Client) Close() { c.transport.CloseIdleConnections() }

// RequestsUsed returns how many network operations this client has made.
func (c *Client) RequestsUsed() int { return int(c.used.Load()) }

// IsAllowedPrivate reports whether host is on the private-host allowlist.
func (c *Client) IsAllowedPrivate(host string) bool {
	return c.allow[strings.ToLower(host)]
}

// methodGuard is defence in depth: even if a caller bypassed Do, the
// transport refuses anything but GET/HEAD.
type methodGuard struct{ rt http.RoundTripper }

func (m methodGuard) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return nil, ErrMethodNotAllowed
	}
	return m.rt.RoundTrip(r)
}

// dialer returns a net.Dialer with the IP guard unless host is allowlisted.
func (c *Client) dialer(host string) *net.Dialer {
	d := &net.Dialer{Timeout: c.opts.Timeout}
	if !c.IsAllowedPrivate(host) {
		d.Control = guardControl
	}
	return d
}

func (c *Client) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	return c.dialer(host).DialContext(ctx, network, addr)
}

// reserve spends one unit of the request budget and waits for the host's
// rate limiter. Over budget, it fails without any network activity.
func (c *Client) reserve(ctx context.Context, host string) error {
	if c.used.Add(1) > int64(c.opts.MaxRequests) {
		c.used.Add(-1)
		return ErrBudgetExceeded
	}
	return c.opts.Limiters.Wait(ctx, host)
}

// Get fetches rawURL with GET, following same-host redirects. GET results
// are cached for the lifetime of the client, so checks that need the same
// page (e.g. the origin root) cost one request.
func (c *Client) Get(ctx context.Context, rawURL string) (*Response, error) {
	return c.cached(ctx, rawURL, func() (*Response, error) {
		return c.do(ctx, http.MethodGet, rawURL, true, "")
	})
}

// GetWithOrigin sends GET rawURL with an Origin header (what any browser sends
// for a cross-origin request), following same-host redirects. Uncached: the
// same URL asked from another origin is a different question (CORS). Only the
// Origin header can be set this way.
func (c *Client) GetWithOrigin(ctx context.Context, rawURL, origin string) (*Response, error) {
	return c.do(ctx, http.MethodGet, rawURL, true, origin)
}

// GetNoFollow fetches rawURL with GET and does not follow redirects.
func (c *Client) GetNoFollow(ctx context.Context, rawURL string) (*Response, error) {
	return c.do(ctx, http.MethodGet, rawURL, false, "")
}

// Head sends a HEAD request, following same-host redirects.
func (c *Client) Head(ctx context.Context, rawURL string) (*Response, error) {
	return c.do(ctx, http.MethodHead, rawURL, true, "")
}

// Do sends a request with the given method. Only GET and HEAD are accepted;
// anything else returns ErrMethodNotAllowed without touching the network.
func (c *Client) Do(ctx context.Context, method, rawURL string) (*Response, error) {
	if method == http.MethodGet {
		return c.Get(ctx, rawURL)
	}
	return c.do(ctx, method, rawURL, true, "")
}

func (c *Client) cached(ctx context.Context, key string, fetch func() (*Response, error)) (*Response, error) {
	c.cacheMu.Lock()
	if e, ok := c.cache[key]; ok {
		c.cacheMu.Unlock()
		select {
		case <-e.done:
			return e.resp, e.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	e := &cacheEntry{done: make(chan struct{})}
	c.cache[key] = e
	c.cacheMu.Unlock()

	e.resp, e.err = fetch()
	if e.err != nil && ctx.Err() != nil {
		// Do not cache cancellation; a later caller may have a live context.
		c.cacheMu.Lock()
		delete(c.cache, key)
		c.cacheMu.Unlock()
	}
	close(e.done)
	return e.resp, e.err
}

func validateURL(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("probe: invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, ErrUnsupportedScheme
	}
	if u.User != nil {
		return nil, ErrCredentialsInURL
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("probe: URL has no host: %q", rawURL)
	}
	return u, nil
}

func (c *Client) do(ctx context.Context, method, rawURL string, follow bool, origin string) (*Response, error) {
	if method != http.MethodGet && method != http.MethodHead {
		return nil, ErrMethodNotAllowed
	}
	u, err := validateURL(rawURL)
	if err != nil {
		return nil, err
	}
	var hops []string
	for redirects := 0; ; redirects++ {
		resp, err := c.roundTrip(ctx, method, u, origin)
		if err != nil {
			return nil, err
		}
		resp.Redirects = hops
		if !follow || !isRedirect(resp.StatusCode) {
			return resp, nil
		}
		loc := resp.Header.Get("Location")
		if loc == "" {
			return resp, nil
		}
		next, err := u.Parse(loc)
		if err != nil || !sameHostRedirect(u, next) || next.User != nil {
			resp.RedirectRefused = true
			return resp, nil
		}
		if redirects >= c.opts.MaxRedirects {
			return nil, ErrTooManyRedirects
		}
		hops = append(hops, u.String())
		u = next
	}
}

func isRedirect(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// sameHostRedirect allows a hop only to the same hostname. The port may
// change only as part of an http→https upgrade (to the default port).
func sameHostRedirect(from, to *url.URL) bool {
	if to.Scheme != "http" && to.Scheme != "https" {
		return false
	}
	if !strings.EqualFold(from.Hostname(), to.Hostname()) {
		return false
	}
	if from.Scheme == "https" && to.Scheme == "http" {
		return false // never downgrade
	}
	if from.Scheme == to.Scheme {
		return effectivePort(from) == effectivePort(to)
	}
	// http → https upgrade: allowed to the default https port or the same port.
	return to.Port() == "" || to.Port() == "443" || to.Port() == from.Port()
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

// roundTrip sends one hop, retrying on network errors, 429 and 503.
func (c *Client) roundTrip(ctx context.Context, method string, u *url.URL, origin string) (*Response, error) {
	host := strings.ToLower(u.Hostname())
	for attempt := 0; ; attempt++ {
		if err := c.reserve(ctx, host); err != nil {
			return nil, err
		}
		resp, err := c.once(ctx, method, u, origin)
		retryable := err != nil || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable
		if !retryable || attempt >= c.opts.MaxRetries || ctx.Err() != nil ||
			errors.Is(err, ErrBlockedAddress) || errors.Is(err, ErrMethodNotAllowed) {
			return resp, err
		}
		wait := c.opts.BackoffBase << attempt
		if resp != nil {
			if ra, ok := parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()); ok {
				wait = ra
			}
		}
		if wait > c.opts.MaxRetryAfter {
			wait = c.opts.MaxRetryAfter
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}

func parseRetryAfter(v string, now time.Time) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return time.Duration(n) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		d := t.Sub(now)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}

func (c *Client) once(ctx context.Context, method string, u *url.URL, origin string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "*/*")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	res, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, c.opts.BodyCap+1))
	if err != nil && len(body) == 0 {
		return nil, err
	}
	truncated := int64(len(body)) > c.opts.BodyCap
	if truncated {
		body = body[:c.opts.BodyCap]
	}
	final := *u
	return &Response{
		URL:        &final,
		StatusCode: res.StatusCode,
		Header:     res.Header.Clone(),
		Body:       body,
		Truncated:  truncated,
	}, nil
}

// CheckHost resolves host and returns ErrBlockedAddress if ANY of its
// addresses is non-public (unless host is allowlisted), or
// ErrUnresolvableTarget if it does not resolve. It costs no HTTP request.
func (c *Client) CheckHost(ctx context.Context, host string) error {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if c.IsAllowedPrivate(host) {
		return nil
	}
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		if IsBlockedIP(ip) {
			return &BlockedError{IP: ip}
		}
		return nil
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return &BlockedError{IP: netip.MustParseAddr("127.0.0.1")}
	}
	lctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()
	addrs, err := c.opts.Resolver.LookupNetIP(lctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%w: %s", ErrUnresolvableTarget, host)
	}
	for _, a := range addrs {
		if IsBlockedIP(a) {
			return &BlockedError{IP: a}
		}
	}
	return nil
}

// LookupTXT returns the TXT records of name. It is budgeted, rate-limited
// (per name) and bounded by the request timeout like any other probe.
func (c *Client) LookupTXT(ctx context.Context, name string) ([]string, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if err := c.reserve(ctx, "dns:"+name); err != nil {
		return nil, err
	}
	lctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()
	return c.opts.Resolver.LookupTXT(lctx, name)
}
