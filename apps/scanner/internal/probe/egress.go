package probe

// Egress transport for the scanner's fixed third-party services (GitHub, OSV;
// ADR-0006). These are not scan targets: no request budget, no per-target
// rate limit and no body cap here (callers bound what they read). They still
// get the probe guard: the IP check runs on every dialled address, so a
// misconfigured or hostile base URL can never reach loopback, private or
// metadata addresses.

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"
)

// NewEgressTransport returns an http.Transport that refuses blocked
// addresses (except the exact allowPrivateHosts, used by tests and the
// validation lab), verifies certificates and never uses proxy variables.
func NewEgressTransport(dialTimeout time.Duration, allowPrivateHosts []string) *http.Transport {
	return &http.Transport{
		Proxy:                 nil, // the guard must see the real peer
		DialContext:           GuardedDialer(dialTimeout, allowPrivateHosts),
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   dialTimeout,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConns:          8,
		IdleConnTimeout:       30 * time.Second,
		ForceAttemptHTTP2:     true,
	}
}

// GuardedDialer returns a DialContext that refuses blocked addresses (the
// probe guard runs on the exact IP being connected), except for the exact
// hostnames in allowPrivateHosts.
func GuardedDialer(dialTimeout time.Duration, allowPrivateHosts []string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	allow := make(map[string]bool, len(allowPrivateHosts))
	for _, h := range allowPrivateHosts {
		allow[strings.ToLower(strings.TrimSpace(h))] = true
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		d := &net.Dialer{Timeout: dialTimeout}
		if !allow[strings.ToLower(host)] {
			d.Control = guardControl
		}
		return d.DialContext(ctx, network, addr)
	}
}
