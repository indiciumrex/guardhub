package checks

// tls_cert: HTTPS availability, HTTP→HTTPS redirect, certificate validity
// (expiry, hostname, trust) and legacy protocol support. Certificate data
// comes from bare TLS handshakes (no HTTP request); the redirect test is one
// GET of http://host/ without following redirects.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
)

// expiringSoonWindow: certificates expiring within this window are reported.
const expiringSoonWindow = 30 * 24 * time.Hour

// TLSCert implements the tls_cert check. Now, Roots and the ports are
// injectable for deterministic tests; NewTLSCert gives production values.
type TLSCert struct {
	// Now returns the current time (time.Now in production).
	Now func() time.Time
	// Roots verifies chains; nil means the system roots.
	Roots *x509.CertPool
	// HTTPSPort is used when the target is http:// (default "443").
	HTTPSPort string
	// HTTPPort is used for the redirect test when the target is https:// (default "80").
	HTTPPort string
}

// NewTLSCert returns the production check.
func NewTLSCert() TLSCert {
	return TLSCert{Now: time.Now, HTTPSPort: "443", HTTPPort: "80"}
}

// ID implements Check.
func (TLSCert) ID() string { return evidence.CheckTlsCert }

func (c TLSCert) now() time.Time {
	if c.Now == nil {
		return time.Now()
	}
	return c.Now()
}

// Run implements Check.
func (c TLSCert) Run(ctx context.Context, t Target) ([]evidence.Finding, error) {
	host := t.Host()
	httpsPort, httpURL := c.endpoints(t)
	httpsAddr := net.JoinHostPort(host, httpsPort)

	var out []evidence.Finding
	res, err := t.Probe.InspectTLS(ctx, host, httpsPort, probe.TLSOptions{})
	if err != nil {
		if isFatal(ctx, err) {
			return nil, err
		}
		if t.Origin.Scheme == "https" && isConnectError(err) {
			// The target itself cannot be reached at all; that is not a TLS finding.
			return nil, fmt.Errorf("%w: %w", ErrTargetUnreachable, err)
		}
		out = append(out, evidence.New(c.ID(), "https_unavailable", map[string]string{},
			evidence.KindTlsHandshake, httpsAddr, "TLS handshake with "+httpsAddr+" failed: "+evidence.Truncate(err.Error(), 300)))
		return out, nil
	}

	out = append(out, c.certFindings(host, res)...)

	if res.Version < tls.VersionTLS12 {
		out = append(out, c.legacyFinding(res))
	} else {
		legacy, err := t.Probe.InspectTLS(ctx, host, httpsPort, probe.TLSOptions{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11})
		if err != nil && isFatal(ctx, err) {
			return out, err
		}
		if err == nil {
			out = append(out, c.legacyFinding(legacy))
		}
	}

	resp, err := t.Probe.GetNoFollow(ctx, httpURL)
	if err != nil {
		if isFatal(ctx, err) {
			return out, err
		}
		return out, nil // nothing listens on plain HTTP: nothing to redirect
	}
	if !redirectsToHTTPS(resp, httpURL) {
		out = append(out, evidence.New(c.ID(), "http_not_redirected", map[string]string{},
			evidence.KindHttpResponse, httpURL, headerPayload(resp, "Location", "Content-Type")))
	}
	return out, nil
}

// endpoints returns the HTTPS port to inspect and the plain-HTTP URL used
// for the redirect test.
func (c TLSCert) endpoints(t Target) (httpsPort, httpURL string) {
	httpsPort, httpPort := c.HTTPSPort, c.HTTPPort
	if httpsPort == "" {
		httpsPort = "443"
	}
	if httpPort == "" {
		httpPort = "80"
	}
	if t.Origin.Scheme == "https" {
		if p := t.Origin.Port(); p != "" {
			httpsPort = p
		}
	} else if p := t.Origin.Port(); p != "" {
		httpPort = p
	}
	hostPort := t.Host()
	if strings.Contains(hostPort, ":") {
		hostPort = "[" + hostPort + "]"
	}
	if httpPort != "80" {
		hostPort += ":" + httpPort
	}
	return httpsPort, "http://" + hostPort + "/"
}

func isConnectError(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "dial"
}

// redirectsToHTTPS: a 3xx whose Location is an https URL (any host, e.g. the
// www. variant, is acceptable for this purpose).
func redirectsToHTTPS(resp *probe.Response, from string) bool {
	if resp.StatusCode < 300 || resp.StatusCode > 399 {
		return false
	}
	base, err := url.Parse(from)
	if err != nil {
		return false
	}
	loc, err := base.Parse(resp.Header.Get("Location"))
	return err == nil && loc.Scheme == "https"
}

func (c TLSCert) certFindings(host string, res *probe.TLSResult) []evidence.Finding {
	if len(res.PeerCertificates) == 0 {
		return nil
	}
	leaf := res.PeerCertificates[0]
	now := c.now()
	payload := certPayload(res)
	var out []evidence.Finding
	add := func(key string, params map[string]string) {
		out = append(out, evidence.New(c.ID(), key, params, evidence.KindTlsHandshake, res.Address, payload))
	}

	expired := now.After(leaf.NotAfter)
	if expired {
		add("cert_expired", map[string]string{"expired_on": leaf.NotAfter.UTC().Format("2006-01-02")})
	} else if left := leaf.NotAfter.Sub(now); left <= expiringSoonWindow {
		add("cert_expiring_soon", map[string]string{
			"days_left":  strconv.Itoa(int(left / (24 * time.Hour))),
			"expires_on": leaf.NotAfter.UTC().Format("2006-01-02"),
		})
	}

	if err := leaf.VerifyHostname(host); err != nil {
		add("cert_hostname_mismatch", map[string]string{"host": host})
	}

	// Trust is checked separately from expiry and hostname so each problem is
	// reported once: verify at a moment inside the leaf's validity window.
	at := now
	if expired || now.Before(leaf.NotBefore) {
		at = leaf.NotAfter.Add(-time.Second)
	}
	inter := x509.NewCertPool()
	for _, ic := range res.PeerCertificates[1:] {
		inter.AddCert(ic)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         c.Roots,
		Intermediates: inter,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		add("cert_untrusted", map[string]string{})
	}
	return out
}

func (c TLSCert) legacyFinding(res *probe.TLSResult) evidence.Finding {
	return evidence.New(c.ID(), "legacy_tls_supported", map[string]string{"version": res.VersionName()},
		evidence.KindTlsHandshake, res.Address,
		fmt.Sprintf("Handshake with %s succeeded using %s (%s)", res.Address, res.VersionName(), tls.CipherSuiteName(res.CipherSuite)))
}

func certPayload(res *probe.TLSResult) string {
	leaf := res.PeerCertificates[0]
	names := strings.Join(leaf.DNSNames, ", ")
	for _, ip := range leaf.IPAddresses {
		if names != "" {
			names += ", "
		}
		names += ip.String()
	}
	return fmt.Sprintf("Protocol: %s\nSubject: %s\nIssuer: %s\nNames: %s\nValid from: %s\nValid until: %s",
		res.VersionName(), leaf.Subject.String(), leaf.Issuer.String(), evidence.Truncate(names, 500),
		leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
}
