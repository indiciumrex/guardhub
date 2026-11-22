package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
)

// TLSResult is what a TLS handshake revealed. The certificate chain is NOT
// verified here; checks verify it themselves with an injectable clock.
type TLSResult struct {
	Address          string
	Version          uint16
	CipherSuite      uint16
	PeerCertificates []*x509.Certificate
	// OCSPResponse is the stapled OCSP response (nil when none was stapled).
	OCSPResponse []byte
	// SCTs are Signed Certificate Timestamps sent in the TLS extension (SCTs
	// embedded in the certificate are in PeerCertificates[0]'s extensions).
	SCTs [][]byte
}

// VersionName returns e.g. "TLS 1.2".
func (r *TLSResult) VersionName() string { return tls.VersionName(r.Version) }

// TLSOptions bounds the protocol versions offered in the handshake.
type TLSOptions struct {
	MinVersion uint16 // default TLS 1.0, so legacy-only servers are still inspected
	MaxVersion uint16 // default TLS 1.3
}

// allCipherSuites offers every suite Go implements (including legacy ones)
// so the handshake succeeds against old servers we want to report on. The
// connection carries no data, so weak suites cannot leak anything.
func allCipherSuites() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		ids = append(ids, s.ID)
	}
	return ids
}

// InspectTLS performs a TLS handshake only (no HTTP request) with host:port
// and returns the negotiated version and peer certificates. It goes through
// the same IP guard, budget, rate limit and timeout as HTTP probes.
func (c *Client) InspectTLS(ctx context.Context, host, port string, o TLSOptions) (*TLSResult, error) {
	host = strings.ToLower(host)
	if o.MinVersion == 0 {
		o.MinVersion = tls.VersionTLS10
	}
	if o.MaxVersion == 0 {
		o.MaxVersion = tls.VersionTLS13
	}
	if err := c.reserve(ctx, host); err != nil {
		return nil, err
	}
	hctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()

	addr := net.JoinHostPort(host, port)
	raw, err := c.dialer(host).DialContext(hctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer raw.Close()

	cfg := &tls.Config{
		// Verification is done by the caller (with its own clock and roots),
		// because we need the chain even when it is invalid.
		InsecureSkipVerify: true, //nolint:gosec // inspection only, see comment
		MinVersion:         o.MinVersion,
		MaxVersion:         o.MaxVersion,
		CipherSuites:       allCipherSuites(),
	}
	if net.ParseIP(host) == nil {
		cfg.ServerName = host
	}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(hctx); err != nil {
		return nil, err
	}
	st := conn.ConnectionState()
	_ = conn.Close()
	return &TLSResult{
		Address:          addr,
		Version:          st.Version,
		CipherSuite:      st.CipherSuite,
		PeerCertificates: st.PeerCertificates,
		OCSPResponse:     st.OCSPResponse,
		SCTs:             st.SignedCertificateTimestamps,
	}, nil
}
