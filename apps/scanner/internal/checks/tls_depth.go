package checks

// tls_depth (ADR-0007): certificate and HTTPS-policy properties beyond
// tls_cert/tls_config. One TLS handshake (the client asks for a stapled OCSP
// response and for SCTs, as browsers do) plus one GET of the HTTPS root for
// the HSTS preload test.
//
//   - cert_weak_signature: a served certificate other than a self-signed root
//     is signed with SHA-1 or MD5. Browsers reject such chains.
//   - cert_lifetime_too_long: a trusted leaf issued after 2020-09-01 valid for
//     more than 398 days (CA/Browser Forum limit; Apple and Chrome reject it).
//   - cert_no_sct: a trusted leaf carries no Signed Certificate Timestamp
//     (neither embedded nor in the TLS extension). Chrome and Safari require
//     Certificate Transparency for publicly trusted certificates. Presence
//     only: log signatures are not verified (docs/checks/tls_depth.md).
//   - ocsp_stapling_missing: a trusted leaf names an OCSP responder but the
//     server staples no response (info: browsers soft-fail).
//   - hsts_preload_ineligible: HSTS asks for preloading ("preload") but does
//     not meet the preload list's requirements. A max-age under 180 days is
//     already security_headers' hsts_weak and is not repeated here.
//
// "Trusted" = the served chain verifies against the roots (system roots in
// production): an untrusted chain is tls_cert's finding, and the properties
// above only matter for publicly trusted certificates.

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
)

const (
	// maxCertLifetimeDays: CA/Browser Forum Baseline Requirements 6.3.2 (since 2020-09-01).
	maxCertLifetimeDays = 398
	// hstsPreloadMaxAge: hstspreload.org requires max-age of at least one year.
	hstsPreloadMaxAge = 31536000
)

var (
	// lifetimeLimitSince: certificates issued before this date may legally be longer-lived.
	lifetimeLimitSince = time.Date(2020, 9, 1, 0, 0, 0, 0, time.UTC)
	// oidSCTList: RFC 6962 embedded SCT list extension.
	oidSCTList           = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	preloadTokenRe       = regexp.MustCompile(`(?i)(?:^|;)\s*preload\s*(?:;|$)`)
	includeSubdomainsRe  = regexp.MustCompile(`(?i)(?:^|;)\s*includesubdomains\s*(?:;|$)`)
	weakSignatureAlgoSet = map[x509.SignatureAlgorithm]string{
		x509.MD2WithRSA:    "MD2-RSA",
		x509.MD5WithRSA:    "MD5-RSA",
		x509.SHA1WithRSA:   "SHA1-RSA",
		x509.DSAWithSHA1:   "DSA-SHA1",
		x509.ECDSAWithSHA1: "ECDSA-SHA1",
	}
)

// TLSDepth implements the tls_depth check.
type TLSDepth struct {
	// Now returns the current time (time.Now in production).
	Now func() time.Time
	// Roots verifies chains; nil means the system roots.
	Roots *x509.CertPool
	// HTTPSPort is used when the target is http:// (default "443").
	HTTPSPort string
}

// ID implements Check.
func (TLSDepth) ID() string { return evidence.CheckTlsDepth }

func (c TLSDepth) now() time.Time {
	if c.Now == nil {
		return time.Now()
	}
	return c.Now()
}

// Run implements Check.
func (c TLSDepth) Run(ctx context.Context, t Target) ([]evidence.Finding, error) {
	host := t.Host()
	httpsPort, _ := TLSCert{HTTPSPort: c.HTTPSPort}.endpoints(t)
	addr := net.JoinHostPort(host, httpsPort)
	res, err := t.Probe.InspectTLS(ctx, host, httpsPort, probe.TLSOptions{})
	if err != nil {
		if isFatal(ctx, err) {
			return nil, err
		}
		return nil, nil // no HTTPS at all is tls_cert's https_unavailable
	}
	if len(res.PeerCertificates) == 0 {
		return nil, nil
	}
	var out []evidence.Finding
	add := func(key string, params map[string]string, payload string) {
		out = append(out, evidence.New(c.ID(), key, params, evidence.KindTlsHandshake, addr, payload))
	}

	// 1. weak signatures anywhere in the served chain (a self-signed root's own
	// signature is never checked by clients, so it does not count).
	for _, cert := range res.PeerCertificates {
		algo, weak := weakSignatureAlgoSet[cert.SignatureAlgorithm]
		if !weak || selfSigned(cert) {
			continue
		}
		subject := cert.Subject.CommonName
		if subject == "" {
			subject = cert.Subject.String()
		}
		add("cert_weak_signature", map[string]string{"algorithm": algo, "subject": evidence.Truncate(subject, 200)},
			fmt.Sprintf("Subject: %s\nIssuer: %s\nSignature algorithm: %s",
				cert.Subject.String(), cert.Issuer.String(), cert.SignatureAlgorithm.String()))
		break // one finding per chain: the fix (reissue) is the same
	}

	leaf := res.PeerCertificates[0]
	if c.trusted(host, res) {
		days := int(leaf.NotAfter.Sub(leaf.NotBefore).Hours() / 24)
		if !leaf.NotBefore.Before(lifetimeLimitSince) && days > maxCertLifetimeDays {
			add("cert_lifetime_too_long", map[string]string{"days": strconv.Itoa(days)}, certPayload(res))
		}
		if len(res.SCTs) == 0 && !hasExtension(leaf, oidSCTList) {
			add("cert_no_sct", map[string]string{}, certPayload(res)+
				"\nSigned Certificate Timestamps: none (no certificate extension, no TLS extension)")
		}
		if len(leaf.OCSPServer) > 0 && len(res.OCSPResponse) == 0 {
			add("ocsp_stapling_missing", map[string]string{}, certPayload(res)+
				"\nOCSP responder: "+evidence.Truncate(strings.Join(leaf.OCSPServer, ", "), 300)+
				"\nStapled OCSP response: none")
		}
	}

	f, err := c.preload(ctx, t, host, httpsPort)
	if err != nil {
		return out, err
	}
	if f != nil {
		out = append(out, *f)
	}
	return out, nil
}

// trusted reports whether the served chain verifies for host at c.now().
func (c TLSDepth) trusted(host string, res *probe.TLSResult) bool {
	inter := x509.NewCertPool()
	for _, cert := range res.PeerCertificates[1:] {
		inter.AddCert(cert)
	}
	_, err := res.PeerCertificates[0].Verify(x509.VerifyOptions{
		DNSName: host, Roots: c.Roots, Intermediates: inter, CurrentTime: c.now(),
	})
	return err == nil
}

// preload fetches the HTTPS root once and checks the HSTS preload requirements.
func (c TLSDepth) preload(ctx context.Context, t Target, host, httpsPort string) (*evidence.Finding, error) {
	hostPort := host
	if strings.Contains(hostPort, ":") {
		hostPort = "[" + hostPort + "]"
	}
	if httpsPort != "443" {
		hostPort += ":" + httpsPort
	}
	u := "https://" + hostPort + "/"
	resp, err := t.Probe.Get(ctx, u)
	if err != nil {
		if isFatal(ctx, err) {
			return nil, err
		}
		return nil, nil
	}
	sts := resp.Header.Get("Strict-Transport-Security")
	if !preloadTokenRe.MatchString(sts) {
		return nil, nil
	}
	age := -1
	if m := maxAgeRe.FindStringSubmatch(sts); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			age = n
		}
	}
	if age < hstsMinMaxAge {
		return nil, nil // security_headers reports hsts_weak
	}
	short, noSub := age < hstsPreloadMaxAge, !includeSubdomainsRe.MatchString(sts)
	var reason string
	switch {
	case short && noSub:
		reason = "max_age_and_include_subdomains"
	case short:
		reason = "max_age"
	case noSub:
		reason = "include_subdomains"
	default:
		return nil, nil
	}
	f := evidence.New(c.ID(), "hsts_preload_ineligible", map[string]string{"reason": reason},
		evidence.KindHttpHeader, resp.URL.String(), headerPayload(resp, "Strict-Transport-Security"))
	return &f, nil
}

// selfSigned: issuer = subject. (CheckSignatureFrom would reject the SHA-1
// roots this is meant to skip.)
func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawSubject, c.RawIssuer)
}

func hasExtension(c *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, e := range c.Extensions {
		if e.Id.Equal(oid) {
			return true
		}
	}
	return false
}
