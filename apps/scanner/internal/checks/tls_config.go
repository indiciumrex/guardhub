package checks

// tls_config: how well HTTPS is configured, beyond the certificate basics of
// tls_cert. Passive: TLS handshakes only, no HTTP request, no application data.
//   - one normal handshake (crypto/tls): negotiated version, certificate key,
//     served chain;
//   - one raw ClientHello per cipher category (insecure, 3DES and, when TLS 1.3
//     is unavailable, forward secrecy), reading only the server's first answer.
// About 4-5 connections per scan, through the probe client's guard, budget,
// rate limit and timeouts. Nothing is reported when the target has no HTTPS at
// all (tls_cert reports that). Deliberately NOT reported: missing OCSP
// stapling (Let's Encrypt ended OCSP in 2025; it is optional for CAs) and
// TLS_FALLBACK_SCSV (TLS 1.3 has built-in downgrade protection; legacy
// protocols are reported by tls_cert). See docs/checks/tls_config.md.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
)

// TLSConfig implements the tls_config check.
type TLSConfig struct {
	// Roots verifies chains (incomplete-chain detection); nil = system roots.
	Roots *x509.CertPool
	// Now is injectable for tests.
	Now func() time.Time
}

// ID implements Check.
func (TLSConfig) ID() string { return evidence.CheckTlsConfig }

const (
	minRSABits = 2048
	minECBits  = 256
)

// Run implements Check.
func (c TLSConfig) Run(ctx context.Context, t Target) ([]evidence.Finding, error) {
	host := t.Host()
	port := "443"
	if t.Origin.Scheme == "https" && t.Origin.Port() != "" {
		port = t.Origin.Port()
	}
	addr := net.JoinHostPort(host, port)

	base, err := t.Probe.InspectTLS(ctx, host, port, probe.TLSOptions{})
	if err != nil {
		if isFatal(ctx, err) {
			return nil, err
		}
		if t.Origin.Scheme == "https" && isConnectError(err) {
			return nil, fmt.Errorf("%w: %w", ErrTargetUnreachable, err)
		}
		return nil, nil // no usable HTTPS: tls_cert reports it
	}

	var out []evidence.Finding
	add := func(key string, params map[string]string, payload string) {
		out = append(out, evidence.New(c.ID(), key, params, evidence.KindTlsHandshake, addr, payload))
	}

	if base.Version < tls.VersionTLS13 {
		add("tls13_unsupported", map[string]string{},
			fmt.Sprintf("Best version negotiated when offering TLS 1.0-1.3: %s", base.VersionName()))
	}
	if kt, bits, weak := weakKey(base); weak {
		add("cert_weak_key", map[string]string{"key_type": kt, "bits": strconv.Itoa(bits)},
			fmt.Sprintf("Certificate public key: %s %d bits (minimum: RSA %d, EC %d)", kt, bits, minRSABits, minECBits))
	}
	if issuer, ok := c.chainIncomplete(base); ok {
		add("chain_incomplete", map[string]string{"issuer": issuer},
			fmt.Sprintf("The server sends %d certificate(s); the issuer of the site certificate (%s) is not among them.\nThe certificate names where to fetch it (AIA): %s",
				len(base.PeerCertificates), issuer, evidence.Truncate(base.PeerCertificates[0].IssuingCertificateURL[0], 200)))
	}

	probes := []struct {
		key    string
		suites []uint16
		label  string
	}{
		{"weak_cipher_insecure", suitesInsecure, "insecure (NULL, anonymous, export, DES, RC4)"},
		{"weak_cipher_3des", suites3DES, "3DES"},
	}
	for _, p := range probes {
		res, err := c.hello(ctx, t, host, port, p.suites)
		if err != nil {
			return out, err
		}
		if res != nil && res.Outcome == probe.HelloAccepted && offered(p.suites, res.CipherSuite) {
			add(p.key, map[string]string{"suite": suiteName(res.CipherSuite)}, helloPayload(p.label, res))
		}
	}

	// Forward secrecy matters only when the server cannot give it to everyone:
	// every TLS 1.3 session has it.
	if base.Version < tls.VersionTLS13 {
		fs, err := c.hello(ctx, t, host, port, suitesForwardSecret)
		if err != nil {
			return out, err
		}
		if fs != nil && fs.Outcome == probe.HelloRejected {
			rsaKx, err := c.hello(ctx, t, host, port, suitesStaticRSA)
			if err != nil {
				return out, err
			}
			if rsaKx != nil && rsaKx.Outcome == probe.HelloAccepted && offered(suitesStaticRSA, rsaKx.CipherSuite) {
				add("no_forward_secrecy", map[string]string{"suite": suiteName(rsaKx.CipherSuite)},
					"Offered only (EC)DHE suites: refused.\n"+helloPayload("static RSA key exchange", rsaKx))
			}
		}
	}
	return out, nil
}

// hello sends one raw ClientHello. A non-fatal failure (timeout, odd answer)
// returns (nil, nil): that probe is skipped, never guessed.
func (c TLSConfig) hello(ctx context.Context, t Target, host, port string, suites []uint16) (*probe.HelloResult, error) {
	res, err := t.Probe.RawTLSHello(ctx, host, port, buildClientHello(host, suites))
	if err != nil {
		if isFatal(ctx, err) {
			return nil, err
		}
		return nil, nil
	}
	return res, nil
}

func helloPayload(label string, res *probe.HelloResult) string {
	return fmt.Sprintf("Offered only %s cipher suites.\nServer accepted: %s (%s)", label, suiteName(res.CipherSuite), tls.VersionName(res.Version))
}

func weakKey(res *probe.TLSResult) (string, int, bool) {
	if len(res.PeerCertificates) == 0 {
		return "", 0, false
	}
	switch k := res.PeerCertificates[0].PublicKey.(type) {
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		return "RSA", bits, bits < minRSABits
	case *ecdsa.PublicKey:
		bits := k.Curve.Params().BitSize
		return "EC", bits, bits < minECBits
	}
	return "", 0, false
}

// chainIncomplete: the chain does not verify, the site certificate is not
// self-signed, its issuer is not among the served certificates, and it names
// where its issuer can be fetched (AIA, as every public CA's intermediates
// do). That is "the intermediate is not served", not "a private CA".
func (c TLSConfig) chainIncomplete(res *probe.TLSResult) (string, bool) {
	if len(res.PeerCertificates) == 0 {
		return "", false
	}
	leaf := res.PeerCertificates[0]
	if bytes.Equal(leaf.RawIssuer, leaf.RawSubject) || len(leaf.IssuingCertificateURL) == 0 {
		return "", false
	}
	inter := x509.NewCertPool()
	for _, ic := range res.PeerCertificates[1:] {
		if bytes.Equal(ic.RawSubject, leaf.RawIssuer) {
			return "", false // issuer served: any problem is elsewhere (tls_cert)
		}
		inter.AddCert(ic)
	}
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	at := now // judge trust inside the leaf's validity (expiry is tls_cert's finding)
	if now.After(leaf.NotAfter) || now.Before(leaf.NotBefore) {
		at = leaf.NotAfter.Add(-time.Second)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: c.Roots, Intermediates: inter, CurrentTime: at,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		return "", false
	}
	return evidence.Truncate(leaf.Issuer.String(), 200), true
}

var suiteNames = map[uint16]string{
	0x0001: "TLS_RSA_WITH_NULL_MD5", 0x0002: "TLS_RSA_WITH_NULL_SHA", 0x003B: "TLS_RSA_WITH_NULL_SHA256",
	0xC006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA", 0xC010: "TLS_ECDHE_RSA_WITH_NULL_SHA", 0xC015: "TLS_ECDH_anon_WITH_NULL_SHA",
	0x0018: "TLS_DH_anon_WITH_RC4_128_MD5", 0x001B: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
	0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA", 0x003A: "TLS_DH_anon_WITH_AES_256_CBC_SHA",
	0x006C: "TLS_DH_anon_WITH_AES_128_CBC_SHA256", 0x006D: "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
	0x00A6: "TLS_DH_anon_WITH_AES_128_GCM_SHA256", 0x00A7: "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
	0xC016: "TLS_ECDH_anon_WITH_RC4_128_SHA", 0xC017: "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
	0xC018: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", 0xC019: "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
	0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5", 0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
	0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", 0x000B: "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
	0x000E: "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", 0x0011: "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
	0x0014: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", 0x0017: "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
	0x0019: "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
	0x0009: "TLS_RSA_WITH_DES_CBC_SHA", 0x000C: "TLS_DH_DSS_WITH_DES_CBC_SHA", 0x000F: "TLS_DH_RSA_WITH_DES_CBC_SHA",
	0x0012: "TLS_DHE_DSS_WITH_DES_CBC_SHA", 0x0015: "TLS_DHE_RSA_WITH_DES_CBC_SHA", 0x001A: "TLS_DH_anon_WITH_DES_CBC_SHA",
	0x0004: "TLS_RSA_WITH_RC4_128_MD5", 0x0005: "TLS_RSA_WITH_RC4_128_SHA", 0xC002: "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
	0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", 0xC00C: "TLS_ECDH_RSA_WITH_RC4_128_SHA", 0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x000D: "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
	0x0010: "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", 0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
	0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", 0xC003: "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
	0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", 0xC00D: "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
	0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256", 0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
	0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA", 0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
}

func suiteName(id uint16) string {
	if n, ok := suiteNames[id]; ok {
		return n
	}
	if n := tls.CipherSuiteName(id); n != "" {
		return n
	}
	return fmt.Sprintf("0x%04X", id)
}
