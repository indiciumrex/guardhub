package checks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// depthCert is a leaf under ca for 127.0.0.1, valid 90 days around tlsNow,
// with an embedded SCT list, then changed by mutate.
func depthCert(t *testing.T, ca testCA, mutate func(*x509.Certificate)) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sct, _ := asn1.Marshal([]byte{0, 0}) // an (empty) SCT list: presence is what is checked
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(time.Now().UnixNano()),
		Subject:         pkix.Name{CommonName: "depth leaf"},
		NotBefore:       tlsNow.AddDate(0, 0, -10),
		NotAfter:        tlsNow.AddDate(0, 0, 80),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:     loopback,
		ExtraExtensions: []pkix.Extension{{Id: oidSCTList, Value: sct}},
	}
	if mutate != nil {
		mutate(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func depthServer(t *testing.T, cert tls.Certificate, sts string) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if sts != "" {
			w.Header().Set("Strict-Transport-Security", sts)
		}
		_, _ = io.WriteString(w, "<!doctype html><title>ok</title>")
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL
}

func depthCheck(ca testCA) TLSDepth {
	return TLSDepth{Now: func() time.Time { return tlsNow }, Roots: ca.pool}
}

func noSCT(c *x509.Certificate) { c.ExtraExtensions = nil }

func TestTLSDepthHealthy(t *testing.T) {
	ca := newTestCA(t)
	u := depthServer(t, depthCert(t, ca, nil), "max-age=63072000; includeSubDomains; preload")
	requireKeys(t, run(t, depthCheck(ca), u))
}

func TestTLSDepthNoSCT(t *testing.T) {
	ca := newTestCA(t)
	u := depthServer(t, depthCert(t, ca, noSCT), "")
	requireKeys(t, run(t, depthCheck(ca), u), "cert_no_sct")
}

func TestTLSDepthSCTInTLSExtension(t *testing.T) {
	ca := newTestCA(t)
	cert := depthCert(t, ca, noSCT)
	cert.SignedCertificateTimestamps = [][]byte{{0, 1, 2, 3}}
	requireKeys(t, run(t, depthCheck(ca), depthServer(t, cert, "")))
}

func TestTLSDepthUntrustedChainSkipsTrustProperties(t *testing.T) {
	ca, other := newTestCA(t), newTestCA(t)
	cert := depthCert(t, ca, func(c *x509.Certificate) {
		noSCT(c)
		c.NotAfter = tlsNow.AddDate(3, 0, 0)
		c.OCSPServer = []string{"http://ocsp.example/"}
	})
	requireKeys(t, run(t, depthCheck(other), depthServer(t, cert, "")))
}

func TestTLSDepthLifetime(t *testing.T) {
	ca := newTestCA(t)
	long := depthCert(t, ca, func(c *x509.Certificate) { c.NotAfter = c.NotBefore.AddDate(2, 0, 0) })
	fs := run(t, depthCheck(ca), depthServer(t, long, ""))
	requireKeys(t, fs, "cert_lifetime_too_long")
	if d := findKey(t, fs, "cert_lifetime_too_long").Params["days"]; d != "731" { // includes 2028-02-29
		t.Fatalf("days = %s", d)
	}
	// issued before the 398-day rule: allowed
	old := depthCert(t, ca, func(c *x509.Certificate) {
		c.NotBefore = time.Date(2020, 8, 1, 0, 0, 0, 0, time.UTC)
		c.NotAfter = tlsNow.AddDate(0, 1, 0)
	})
	requireKeys(t, run(t, depthCheck(ca), depthServer(t, old, "")))
	// exactly 398 days: allowed
	edge := depthCert(t, ca, func(c *x509.Certificate) { c.NotAfter = c.NotBefore.AddDate(0, 0, 398) })
	requireKeys(t, run(t, depthCheck(ca), depthServer(t, edge, "")))
}

func TestTLSDepthWeakSignature(t *testing.T) {
	ca := newTestCA(t)
	cert := depthCert(t, ca, func(c *x509.Certificate) { c.SignatureAlgorithm = x509.ECDSAWithSHA1 })
	fs := run(t, depthCheck(ca), depthServer(t, cert, ""))
	// Go itself rejects SHA-1 chains, so the trust-based checks stay silent (tls_cert reports cert_untrusted).
	requireKeys(t, fs, "cert_weak_signature")
	f := findKey(t, fs, "cert_weak_signature")
	if f.Params["algorithm"] != "ECDSA-SHA1" || f.Params["subject"] != "depth leaf" {
		t.Fatalf("params = %v", f.Params)
	}
}

func TestTLSDepthOCSPStapling(t *testing.T) {
	ca := newTestCA(t)
	withURL := func(c *x509.Certificate) { c.OCSPServer = []string{"http://ocsp.example/"} }
	requireKeys(t, run(t, depthCheck(ca), depthServer(t, depthCert(t, ca, withURL), "")), "ocsp_stapling_missing")

	stapled := depthCert(t, ca, withURL)
	stapled.OCSPStaple = []byte{0x30, 0x03, 0x0a, 0x01, 0x00}
	requireKeys(t, run(t, depthCheck(ca), depthServer(t, stapled, "")))
}

func TestTLSDepthHSTSPreload(t *testing.T) {
	ca := newTestCA(t)
	for _, tc := range []struct {
		sts, reason string
	}{
		{"max-age=31536000; includeSubDomains; preload", ""},
		{"max-age=20000000; includeSubDomains; preload", "max_age"},
		{"max-age=31536000; preload", "include_subdomains"},
		{"max-age=20000000; Preload", "max_age_and_include_subdomains"},
		{"max-age=8640000; includeSubDomains; preload", ""}, // under 180 days: security_headers' hsts_weak
		{"max-age=100; includeSubDomains", ""},              // no preload requested
		{"max-age=31536000; preloaded", ""},                 // not the preload token
	} {
		fs := run(t, depthCheck(ca), depthServer(t, depthCert(t, ca, nil), tc.sts))
		if tc.reason == "" {
			requireKeys(t, fs)
			continue
		}
		requireKeys(t, fs, "hsts_preload_ineligible")
		if r := findKey(t, fs, "hsts_preload_ineligible").Params["reason"]; r != tc.reason {
			t.Errorf("%q: reason %q, want %q", tc.sts, r, tc.reason)
		}
	}
}
