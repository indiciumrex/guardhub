package checks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

var tlsNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "GuardHub Test CA"},
		NotBefore:             tlsNow.AddDate(-5, 0, 0),
		NotAfter:              tlsNow.AddDate(5, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return testCA{cert: cert, key: key, pool: pool}
}

func (ca testCA) leaf(t *testing.T, notBefore, notAfter time.Time, dns []string, ips []net.IP) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "test leaf"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func tlsServer(t *testing.T, cert tls.Certificate, minV, maxV uint16) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: minV, MaxVersion: maxV}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // refused legacy handshakes are expected
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// closedPort returns a local port with nothing listening.
func closedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(l.Addr().String())
	_ = l.Close()
	return port
}

func portOf(rawURL string) string {
	u, _ := url.Parse(rawURL)
	return u.Port()
}

var loopback = []net.IP{net.ParseIP("127.0.0.1")}

func tlsCheck(ca testCA, httpPort string) TLSCert {
	return TLSCert{Now: func() time.Time { return tlsNow }, Roots: ca.pool, HTTPSPort: "443", HTTPPort: httpPort}
}

func TestTLSCertHealthy(t *testing.T) {
	ca := newTestCA(t)
	srv := tlsServer(t, ca.leaf(t, tlsNow.AddDate(0, -1, 0), tlsNow.AddDate(1, 0, 0), nil, loopback), tls.VersionTLS12, 0)
	requireKeys(t, run(t, tlsCheck(ca, closedPort(t)), srv.URL))
}

func TestTLSCertExpired(t *testing.T) {
	ca := newTestCA(t)
	srv := tlsServer(t, ca.leaf(t, tlsNow.AddDate(-1, 0, 0), time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC), nil, loopback), tls.VersionTLS12, 0)
	fs := run(t, tlsCheck(ca, closedPort(t)), srv.URL)
	requireKeys(t, fs, "cert_expired")
	if f := fs[0]; f.Params["expired_on"] != "2026-05-20" || f.Evidence.Kind != "tls_handshake" {
		t.Fatalf("finding %+v", f)
	}
}

func TestTLSCertExpiringSoon(t *testing.T) {
	ca := newTestCA(t)
	srv := tlsServer(t, ca.leaf(t, tlsNow.AddDate(0, -2, 0), tlsNow.Add(10*24*time.Hour+time.Hour), nil, loopback), tls.VersionTLS12, 0)
	fs := run(t, tlsCheck(ca, closedPort(t)), srv.URL)
	requireKeys(t, fs, "cert_expiring_soon")
	if p := fs[0].Params; p["days_left"] != "10" || p["expires_on"] != "2026-06-11" {
		t.Fatalf("params %v", p)
	}
	// 31 days left: not reported.
	srv2 := tlsServer(t, ca.leaf(t, tlsNow.AddDate(0, -2, 0), tlsNow.Add(31*24*time.Hour), nil, loopback), tls.VersionTLS12, 0)
	requireKeys(t, run(t, tlsCheck(ca, closedPort(t)), srv2.URL))
}

func TestTLSCertHostnameMismatch(t *testing.T) {
	ca := newTestCA(t)
	srv := tlsServer(t, ca.leaf(t, tlsNow.AddDate(0, -1, 0), tlsNow.AddDate(1, 0, 0), []string{"other.example"}, nil), tls.VersionTLS12, 0)
	fs := run(t, tlsCheck(ca, closedPort(t)), srv.URL)
	requireKeys(t, fs, "cert_hostname_mismatch")
	if fs[0].Params["host"] != "127.0.0.1" {
		t.Fatalf("params %v", fs[0].Params)
	}
}

func TestTLSCertUntrusted(t *testing.T) {
	ca := newTestCA(t)
	other := newTestCA(t)
	srv := tlsServer(t, ca.leaf(t, tlsNow.AddDate(0, -1, 0), tlsNow.AddDate(1, 0, 0), nil, loopback), tls.VersionTLS12, 0)
	requireKeys(t, run(t, tlsCheck(other, closedPort(t)), srv.URL), "cert_untrusted")
}

func TestTLSCertLegacyProtocol(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.leaf(t, tlsNow.AddDate(0, -1, 0), tlsNow.AddDate(1, 0, 0), nil, loopback)

	legacyOnly := tlsServer(t, cert, tls.VersionTLS10, tls.VersionTLS11)
	fs := run(t, tlsCheck(ca, closedPort(t)), legacyOnly.URL)
	requireKeys(t, fs, "legacy_tls_supported")
	if fs[0].Params["version"] != "TLS 1.1" {
		t.Fatalf("version %v", fs[0].Params)
	}

	// Modern server that still accepts TLS 1.0 alongside 1.3.
	mixed := tlsServer(t, cert, tls.VersionTLS10, 0)
	fs = run(t, tlsCheck(ca, closedPort(t)), mixed.URL)
	requireKeys(t, fs, "legacy_tls_supported")
}

func TestTLSHTTPRedirect(t *testing.T) {
	ca := newTestCA(t)
	srv := tlsServer(t, ca.leaf(t, tlsNow.AddDate(0, -1, 0), tlsNow.AddDate(1, 0, 0), nil, loopback), tls.VersionTLS12, 0)

	plain := site(t, false, map[string]http.HandlerFunc{"/": html("<title>plain http</title>")})
	fs := run(t, tlsCheck(ca, portOf(plain.URL)), srv.URL)
	requireKeys(t, fs, "http_not_redirected")
	if loc := fs[0].Evidence.Location; loc != "http://127.0.0.1:"+portOf(plain.URL)+"/" {
		t.Fatalf("location %s", loc)
	}

	redirecting := site(t, false, map[string]http.HandlerFunc{"/": func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://www.example.com/", http.StatusMovedPermanently)
	}})
	requireKeys(t, run(t, tlsCheck(ca, portOf(redirecting.URL)), srv.URL))
}

func TestTLSHTTPTarget(t *testing.T) {
	ca := newTestCA(t)
	plain := site(t, false, map[string]http.HandlerFunc{"/": html("<title>plain http</title>")})

	// No HTTPS on the host at all.
	c := tlsCheck(ca, "")
	c.HTTPSPort = closedPort(t)
	fs := run(t, c, plain.URL)
	requireKeys(t, fs, "https_unavailable")
	if fs[0].Evidence.Location != "127.0.0.1:"+c.HTTPSPort {
		t.Fatalf("location %s", fs[0].Evidence.Location)
	}

	// HTTPS exists, and the http target redirects to it: clean.
	secure := tlsServer(t, ca.leaf(t, tlsNow.AddDate(0, -1, 0), tlsNow.AddDate(1, 0, 0), nil, loopback), tls.VersionTLS12, 0)
	redirecting := site(t, false, map[string]http.HandlerFunc{"/": func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, secure.URL+"/", http.StatusMovedPermanently)
	}})
	c.HTTPSPort = portOf(secure.URL)
	requireKeys(t, run(t, c, redirecting.URL))
}

func TestTLSUnreachableHTTPSTarget(t *testing.T) {
	ca := newTestCA(t)
	tg := targetFor(t, "https://127.0.0.1:"+closedPort(t))
	_, err := tlsCheck(ca, closedPort(t)).Run(context.Background(), tg)
	if !errors.Is(err, ErrTargetUnreachable) {
		t.Fatalf("expected unreachable, got %v", err)
	}
}
