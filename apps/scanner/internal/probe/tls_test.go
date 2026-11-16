package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestInspectTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	c := New(testOptions())
	res, err := c.InspectTLS(context.Background(), u.Hostname(), u.Port(), TLSOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Version < tls.VersionTLS12 || len(res.PeerCertificates) == 0 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if c.RequestsUsed() != 1 {
		t.Fatalf("handshake should cost 1 budget unit, used %d", c.RequestsUsed())
	}

	// Capped at TLS 1.1 against a modern server: handshake must fail.
	if _, err := c.InspectTLS(context.Background(), u.Hostname(), u.Port(), TLSOptions{MaxVersion: tls.VersionTLS11}); err == nil {
		t.Fatal("legacy handshake against a TLS1.2+ server should fail")
	}

	// The IP guard applies to TLS inspection too.
	opts := testOptions()
	opts.AllowPrivateHosts = nil
	blocked := New(opts)
	if _, err := blocked.InspectTLS(context.Background(), u.Hostname(), u.Port(), TLSOptions{}); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("expected blocked, got %v", err)
	}
}

func TestInspectTLSLegacyServer(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}
	srv.StartTLS()
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	c := New(testOptions())
	res, err := c.InspectTLS(context.Background(), u.Hostname(), u.Port(), TLSOptions{MaxVersion: tls.VersionTLS11})
	if err != nil {
		t.Fatal(err)
	}
	if res.VersionName() != "TLS 1.1" {
		t.Fatalf("got %s", res.VersionName())
	}
}
