package checks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
)

type keyKind int

const (
	keyEC256 keyKind = iota
	keyRSA2048
	keyRSA1024
)

func selfSignedCert(t *testing.T, kind keyKind) tls.Certificate {
	t.Helper()
	var priv any
	var pub any
	switch kind {
	case keyEC256:
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		priv, pub = k, k.Public()
	case keyRSA2048, keyRSA1024:
		bits := 2048
		if kind == keyRSA1024 {
			bits = 1024
		}
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		priv, pub = k, k.Public()
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// tlsListener serves cfg, except that a ClientHello offering one of
// nullSuites gets a hand-made ServerHello choosing answerSuite (Go cannot
// serve NULL/anonymous suites). answerSuite 0 disables that branch.
func tlsListener(t *testing.T, cfg *tls.Config, nullSuites []uint16, answerSuite uint16) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleConn(conn, cfg, nullSuites, answerSuite)
		}
	}()
	return "https://" + ln.Addr().String()
}

func handleConn(conn net.Conn, cfg *tls.Config, nullSuites []uint16, answerSuite uint16) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	hdr, err := br.Peek(5)
	if err != nil {
		return
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	rec, err := br.Peek(5 + n)
	if err != nil {
		return
	}
	if answerSuite != 0 && helloOffers(rec[5:], nullSuites) {
		_, _ = conn.Write(fakeServerHello(answerSuite))
		return
	}
	srv := tls.Server(&prefixConn{Conn: conn, r: br}, cfg)
	_ = srv.Handshake()
	_ = srv.Close()
}

type prefixConn struct {
	net.Conn
	r io.Reader
}

func (p *prefixConn) Read(b []byte) (int, error) { return p.r.Read(b) }

func helloOffers(hs []byte, want []uint16) bool {
	// handshake(4) version(2) random(32) sid
	if len(hs) < 39 {
		return false
	}
	p := 38
	p += 1 + int(hs[p])
	if len(hs) < p+2 {
		return false
	}
	l := int(binary.BigEndian.Uint16(hs[p : p+2]))
	for i := p + 2; i+1 < p+2+l && i+1 < len(hs); i += 2 {
		if offered(want, binary.BigEndian.Uint16(hs[i:i+2])) {
			return true
		}
	}
	return false
}

func fakeServerHello(suite uint16) []byte {
	var b bytes.Buffer
	b.Write([]byte{3, 3})
	b.Write(make([]byte, 32))
	b.WriteByte(0)
	_ = binary.Write(&b, binary.BigEndian, suite)
	b.WriteByte(0)
	hs := append([]byte{2, 0, byte(b.Len() >> 8), byte(b.Len())}, b.Bytes()...)
	return append([]byte{22, 3, 3, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func runTLSConfig(t *testing.T, url string) []string {
	t.Helper()
	return keysOf(run(t, TLSConfig{}, url))
}

func TestTLSConfigModernServerIsClean(t *testing.T) {
	url := tlsListener(t, &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t, keyEC256)}, MinVersion: tls.VersionTLS12}, nil, 0)
	if ks := runTLSConfig(t, url); len(ks) != 0 {
		t.Fatalf("modern TLS 1.2/1.3 server: want no findings, got %v", ks)
	}
}

func TestTLSConfigNoForwardSecrecyAndNoTLS13(t *testing.T) {
	cfg := &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t, keyRSA2048)}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256}}
	fs := run(t, TLSConfig{}, tlsListener(t, cfg, nil, 0))
	requireKeys(t, fs, "tls13_unsupported", "no_forward_secrecy")
	if f := findKey(t, fs, "no_forward_secrecy"); f.Params["suite"] != "TLS_RSA_WITH_AES_128_GCM_SHA256" {
		t.Fatalf("suite: %v", f.Params)
	}
}

func TestTLSConfig3DESAccepted(t *testing.T) {
	cfg := &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t, keyRSA2048)}, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA}}
	fs := run(t, TLSConfig{}, tlsListener(t, cfg, nil, 0))
	requireKeys(t, fs, "tls13_unsupported", "weak_cipher_3des")
}

func TestTLSConfigInsecureSuiteOnlyWhenOfferedSuiteIsChosen(t *testing.T) {
	good := &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t, keyEC256)}}
	nulls := []uint16{0x0002}
	// the server picks the NULL suite we offered → insecure
	fs := run(t, TLSConfig{}, tlsListener(t, good, nulls, 0x0002))
	f := findKey(t, fs, "weak_cipher_insecure")
	if f.Params["suite"] != "TLS_RSA_WITH_NULL_SHA" || !strings.Contains(f.Evidence.RedactedPayload, "TLS_RSA_WITH_NULL_SHA") {
		t.Fatalf("%+v", f)
	}
	// a broken server that answers with a suite we did NOT offer proves nothing
	for _, k := range runTLSConfig(t, tlsListener(t, good, nulls, 0xC02F)) {
		if k == "weak_cipher_insecure" {
			t.Fatal("a ServerHello choosing a suite we did not offer must not count")
		}
	}
}

func TestTLSConfigWeakKey(t *testing.T) {
	url := tlsListener(t, &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t, keyRSA1024)}}, nil, 0)
	f := findKey(t, run(t, TLSConfig{}, url), "cert_weak_key")
	if f.Params["key_type"] != "RSA" || f.Params["bits"] != "1024" {
		t.Fatalf("%v", f.Params)
	}
}

// No HTTPS at all is tls_cert's finding (https_unavailable), not ours.
func TestTLSConfigNoHTTPSReportsNothing(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	_ = ln.Close() // nothing listens there now
	fs, err := TLSConfig{}.Run(context.Background(), targetFor(t, "http://"+addr))
	if err != nil || len(fs) != 0 {
		t.Fatalf("http origin without 443: %v %v", fs, err)
	}
}

func TestChainIncomplete(t *testing.T) {
	now := time.Now()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, rootKey.Public(), rootKey)
	root, _ := x509.ParseCertificate(rootDER)
	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interTpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Inter"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	interDER, _ := x509.CreateCertificate(rand.Reader, interTpl, root, interKey.Public(), rootKey)
	inter, _ := x509.ParseCertificate(interDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := func(aia bool, signer *x509.Certificate, key any) *x509.Certificate {
		tpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "site"}, DNSNames: []string{"site"},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
		if aia {
			tpl.IssuingCertificateURL = []string{"http://pki.example/inter.crt"}
		}
		der, _ := x509.CreateCertificate(rand.Reader, tpl, signer, leafKey.Public(), key)
		c, _ := x509.ParseCertificate(der)
		return c
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	c := TLSConfig{Roots: roots}
	res := func(certs ...*x509.Certificate) *probeTLS { return &probeTLS{certs} }
	cases := []struct {
		name string
		in   *probeTLS
		want bool
	}{
		{"intermediate missing, AIA present", res(leaf(true, inter, interKey)), true},
		{"full chain served", res(leaf(true, inter, interKey), inter), false},
		{"private CA leaf without AIA", res(leaf(false, inter, interKey)), false},
		{"leaf signed directly by a trusted root", res(leaf(true, root, rootKey)), false},
	}
	for _, tc := range cases {
		if _, got := c.chainIncomplete(tc.in.result()); got != tc.want {
			t.Errorf("%s: got %v", tc.name, got)
		}
	}
}

type probeTLS struct{ certs []*x509.Certificate }

func (p *probeTLS) result() *probe.TLSResult { return &probe.TLSResult{PeerCertificates: p.certs} }
