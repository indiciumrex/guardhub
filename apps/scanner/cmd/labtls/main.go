// Command labtls is a validation-lab TLS target (test_corpus/) for cipher
// suites that current OpenSSL builds no longer contain (3DES, RC4) but Go's
// crypto/tls still serves when configured, as Go-based proxies (Traefik, ...)
// allow. It serves a static hardened page on :443 and redirects :80.
//
//	labtls serve  -name NAME -cert FILE -key FILE -suites ID,ID -max 1.2
//	labtls verify -addr HOST:443 -suites ID,ID     (full handshake, prints the suite)
//
// verify is the independent ground truth: a full crypto/tls handshake, not the
// scanner's raw-hello parser.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: labtls serve|verify ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		err = fmt.Errorf("unknown mode %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "labtls:", err)
		os.Exit(1)
	}
}

func parseSuites(s string) ([]uint16, error) {
	var out []uint16
	for _, p := range strings.Split(s, ",") {
		v, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(p), "0x"), 16, 16)
		if err != nil {
			return nil, fmt.Errorf("bad suite %q", p)
		}
		out = append(out, uint16(v))
	}
	return out, nil
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	name := fs.String("name", "", "host name")
	cert := fs.String("cert", "", "certificate chain (PEM)")
	key := fs.String("key", "", "private key (PEM)")
	suites := fs.String("suites", "", "cipher suite ids (hex, comma separated)")
	_ = fs.Parse(args)
	ids, err := parseSuites(*suites)
	if err != nil {
		return err
	}
	pair, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		return err
	}
	page := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		h.Set("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()") // as nginx/clean.conf
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		h.Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Lab site</title></head><body><h1>GuardHub validation lab</h1></body></html>`))
	})
	srv := &http.Server{
		Addr: ":443", Handler: page, ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{ //nolint:gosec // deliberately weak lab target
			Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: ids,
		},
	}
	redirect := &http.Server{Addr: ":80", ReadHeaderTimeout: 10 * time.Second,
		Handler: http.RedirectHandler("https://"+*name+"/", http.StatusMovedPermanently)}
	go func() { _ = redirect.ListenAndServe() }()
	return srv.ListenAndServeTLS("", "")
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	addr := fs.String("addr", "", "host:port")
	suites := fs.String("suites", "", "cipher suite ids to offer (hex)")
	_ = fs.Parse(args)
	ids, err := parseSuites(*suites)
	if err != nil {
		return err
	}
	host := strings.Split(*addr, ":")[0]
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d := &tls.Dialer{Config: &tls.Config{
		ServerName: host,
		// ground truth about cipher suites of a lab target, not about its certificate
		InsecureSkipVerify: true, //nolint:gosec // see comment above
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       ids,
	}}
	raw, err := d.DialContext(ctx, "tcp", *addr)
	if err != nil {
		fmt.Printf("%s refused: %v\n", *addr, err)
		return nil
	}
	conn := raw.(*tls.Conn)
	defer conn.Close()
	st := conn.ConnectionState()
	fmt.Printf("%s accepted %s (%s)\n", *addr, tls.CipherSuiteName(st.CipherSuite), tls.VersionName(st.Version))
	return nil
}
