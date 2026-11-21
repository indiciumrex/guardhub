// Package egressproxy is a CONNECT-only forward proxy that lets the API
// containers, which have no internet access, reach exactly the GitHub hosts
// they need (ADR-0006: api.github.com, github.com). It runs as `scanner
// egress-proxy` in its own container on the internal and egress networks.
//
// It only tunnels: TLS stays end to end between the API and GitHub, so the
// proxy sees host names, never tokens or content. It refuses any method but
// CONNECT, any port but 443, any host not on the exact allowlist, and (via
// the probe guard) any private or special address the name resolves to.
package egressproxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Proxy is the CONNECT handler.
type Proxy struct {
	Allow  map[string]bool // lowercase host names
	Dial   func(ctx context.Context, network, addr string) (net.Conn, error)
	Log    *slog.Logger
	MaxAge time.Duration // hard cap on one tunnel's lifetime
}

// New builds a proxy for the comma-separated host allowlist.
func New(allow string, dial func(ctx context.Context, network, addr string) (net.Conn, error), log *slog.Logger) *Proxy {
	p := &Proxy{Allow: map[string]bool{}, Dial: dial, Log: log, MaxAge: 5 * time.Minute}
	for _, h := range strings.Split(allow, ",") {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			p.Allow[h] = true
		}
	}
	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
		return
	}
	host, port, err := net.SplitHostPort(r.Host)
	host = strings.ToLower(host)
	if err != nil || port != "443" || !p.Allow[host] {
		p.Log.Warn("egress refused", "host", host, "port", port)
		http.Error(w, "destination not allowed", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	upstream, err := p.Dial(ctx, "tcp", net.JoinHostPort(host, "443"))
	cancel()
	if err != nil {
		p.Log.Warn("egress dial failed", "host", host, "err", err)
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	deadline := time.Now().Add(p.MaxAge)
	_ = client.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // client → upstream (bytes the client already sent are in buf)
		defer wg.Done()
		_, _ = io.Copy(upstream, buf)
		closeWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream)
		closeWrite(client)
	}()
	wg.Wait()
	_ = client.Close()
	_ = upstream.Close()
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(interface{ CloseWrite() error }); ok {
		_ = tc.CloseWrite()
	}
}

// Serve listens on addr until ctx ends.
func Serve(ctx context.Context, addr string, p *Proxy) error {
	srv := &http.Server{Addr: addr, Handler: p, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
