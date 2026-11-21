package egressproxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
)

// echoServer accepts one connection and echoes what it reads.
func echoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func connect(t *testing.T, proxyAddr, method, target string) (int, net.Conn) {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(method + " " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: method})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode, c
}

func TestProxyTunnelsOnlyAllowedHostsOn443(t *testing.T) {
	echo := echoServer(t)
	var dialed []string
	dial := func(_ context.Context, network, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		return net.Dial(network, echo.Addr().String()) // stand-in for the real host
	}
	p := New("api.github.com, GitHub.com", dial, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(p)
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	code, c := connect(t, addr, "CONNECT", "api.github.com:443")
	if code != http.StatusOK {
		t.Fatalf("allowed host: %d", code)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("tunnel did not carry bytes: %q %v", buf, err)
	}
	_ = c.Close()

	for _, tc := range []struct{ method, target string }{
		{"CONNECT", "evil.example:443"},
		{"CONNECT", "api.github.com:80"},
		{"CONNECT", "api.github.com.evil.example:443"},
		{"CONNECT", "169.254.169.254:443"},
		{"GET", "http://api.github.com/"},
	} {
		code, c := connect(t, addr, tc.method, tc.target)
		_ = c.Close()
		if code == http.StatusOK {
			t.Errorf("%s %s must be refused", tc.method, tc.target)
		}
	}
	if len(dialed) != 1 || dialed[0] != "api.github.com:443" {
		t.Fatalf("refused requests must not dial anything: %v", dialed)
	}
}

func TestProxyUsesTheGuard(t *testing.T) {
	// An allowed name that resolves to a private address is refused by the probe guard.
	dial := probe.GuardedDialer(2*time.Second, nil)
	_, err := dial(context.Background(), "tcp", "127.0.0.1:443")
	if !errors.Is(err, probe.ErrBlockedAddress) {
		t.Fatalf("guarded dial of loopback: %v", err)
	}
}
