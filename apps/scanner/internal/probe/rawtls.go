package probe

// Raw TLS hello: send one hand-built ClientHello and read only the server's
// first answer (ServerHello or alert). No key exchange, no application data:
// the connection is closed right after. Used by tls_config to learn which
// cipher suites a server ACCEPTS, including suites Go's crypto/tls cannot
// offer (NULL, anonymous, export). Same IP guard, budget, rate limit and
// timeout as every other probe.

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

// HelloOutcome classifies the server's answer to a ClientHello.
type HelloOutcome int

const (
	// HelloRejected: a TLS alert, or the server closed the connection.
	HelloRejected HelloOutcome = iota
	// HelloAccepted: a well-formed ServerHello.
	HelloAccepted
	// HelloNotTLS: the server answered something that is not TLS.
	HelloNotTLS
)

// HelloResult is what the server answered.
type HelloResult struct {
	Outcome HelloOutcome
	// Version is the negotiated version (supported_versions wins over legacy_version).
	Version uint16
	// CipherSuite chosen by the server (Accepted only).
	CipherSuite uint16
	// Alert is the alert description when the server sent one.
	Alert byte
}

// ErrMalformedServerHello: the server sent TLS records we could not parse.
var ErrMalformedServerHello = errors.New("probe: malformed ServerHello")

const (
	recordHandshake  = 22
	recordAlert      = 21
	handshakeSH      = 2
	extSupportedVers = 43
	maxHelloRead     = 16 << 10
)

// RawTLSHello sends hello (a complete TLS record) to host:port and parses the
// first answer. A refused/closed connection after the hello is HelloRejected.
func (c *Client) RawTLSHello(ctx context.Context, host, port string, hello []byte) (*HelloResult, error) {
	host = strings.ToLower(host)
	if err := c.reserve(ctx, host); err != nil {
		return nil, err
	}
	hctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()
	conn, err := c.dialer(host).DialContext(hctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := hctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(c.opts.Timeout))
	}
	if _, err := conn.Write(hello); err != nil {
		return &HelloResult{Outcome: HelloRejected}, nil //nolint:nilerr // the server closed: a refusal
	}
	var buf []byte
	tmp := make([]byte, 4096)
	for len(buf) < maxHelloRead {
		if res, done := ParseServerHello(buf); done {
			return res, nil
		}
		n, err := conn.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			if res, done := ParseServerHello(buf); done {
				return res, nil
			}
			if errors.Is(err, io.EOF) || isReset(err) {
				return &HelloResult{Outcome: HelloRejected}, nil
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
	}
	return nil, ErrMalformedServerHello
}

func isReset(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && (strings.Contains(op.Err.Error(), "reset") || strings.Contains(op.Err.Error(), "broken pipe"))
}

// ParseServerHello inspects the bytes received so far. done=false means more
// bytes are needed. It handles a ServerHello split across records and records
// that hold several handshake messages.
func ParseServerHello(data []byte) (res *HelloResult, done bool) {
	var hs []byte // concatenated handshake-record payloads
	for off := 0; ; {
		if len(data)-off < 5 {
			break
		}
		typ := data[off]
		major := data[off+1]
		length := int(binary.BigEndian.Uint16(data[off+3 : off+5]))
		if major != 3 || length > 1<<14+2048 || (typ != recordHandshake && typ != recordAlert && typ != 20) {
			return &HelloResult{Outcome: HelloNotTLS}, true
		}
		if len(data)-off-5 < length {
			break
		}
		body := data[off+5 : off+5+length]
		off += 5 + length
		switch typ {
		case recordAlert:
			if len(hs) == 0 {
				r := &HelloResult{Outcome: HelloRejected}
				if len(body) >= 2 {
					r.Alert = body[1]
				}
				return r, true
			}
		case recordHandshake:
			hs = append(hs, body...)
		}
	}
	if len(hs) < 4 {
		if len(data) >= 5 && data[0] != recordHandshake && data[0] != recordAlert && data[0] != 20 {
			return &HelloResult{Outcome: HelloNotTLS}, true
		}
		return nil, false
	}
	if hs[0] != handshakeSH {
		return &HelloResult{Outcome: HelloNotTLS}, true
	}
	msgLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+msgLen {
		return nil, false
	}
	r, ok := parseServerHelloBody(hs[4 : 4+msgLen])
	if !ok {
		return &HelloResult{Outcome: HelloNotTLS}, true
	}
	return r, true
}

// parseServerHelloBody: legacy_version(2) random(32) session_id<0..32>
// cipher_suite(2) compression(1) [extensions<..>].
func parseServerHelloBody(b []byte) (*HelloResult, bool) {
	if len(b) < 2+32+1 {
		return nil, false
	}
	r := &HelloResult{Outcome: HelloAccepted, Version: binary.BigEndian.Uint16(b[0:2])}
	p := 34
	sidLen := int(b[p])
	p++
	if sidLen > 32 || len(b) < p+sidLen+3 {
		return nil, false
	}
	p += sidLen
	r.CipherSuite = binary.BigEndian.Uint16(b[p : p+2])
	p += 3 // suite + compression method
	if len(b) < p+2 {
		return r, true // no extensions
	}
	extLen := int(binary.BigEndian.Uint16(b[p : p+2]))
	p += 2
	if len(b) < p+extLen {
		return nil, false
	}
	exts := b[p : p+extLen]
	for len(exts) >= 4 {
		typ := binary.BigEndian.Uint16(exts[0:2])
		l := int(binary.BigEndian.Uint16(exts[2:4]))
		if len(exts) < 4+l {
			return nil, false
		}
		if typ == extSupportedVers && l == 2 {
			r.Version = binary.BigEndian.Uint16(exts[4:6])
		}
		exts = exts[4+l:]
	}
	return r, true
}
