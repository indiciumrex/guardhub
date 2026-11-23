package probe

// DNS probes for dns_email: lookups through the recursive resolver (public
// records, like any visitor's resolver does) and single queries sent
// straight to a zone's own nameservers (open-resolver and zone-transfer
// tests). Every query counts against the scan budget; queries to
// nameservers go through the same IP guard as HTTP (a nameserver that
// resolves to a private address is refused unless allowlisted).

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ErrNoResolver: no recursive resolver is configured or found.
var ErrNoResolver = errors.New("probe: no DNS resolver configured")

func (c *Client) resolverAddr() (string, error) {
	if c.opts.DNSServer != "" {
		return c.opts.DNSServer, nil
	}
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(cfg.Servers) == 0 {
		return "", ErrNoResolver
	}
	return net.JoinHostPort(cfg.Servers[0], cfg.Port), nil
}

// DNSQuery asks the recursive resolver for name/qtype (RD set, EDNS0 with the
// DO bit so DNSSEC records come back). Truncated UDP answers are retried
// over TCP. A non-NOERROR rcode is returned as a message, not an error:
// callers tell "does not exist" (NXDOMAIN) from "could not tell" (SERVFAIL).
func (c *Client) DNSQuery(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	return c.dnsQuery(ctx, name, qtype, false)
}

// DNSQueryCD is DNSQuery with the CD ("checking disabled") bit: a validating
// resolver returns the records of a zone whose DNSSEC is broken instead of
// SERVFAIL, so the break itself can be examined (dns_depth).
func (c *Client) DNSQueryCD(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	return c.dnsQuery(ctx, name, qtype, true)
}

func (c *Client) dnsQuery(ctx context.Context, name string, qtype uint16, cd bool) (*dns.Msg, error) {
	name = dns.Fqdn(strings.ToLower(name))
	if err := c.reserve(ctx, "dns:"+name); err != nil {
		return nil, err
	}
	addr, err := c.resolverAddr()
	if err != nil {
		return nil, err
	}
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = true
	m.CheckingDisabled = cd
	m.SetEdns0(1232, true)
	// Two UDP attempts of half the timeout each: a single lost datagram (UDP has no
	// retransmission) must not cost the whole answer, as stub resolvers retry too.
	// The total stays within the client's timeout.
	half := c.opts.Timeout / 2
	var resp *dns.Msg
	for attempt := 0; attempt < 2; attempt++ {
		resp, err = exchange(ctx, m, addr, "udp", half)
		if err == nil || ctx.Err() != nil || !isTimeout(err) {
			break
		}
	}
	if err == nil && resp.Truncated {
		resp, err = exchange(ctx, m, addr, "tcp", c.opts.Timeout)
	}
	return resp, err
}

func exchange(ctx context.Context, m *dns.Msg, addr, network string, timeout time.Duration) (*dns.Msg, error) {
	qctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cl := &dns.Client{Net: network, Timeout: timeout}
	resp, _, err := cl.ExchangeContext(qctx, m, addr)
	return resp, err
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

// DNSAsk sends m to nameserver nsHost on port 53 (Options.DNSPort; UDP, or TCP when tcp is
// set) and returns the first answer message. The connection goes through the
// probe client's guarded dialer: nsHost's address must be public (or nsHost
// allowlisted).
func (c *Client) DNSAsk(ctx context.Context, nsHost string, m *dns.Msg, tcp bool) (*dns.Msg, error) {
	nsHost = strings.ToLower(strings.TrimSuffix(nsHost, "."))
	if err := c.reserve(ctx, nsHost); err != nil {
		return nil, err
	}
	qctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()
	network := "udp"
	if tcp {
		network = "tcp"
	}
	port := c.opts.DNSPort
	if port == "" {
		port = "53"
	}
	raw, err := c.dialer(nsHost).DialContext(qctx, network, net.JoinHostPort(nsHost, port))
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	deadline := time.Now().Add(c.opts.Timeout)
	if dl, ok := qctx.Deadline(); ok {
		deadline = dl
	}
	_ = raw.SetDeadline(deadline)
	conn := &dns.Conn{Conn: raw}
	if err := conn.WriteMsg(m); err != nil {
		return nil, err
	}
	return conn.ReadMsg()
}
