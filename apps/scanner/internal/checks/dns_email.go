package checks

// dns_email: e-mail spoofing protection (SPF, DMARC) and nameserver hygiene
// (open resolver, zone transfer) for the verified host. Passive DNS only:
//   - record lookups through the recursive resolver (the same public data any
//     mail server reads): MX, TXT, _dmarc TXT, SOA, NS;
//   - ONLY when the verified host is the apex of its own DNS zone: one
//     recursive-question query and one AXFR request per nameserver (max 4),
//     each a single message read then closed. A subdomain owner has not
//     proven control of the parent zone, so its nameservers are not touched
//     (§9.2).
// A lookup error (SERVFAIL, timeout, refused) is never turned into "missing".
// Not reported on purpose: missing DKIM (unprovable without the selector,
// which only real e-mails reveal) and DNSSEC (see docs/checks/dns_email.md).

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
)

// DNSEmail implements the dns_email check.
type DNSEmail struct {
	// RecursionProbe is the out-of-zone name asked to each nameserver to see
	// if it recurses for anyone (default "example.com."; the lab sets its own).
	RecursionProbe string
}

// ID implements Check.
func (DNSEmail) ID() string { return evidence.CheckDnsEmail }

const maxNameservers = 4

// errAllLookupsFailed: no DNS answer at all, so nothing can be judged.
var errAllLookupsFailed = errors.New("dns_email: every DNS lookup failed")

// Run implements Check.
func (c DNSEmail) Run(ctx context.Context, t Target) ([]evidence.Finding, error) {
	host := t.Host()
	if net.ParseIP(strings.Trim(host, "[]")) != nil {
		return nil, nil // an IP address has no DNS records of its own
	}
	d := &dnsLookups{t: t}
	var out []evidence.Finding
	add := func(key string, params map[string]string, loc, payload string) {
		out = append(out, evidence.New(c.ID(), key, params, evidence.KindDnsRecord, loc, payload))
	}

	mx, mxSt, err := d.query(ctx, host, dns.TypeMX)
	if err != nil {
		return nil, err
	}
	nullMX, hasMX := classifyMX(mx)
	spf, err := evaluateSPF(ctx, host, d.txt)
	if err != nil {
		return nil, err
	}

	if !nullMX && !spf.Unknown {
		switch {
		case spf.Found && spf.Problem != "":
			add("spf_invalid", map[string]string{"domain": host, "reason": spf.Problem}, "TXT "+host, "SPF record: "+evidence.Truncate(spf.Record, 400)+"\nProblem: "+spf.Problem)
		case spf.Found && spf.AllowAll:
			add("spf_allow_all", map[string]string{"domain": host}, "TXT "+host, "SPF record: "+evidence.Truncate(spf.Record, 400)+"\nIts final \"all\" passes every sender.")
		case !spf.Found && hasMX && mxSt == lookupOK:
			add("spf_missing", map[string]string{"domain": host}, "TXT "+host, "MX records: "+evidence.Truncate(strings.Join(mxHosts(mx), ", "), 300)+"\nNo TXT record starting with v=spf1.")
		}
	}

	// DMARC applies to domains that handle mail: MX, an SPF that allows senders,
	// or a DMARC record published on the host itself. The last one matters for
	// today's e-mail providers (Resend, SendGrid, Postmark, SES custom MAIL
	// FROM): the From domain carries only DKIM + DMARC, while MX/SPF live on a
	// subdomain (send.example.com). Found on our own domain before release.
	sendsOnlyNothing := spf.Found && strings.EqualFold(strings.Join(strings.Fields(spf.Record), " "), "v=spf1 -all")
	mailDomain := !nullMX && (hasMX || (spf.Found && !sendsOnlyNothing))
	if !mailDomain && !nullMX {
		own, st, err := d.txt(ctx, "_dmarc."+host)
		if err != nil {
			return out, err
		}
		_, published := dmarcPolicy(own, false)
		mailDomain = st == lookupOK && published
	}
	if mailDomain {
		policy, where, known, err := c.dmarc(ctx, d, host)
		if err != nil {
			return out, err
		}
		if known {
			switch policy {
			case "":
				add("dmarc_missing", map[string]string{"domain": host}, "TXT _dmarc."+host, "No valid DMARC record at _dmarc."+host+orgNote(host))
			case "none":
				add("dmarc_not_enforced", map[string]string{"domain": host}, "TXT "+where, "DMARC at "+where+" has p=none (monitor only): spoofed mail is still delivered.")
			}
		}
	}

	// Nameserver hygiene, only for the apex of a zone the user proved.
	if apex, err := d.isZoneApex(ctx, host); err != nil {
		return out, err
	} else if apex {
		found, err := c.nameserverFindings(ctx, d, host)
		if err != nil {
			return out, err
		}
		out = append(out, found...)
	}

	if d.answered == 0 && d.asked > 0 {
		return out, errAllLookupsFailed
	}
	return out, nil
}

// dmarc finds the policy for host: _dmarc.host, else the organisational
// domain's record (RFC 7489 §6.6.3; its sp= applies to subdomains). known is
// false when a lookup failed, so no finding may be derived.
func (c DNSEmail) dmarc(ctx context.Context, d *dnsLookups, host string) (policy, where string, known bool, err error) {
	txts, st, err := d.txt(ctx, "_dmarc."+host)
	if err != nil || st == lookupUnknown {
		return "", "", false, err
	}
	if p, ok := dmarcPolicy(txts, false); ok {
		return p, "_dmarc." + host, true, nil
	}
	org, perr := publicsuffix.EffectiveTLDPlusOne(host)
	if perr != nil || org == host {
		return "", "", true, nil
	}
	txts, st, err = d.txt(ctx, "_dmarc."+org)
	if err != nil || st == lookupUnknown {
		return "", "", false, err
	}
	if p, ok := dmarcPolicy(txts, true); ok {
		return p, "_dmarc." + org, true, nil
	}
	return "", "", true, nil
}

func orgNote(host string) string {
	if org, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil && org != host {
		return " nor at _dmarc." + org
	}
	return ""
}

func (c DNSEmail) nameserverFindings(ctx context.Context, d *dnsLookups, host string) ([]evidence.Finding, error) {
	msg, st, err := d.query(ctx, host, dns.TypeNS)
	if err != nil || st != lookupOK {
		return nil, err
	}
	var nss []string
	for _, rr := range msg.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			nss = append(nss, strings.ToLower(strings.TrimSuffix(ns.Ns, ".")))
		}
	}
	sort.Strings(nss)
	if len(nss) > maxNameservers {
		nss = nss[:maxNameservers]
	}
	probeName := c.RecursionProbe
	if probeName == "" {
		probeName = "example.com."
	}
	var out []evidence.Finding
	openRes, axfr := false, false
	for _, ns := range nss {
		if !openRes {
			q := new(dns.Msg)
			q.SetQuestion(dns.Fqdn(probeName), dns.TypeA)
			q.RecursionDesired = true
			resp, err := d.t.Probe.DNSAsk(ctx, ns, q, false)
			if err != nil && isFatal(ctx, err) {
				return out, err
			}
			if err == nil && resp.RecursionAvailable && resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
				openRes = true
				out = append(out, evidence.New(evidence.CheckDnsEmail, "open_resolver", map[string]string{"nameserver": ns},
					evidence.KindDnsRecord, "NS "+ns, fmt.Sprintf("Asked %s (a nameserver of %s) for %s with recursion desired:\nit answered (RA flag set, %d record(s)).", ns, host, probeName, len(resp.Answer))))
			}
		}
		if !axfr {
			q := new(dns.Msg)
			q.SetAxfr(dns.Fqdn(host))
			resp, err := d.t.Probe.DNSAsk(ctx, ns, q, true)
			if err != nil && isFatal(ctx, err) {
				return out, err
			}
			if err == nil && resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
				if soa, ok := resp.Answer[0].(*dns.SOA); ok && strings.EqualFold(soa.Hdr.Name, dns.Fqdn(host)) {
					axfr = true
					out = append(out, evidence.New(evidence.CheckDnsEmail, "zone_transfer_open", map[string]string{"nameserver": ns},
						evidence.KindDnsRecord, "AXFR "+host+" @"+ns, fmt.Sprintf("AXFR of %s from %s was answered: the first message held %d record(s), starting with the zone's SOA.\n(Only the first message was read; no zone data is stored.)", host, ns, len(resp.Answer))))
				}
			}
		}
	}
	return out, nil
}

// dnsLookups wraps DNS queries through the probe client and keeps count of
// answered lookups (all failing = the check cannot judge anything).
type dnsLookups struct {
	t        Target
	asked    int
	answered int
}

func (d *dnsLookups) query(ctx context.Context, name string, qtype uint16) (*dns.Msg, lookupStatus, error) {
	d.asked++
	resp, err := d.t.Probe.DNSQuery(ctx, name, qtype)
	if err != nil {
		if isFatal(ctx, err) {
			return nil, lookupUnknown, err
		}
		return nil, lookupUnknown, nil
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
		d.answered++
		return resp, lookupOK, nil
	case dns.RcodeNameError:
		d.answered++
		return resp, lookupNone, nil
	default: // SERVFAIL, REFUSED, ...: we could not find out
		return resp, lookupUnknown, nil
	}
}

// txt returns the TXT records of name, each record's strings joined without
// a separator (RFC 7208 §3.3).
func (d *dnsLookups) txt(ctx context.Context, name string) ([]string, lookupStatus, error) {
	resp, st, err := d.query(ctx, name, dns.TypeTXT)
	if err != nil || st != lookupOK {
		return nil, st, err
	}
	var out []string
	for _, rr := range resp.Answer {
		if t, ok := rr.(*dns.TXT); ok && strings.EqualFold(t.Hdr.Name, dns.Fqdn(name)) {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	return out, lookupOK, nil
}

// isZoneApex: the SOA for host is owned by host itself.
func (d *dnsLookups) isZoneApex(ctx context.Context, host string) (bool, error) {
	resp, st, err := d.query(ctx, host, dns.TypeSOA)
	if err != nil || st != lookupOK {
		return false, err
	}
	for _, rr := range resp.Answer {
		if soa, ok := rr.(*dns.SOA); ok && strings.EqualFold(soa.Hdr.Name, dns.Fqdn(host)) {
			return true, nil
		}
	}
	return false, nil
}

func classifyMX(m *dns.Msg) (nullMX, hasMX bool) {
	if m == nil {
		return false, false
	}
	var mxs []*dns.MX
	for _, rr := range m.Answer {
		if mx, ok := rr.(*dns.MX); ok {
			mxs = append(mxs, mx)
		}
	}
	if len(mxs) == 1 && mxs[0].Mx == "." {
		return true, false // RFC 7505 null MX: "this domain accepts no mail"
	}
	return false, len(mxs) > 0
}

func mxHosts(m *dns.Msg) []string {
	var out []string
	if m == nil {
		return out
	}
	for _, rr := range m.Answer {
		if mx, ok := rr.(*dns.MX); ok {
			out = append(out, strings.TrimSuffix(mx.Mx, "."))
		}
	}
	return out
}
