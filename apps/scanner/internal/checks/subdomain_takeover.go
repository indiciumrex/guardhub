package checks

// subdomain_takeover: names under the verified host whose DNS points into a
// third-party provider where the resource no longer exists, so anyone could
// claim it and serve content on the name. Read-only:
//
//  1. Discovery, in scope only: the verified host itself, the names
//     Certificate Transparency logs have seen under it (one query to the CT
//     search service), and a short fixed list of names commonly pointed at
//     hosted services. Nothing outside "<host>" and "*.<host>" is ever
//     queried: the owner of shop.example.com has not proven example.com
//     (§9.2), so CT results for siblings or the parent are dropped unread.
//  2. Resolution: the CNAME chain of each name through the recursive
//     resolver, one CNAME query per hop.
//  3. Decision. High ONLY when both hold:
//     a) a hop points into a provider on the curated list
//        (takeover_providers.yaml: takeover really possible there), and
//     b) the provider's "unclaimed" fingerprint is seen: its NXDOMAIN
//        (asked twice) or its HTTP error answer for the name (one GET; a
//        2xx page is never an unclaimed resource).
//     A CNAME into a provider is NOT a finding by itself. A chain that ends
//     in NXDOMAIN outside the owner's registrable domain, at a provider not
//     on the list, is reported as low (dangling_cname): broken, but no proven
//     takeover path.
// GuardHub never creates, registers or claims anything.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
)

// DefaultCTURL is the Certificate Transparency search service (crt.sh JSON
// API). Its query carries only the verified domain (ADR-0005).
const DefaultCTURL = "https://crt.sh/"

// CTDisabled as CTURL turns CT discovery off (DNS-only discovery).
const CTDisabled = "off"

// Limits that keep the check's cost bounded inside the scan budget.
const (
	takeoverMaxNames = 40 // names resolved per scan
	takeoverMaxOps   = 70 // network operations (CT + DNS + HTTP) per scan
	takeoverMaxHops  = 4  // CNAME hops followed per name
	takeoverMaxHTTP  = 10 // fingerprint GETs per scan
)

// takeoverCommonNames are the only guessed names (not a brute force): labels
// commonly pointed at hosted services. Each costs one DNS query.
var takeoverCommonNames = []string{"www", "blog", "docs", "help", "support", "status", "shop", "cdn", "assets", "static"}

// SubdomainTakeover implements the subdomain_takeover check.
type SubdomainTakeover struct {
	// CTURL is the crt.sh-compatible search endpoint ("" = DefaultCTURL,
	// CTDisabled = no CT discovery). The lab points it at its own CT stand-in.
	CTURL string
	// fetchURL overrides the URL of fingerprint fetches (tests only: they
	// cannot resolve made-up names to the test server).
	fetchURL func(scheme, name string) string
}

// ID implements Check.
func (SubdomainTakeover) ID() string { return evidence.CheckSubdomainTakeover }

var errTakeoverNoAnswers = errors.New("subdomain_takeover: no DNS lookup was answered")

type takeoverRun struct {
	c    SubdomainTakeover
	t    Target
	d    *dnsLookups
	ops  int
	gets int
}

func (r *takeoverRun) spend() bool {
	if r.ops >= takeoverMaxOps {
		return false
	}
	r.ops++
	return true
}

// Run implements Check.
func (c SubdomainTakeover) Run(ctx context.Context, t Target) ([]evidence.Finding, error) {
	host := t.Host()
	if net.ParseIP(strings.Trim(host, "[]")) != nil || !strings.Contains(host, ".") {
		return nil, nil // an IP address (or single label) has no subdomains of its own
	}
	r := &takeoverRun{c: c, t: t, d: &dnsLookups{t: t}}
	names, ctNames, err := r.discover(ctx, host)
	if err != nil {
		return nil, err
	}
	var out []evidence.Finding
	for _, name := range names {
		if r.ops >= takeoverMaxOps {
			break
		}
		f, err := r.evaluate(ctx, host, name, ctNames[name])
		if err != nil {
			return out, err
		}
		if f != nil {
			out = append(out, *f)
		}
	}
	if r.d.asked > 0 && r.d.answered == 0 {
		return out, errTakeoverNoAnswers
	}
	return out, nil
}

// discover returns the in-scope names to resolve (host first, then CT names,
// then the common names), and which came from CT.
func (r *takeoverRun) discover(ctx context.Context, host string) ([]string, map[string]bool, error) {
	ct, err := r.ctNames(ctx, host)
	if err != nil {
		return nil, nil, err
	}
	seen := map[string]bool{host: true}
	names := []string{host}
	fromCT := map[string]bool{}
	ctList := make([]string, 0, len(ct))
	for n := range ct {
		ctList = append(ctList, n)
	}
	sort.Strings(ctList)
	for _, n := range ctList {
		fromCT[n] = true
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	for _, label := range takeoverCommonNames {
		n := label + "." + host
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	if len(names) > takeoverMaxNames {
		// Keep the guessed names' share small when CT already found many.
		names = names[:takeoverMaxNames]
	}
	return names, fromCT, nil
}

// ctNames asks the CT search service for certificates naming *.host and
// returns the in-scope names. A failing or slow CT service is not an error
// (discovery falls back to DNS); only budget/context errors are.
func (r *takeoverRun) ctNames(ctx context.Context, host string) (map[string]bool, error) {
	base := r.c.CTURL
	if base == "" {
		base = DefaultCTURL
	}
	if base == CTDisabled || !r.spend() {
		return nil, nil
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, nil
	}
	q := url.Values{}
	q.Set("q", "%."+host)
	q.Set("output", "json")
	q.Set("deduplicate", "Y")
	u.RawQuery = q.Encode()
	resp, err := r.t.Probe.Get(ctx, u.String())
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, probe.ErrBudgetExceeded) {
			return nil, err
		}
		return nil, nil
	}
	if resp.StatusCode != 200 {
		return nil, nil
	}
	return parseCTNames(resp.Body, host), nil
}

// parseCTNames reads a crt.sh JSON array ([{"common_name","name_value"}...])
// tolerantly: a body cut at the probe's size cap still yields the entries
// before the cut. Only names equal to host or below it are kept.
func parseCTNames(body []byte, host string) map[string]bool {
	out := map[string]bool{}
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
		return out
	}
	for dec.More() {
		var e struct {
			CommonName string `json:"common_name"`
			NameValue  string `json:"name_value"`
		}
		if err := dec.Decode(&e); err != nil {
			break
		}
		for _, n := range append(strings.Split(e.NameValue, "\n"), e.CommonName) {
			if n, ok := inScope(n, host); ok {
				out[n] = true
			}
		}
	}
	return out
}

// inScope normalises a CT name and keeps it only if it is host or a name
// below host. Wildcards ("*.a.host") stand for their base name ("a.host").
func inScope(name, host string) (string, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.TrimPrefix(n, "*.")
	n = strings.TrimSuffix(n, ".")
	if n == "" || len(n) > 253 || strings.ContainsAny(n, "*@/: ") {
		return "", false
	}
	if _, ok := dns.IsDomainName(n); !ok {
		return "", false
	}
	if n != host && !strings.HasSuffix(n, "."+host) {
		return "", false
	}
	return n, true
}

type chainEnd int

const (
	chainExists  chainEnd = iota // the last hop exists (NOERROR)
	chainNX                      // the last hop does not exist (NXDOMAIN)
	chainUnknown                 // could not tell (SERVFAIL, timeout, hop limit)
)

// cnameChain follows name's CNAMEs. It asks for A records, as a browser's
// resolver does: a recursive resolver answers with the whole chain (and the
// final status); an answer that stops at a CNAME whose target it did not
// follow is continued from that target. (Some resolvers, Docker's among them,
// refuse qtype CNAME, so it is not used.) chain holds the targets in order;
// end says whether the last name exists.
func (r *takeoverRun) cnameChain(ctx context.Context, name string) (chain []string, end chainEnd, err error) {
	cur := dns.Fqdn(strings.ToLower(name))
	for hop := 0; hop <= takeoverMaxHops; hop++ {
		if !r.spend() {
			return chain, chainUnknown, nil
		}
		resp, st, err := r.d.query(ctx, cur, dns.TypeA)
		if err != nil {
			return chain, chainUnknown, err
		}
		if st == lookupUnknown {
			return chain, chainUnknown, nil
		}
		// Walk the CNAMEs in the answer starting at cur.
		cnames := map[string]string{}
		hasAddr := map[string]bool{}
		for _, rr := range resp.Answer {
			switch v := rr.(type) {
			case *dns.CNAME:
				cnames[strings.ToLower(v.Hdr.Name)] = strings.ToLower(dns.Fqdn(v.Target))
			case *dns.A, *dns.AAAA:
				hasAddr[strings.ToLower(rr.Header().Name)] = true
			}
		}
		start := cur
		for i := 0; i <= takeoverMaxHops; i++ {
			next, ok := cnames[cur]
			if !ok || len(chain) > takeoverMaxHops {
				break
			}
			chain = append(chain, strings.TrimSuffix(next, "."))
			cur = next
		}
		switch {
		case st == lookupNone:
			return chain, chainNX, nil // NXDOMAIN refers to the end of the chain
		case hasAddr[cur] || cur == start:
			return chain, chainExists, nil // addresses, or the name exists without A (NODATA)
		case len(chain) > takeoverMaxHops:
			return chain, chainUnknown, nil
		}
		// The answer stopped at a CNAME target it did not follow: ask for it.
	}
	return chain, chainUnknown, nil
}

// stillNX asks for the final target once more: one NXDOMAIN may be a glitch.
func (r *takeoverRun) stillNX(ctx context.Context, target string) (bool, error) {
	if !r.spend() {
		return false, nil
	}
	_, st, err := r.d.query(ctx, target, dns.TypeA)
	return err == nil && st == lookupNone, err
}

func (r *takeoverRun) evaluate(ctx context.Context, host, name string, fromCT bool) (*evidence.Finding, error) {
	chain, end, err := r.cnameChain(ctx, name)
	if err != nil || len(chain) == 0 || end == chainUnknown {
		return nil, err // no CNAME: nothing can be taken over through it
	}
	final := chain[len(chain)-1]
	prov := providerFor(chain)
	source := "found in Certificate Transparency logs"
	if !fromCT {
		source = "a common name, resolved in DNS"
		if name == host {
			source = "the verified host itself"
		}
	}
	chainText := name + " → " + strings.Join(chain, " → ")

	if end == chainNX {
		nx, err := r.stillNX(ctx, final)
		if err != nil || !nx {
			return nil, err
		}
		if prov != nil && prov.Kind == takeoverNXDomain {
			f := evidence.New(evidence.CheckSubdomainTakeover, "unclaimed_resource",
				map[string]string{"subdomain": name, "provider": prov.Name}, evidence.KindDnsRecord, "CNAME "+name,
				fmt.Sprintf("Name: %s (%s)\nCNAME chain: %s\n%s is a %s name and does not exist (NXDOMAIN, asked twice):\nanyone can create it there and serve content on %s.",
					name, source, chainText, final, prov.Name, name))
			return &f, nil
		}
		if !sameRegistrable(final, host) {
			f := evidence.New(evidence.CheckSubdomainTakeover, "dangling_cname",
				map[string]string{"subdomain": name, "target": final}, evidence.KindDnsRecord, "CNAME "+name,
				fmt.Sprintf("Name: %s (%s)\nCNAME chain: %s\n%s does not exist (NXDOMAIN, asked twice).", name, source, chainText, final))
			return &f, nil
		}
		return nil, nil // a broken record inside the owner's own domain: nobody else can create the target
	}

	if prov == nil || prov.Kind != takeoverHTTP || r.gets >= takeoverMaxHTTP {
		return nil, nil
	}
	resp, err := r.fetch(ctx, name)
	if err != nil || resp == nil {
		return nil, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// A working page that merely mentions the text (a help article about
		// "Repository not found") is a claimed site. Conservative: a provider
		// that answered 2xx for an unclaimed name would be missed, not
		// misreported (docs/checks/subdomain_takeover.md).
		return nil, nil
	}
	fp, ok := prov.fingerprint(resp.Body)
	if !ok {
		return nil, nil // the resource answers normally: claimed
	}
	f := evidence.New(evidence.CheckSubdomainTakeover, "unclaimed_resource",
		map[string]string{"subdomain": name, "provider": prov.Name}, evidence.KindHttpResponse, resp.URL.String(),
		fmt.Sprintf("Name: %s (%s)\nCNAME chain: %s\nGET %s → HTTP %d\nMatched %s's \"not claimed\" fingerprint: %q",
			name, source, chainText, resp.URL.String(), resp.StatusCode, prov.Name, evidence.Truncate(fp, 120)))
	return &f, nil
}

// fetch GETs the name's root over http, then https if http did not answer.
// One name that cannot be reached (or resolves to a private address) is
// skipped; only budget/context errors stop the check.
func (r *takeoverRun) fetch(ctx context.Context, name string) (*probe.Response, error) {
	for _, scheme := range []string{"http", "https"} {
		if !r.spend() {
			return nil, nil
		}
		r.gets++
		target := scheme + "://" + name + "/"
		if r.c.fetchURL != nil {
			target = r.c.fetchURL(scheme, name)
		}
		resp, err := r.t.Probe.Get(ctx, target)
		if err == nil {
			return resp, nil
		}
		if ctx.Err() != nil || errors.Is(err, probe.ErrBudgetExceeded) {
			return nil, err
		}
		if errors.Is(err, probe.ErrBlockedAddress) {
			return nil, nil
		}
	}
	return nil, nil
}

// sameRegistrable: a and b share a registrable domain (eTLD+1).
func sameRegistrable(a, b string) bool {
	ra, err1 := publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(a, "."))
	rb, err2 := publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(b, "."))
	return err1 == nil && err2 == nil && strings.EqualFold(ra, rb)
}
