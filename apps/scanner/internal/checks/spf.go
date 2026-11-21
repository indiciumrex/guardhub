package checks

// SPF (RFC 7208) and DMARC (RFC 7489) record evaluation for dns_email. Pure:
// DNS comes in through a txtLookup function, so every rule is table-tested.

import (
	"context"
	"fmt"
	"strings"
)

// lookupStatus distinguishes "the name has no such record" from "we could
// not find out" (SERVFAIL, timeout, refused): only the first may become a
// "missing" finding.
type lookupStatus int

const (
	lookupOK      lookupStatus = iota // answered (records may be empty: NODATA)
	lookupNone                        // NXDOMAIN
	lookupUnknown                     // SERVFAIL / timeout / refused
)

// txtLookup returns the TXT records of name, each record's strings already
// joined WITHOUT a separator (RFC 7208 §3.3, RFC 1035 §3.3.14).
type txtLookup func(ctx context.Context, name string) ([]string, lookupStatus, error)

const spfLookupLimit = 10 // RFC 7208 §4.6.4

// spfVerdict is the evaluation of a domain's SPF policy.
type spfVerdict struct {
	Found    bool
	Record   string
	Problem  string // "" | "multiple_records" | "syntax: ..." | "too_many_lookups" | "include_without_spf: ..."
	AllowAll bool   // the effective "all" is +all (or a bare "all")
	Lookups  int
	Unknown  bool // a lookup failed: the verdict is incomplete, report nothing about validity
}

// spfRecords picks the "v=spf1" records out of TXT records (exact version
// token: "v=spf10" is not SPF).
func spfRecords(txts []string) []string {
	var out []string
	for _, t := range txts {
		l := strings.ToLower(strings.TrimSpace(t))
		if l == "v=spf1" || strings.HasPrefix(l, "v=spf1 ") {
			out = append(out, strings.TrimSpace(t))
		}
	}
	return out
}

// evaluateSPF evaluates domain's SPF, following include and redirect.
func evaluateSPF(ctx context.Context, domain string, lookup txtLookup) (spfVerdict, error) {
	txts, st, err := lookup(ctx, domain)
	if err != nil {
		return spfVerdict{}, err
	}
	if st == lookupUnknown {
		return spfVerdict{Unknown: true}, nil
	}
	recs := spfRecords(txts)
	if len(recs) == 0 {
		return spfVerdict{}, nil
	}
	v := spfVerdict{Found: true, Record: recs[0]}
	if len(recs) > 1 {
		v.Problem = "multiple_records"
		return v, nil
	}
	e := &spfEval{lookup: lookup, visited: map[string]bool{strings.ToLower(domain): true}}
	allQ, hasAll, err := e.record(ctx, recs[0], 0)
	if err != nil {
		return v, err
	}
	v.Lookups = e.lookups
	v.Unknown = e.unknown
	v.Problem = e.problem
	v.AllowAll = hasAll && allQ == '+'
	return v, nil
}

type spfEval struct {
	lookup  txtLookup
	visited map[string]bool
	lookups int
	problem string
	unknown bool
}

// record walks one SPF record. It returns the qualifier of the record's
// effective "all" (following redirect when the record has no "all").
func (e *spfEval) record(ctx context.Context, rec string, depth int) (byte, bool, error) {
	if depth > 2*spfLookupLimit { // backstop only: the lookup limit stops real chains first
		e.setProblem("include/redirect loop")
		return 0, false, nil
	}
	terms := strings.Fields(rec)[1:]
	var allQ byte
	hasAll := false
	redirect := ""
	for _, raw := range terms {
		term := strings.ToLower(raw)
		if name, value, isMod := strings.Cut(term, "="); isMod && !strings.ContainsAny(name, ":/") {
			switch name {
			case "redirect":
				redirect = value
			case "exp":
			default:
				if !validModifierName(name) {
					e.setProblem("syntax: " + evidenceTerm(raw))
				}
			}
			continue
		}
		q := byte('+')
		if strings.ContainsRune("+-~?", rune(term[0])) {
			q, term = term[0], term[1:]
		}
		mech, arg, _ := strings.Cut(term, ":")
		mech, _, _ = strings.Cut(mech, "/") // "a/24", "mx/24"
		switch mech {
		case "all":
			allQ, hasAll = q, true
		case "ip4", "ip6":
			if arg == "" {
				e.setProblem("syntax: " + evidenceTerm(raw))
			}
		case "a", "mx", "ptr":
			if !e.count() {
				return 0, false, nil
			}
		case "exists":
			if !e.count() {
				return 0, false, nil
			}
			if arg == "" {
				e.setProblem("syntax: " + evidenceTerm(raw))
			}
		case "include":
			if !e.count() {
				return 0, false, nil
			}
			if arg == "" {
				e.setProblem("syntax: " + evidenceTerm(raw))
				continue
			}
			if err := e.follow(ctx, arg, depth, true); err != nil {
				return 0, false, err
			}
		default:
			e.setProblem("syntax: " + evidenceTerm(raw))
		}
	}
	if redirect != "" && !hasAll {
		if !e.count() {
			return 0, false, nil
		}
		q, has, err := e.followRedirect(ctx, redirect, depth)
		return q, has, err
	}
	return allQ, hasAll, nil
}

func (e *spfEval) follow(ctx context.Context, domain string, depth int, include bool) error {
	if strings.Contains(domain, "%{") { // macros: cannot be expanded without a sender
		return nil
	}
	if e.visited[domain] {
		e.setProblem("include/redirect loop")
		return nil
	}
	e.visited[domain] = true
	txts, st, err := e.lookup(ctx, domain)
	if err != nil {
		return err
	}
	if st == lookupUnknown {
		e.unknown = true
		return nil
	}
	recs := spfRecords(txts)
	if len(recs) != 1 {
		if include {
			e.setProblem("include_without_spf: " + domain)
		}
		return nil
	}
	_, _, err = e.record(ctx, recs[0], depth+1) // an include's "all" does not decide the outer result
	return err
}

func (e *spfEval) followRedirect(ctx context.Context, domain string, depth int) (byte, bool, error) {
	if strings.Contains(domain, "%{") || e.visited[domain] {
		return 0, false, nil
	}
	e.visited[domain] = true
	txts, st, err := e.lookup(ctx, domain)
	if err != nil || st == lookupUnknown {
		e.unknown = e.unknown || st == lookupUnknown
		return 0, false, err
	}
	recs := spfRecords(txts)
	if len(recs) != 1 {
		e.setProblem("redirect_without_spf: " + domain)
		return 0, false, nil
	}
	return e.record(ctx, recs[0], depth+1)
}

// count records one DNS-querying term; past the limit evaluation stops with a
// permanent error (RFC 7208 §4.6.4), as receivers do.
func (e *spfEval) count() bool {
	e.lookups++
	if e.lookups > spfLookupLimit {
		e.setProblem("too_many_lookups")
		return false
	}
	return true
}

func (e *spfEval) setProblem(p string) {
	if e.problem == "" {
		e.problem = p
	}
}

func validModifierName(n string) bool {
	if n == "" || n[0] < 'a' || n[0] > 'z' {
		return false
	}
	for _, r := range n {
		lower, digit := r >= 'a' && r <= 'z', r >= '0' && r <= '9'
		if !lower && !digit && r != '-' && r != '_' && r != '.' {
			return false
		}
	}
	return true
}

func evidenceTerm(t string) string {
	if len(t) > 60 {
		return t[:60] + "…"
	}
	return t
}

// dmarcPolicy parses DMARC records; ok=false when there is no single valid
// record (RFC 7489 §6.6.3: several records = no policy).
func dmarcPolicy(txts []string, subdomain bool) (policy string, ok bool) {
	var valid []string
	for _, t := range txts {
		if strings.HasPrefix(strings.TrimSpace(t), "v=DMARC1") {
			valid = append(valid, t)
		}
	}
	if len(valid) != 1 {
		return "", false
	}
	tags := map[string]string{}
	for _, part := range strings.Split(valid[0], ";") {
		k, val, found := strings.Cut(strings.TrimSpace(part), "=")
		if found {
			tags[strings.ToLower(strings.TrimSpace(k))] = strings.ToLower(strings.TrimSpace(val))
		}
	}
	p, hasP := tags["p"]
	if !hasP || (p != "none" && p != "quarantine" && p != "reject") {
		return "", false
	}
	if subdomain {
		if sp, has := tags["sp"]; has && (sp == "none" || sp == "quarantine" || sp == "reject") {
			p = sp
		}
	}
	return p, true
}

func (v spfVerdict) String() string {
	return fmt.Sprintf("found=%v problem=%q allowAll=%v lookups=%d unknown=%v", v.Found, v.Problem, v.AllowAll, v.Lookups, v.Unknown)
}
