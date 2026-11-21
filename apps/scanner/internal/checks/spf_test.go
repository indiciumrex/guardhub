package checks

import (
	"context"
	"fmt"
	"testing"
)

type fakeTXT map[string][]string

const servfail = "SERVFAIL"

func (f fakeTXT) lookup(_ context.Context, name string) ([]string, lookupStatus, error) {
	recs, ok := f[name]
	if !ok {
		return nil, lookupNone, nil
	}
	if len(recs) == 1 && recs[0] == servfail {
		return nil, lookupUnknown, nil
	}
	return recs, lookupOK, nil
}

func TestEvaluateSPF(t *testing.T) {
	zone := fakeTXT{
		"good.test":         {"v=spf1 mx include:_spf.mailer.test -all", "google-site-verification=abc"},
		"_spf.mailer.test":  {"v=spf1 ip4:192.0.2.0/24 ~all"},
		"plusall.test":      {"v=spf1 include:_spf.mailer.test +all"},
		"bareall.test":      {"v=spf1 a all"},
		"neutral.test":      {"v=spf1 mx ?all"},
		"two.test":          {"v=spf1 mx -all", "v=spf1 a -all"},
		"spf10.test":        {"v=spf10 nothing", "v=spf1 -all"},
		"typo.test":         {"v=spf1 mx inclde:x.test -all"},
		"noall.test":        {"v=spf1 mx"},
		"redir.test":        {"v=spf1 redirect=_spf.mailer.test"},
		"redirall.test":     {"v=spf1 redirect=plusall.test"},
		"inc-missing.test":  {"v=spf1 include:nowhere.test -all"},
		"inc-servfail.test": {"v=spf1 include:broken.test -all"},
		"broken.test":       {servfail},
		"loop1.test":        {"v=spf1 include:loop2.test -all"},
		"loop2.test":        {"v=spf1 include:loop1.test -all"},
		"macro.test":        {"v=spf1 exists:%{i}._spf.example.test -all"},
		"unknownmod.test":   {"v=spf1 mx foo=bar -all"},
	}
	// 11 nested includes: each counts one lookup (RFC 7208 §4.6.4)
	for i := 0; i < 11; i++ {
		next := fmt.Sprintf("n%d.test", i+1)
		rec := "v=spf1 include:" + next + " -all"
		if i == 10 {
			rec = "v=spf1 ip4:192.0.2.1 -all"
		}
		zone[fmt.Sprintf("n%d.test", i)] = []string{rec}
	}
	zone["n11.test"] = []string{"v=spf1 -all"}
	zone["deep.test"] = []string{"v=spf1 include:n0.test -all"}

	cases := []struct {
		domain   string
		found    bool
		problem  string
		allowAll bool
		unknown  bool
	}{
		{"good.test", true, "", false, false},
		{"plusall.test", true, "", true, false},
		{"bareall.test", true, "", true, false}, // a bare "all" means "+all"
		{"neutral.test", true, "", false, false},
		{"two.test", true, "multiple_records", false, false},
		{"spf10.test", true, "", false, false}, // "v=spf10" is not an SPF record
		{"typo.test", true, "syntax: inclde:x.test", false, false},
		{"noall.test", true, "", false, false},
		{"redir.test", true, "", false, false},
		{"redirall.test", true, "", true, false}, // the redirect target's +all applies
		{"inc-missing.test", true, "include_without_spf: nowhere.test", false, false},
		{"inc-servfail.test", true, "", false, true}, // can't tell: never "invalid"
		{"loop1.test", true, "include/redirect loop", false, false},
		{"macro.test", true, "", false, false},
		{"unknownmod.test", true, "", false, false},
		{"deep.test", true, "too_many_lookups", false, false},
		{"nothing.test", false, "", false, false},
		{"broken.test", false, "", false, true},
	}
	for _, c := range cases {
		v, err := evaluateSPF(context.Background(), c.domain, zone.lookup)
		if err != nil {
			t.Fatalf("%s: %v", c.domain, err)
		}
		if v.Found != c.found || v.Problem != c.problem || v.AllowAll != c.allowAll || v.Unknown != c.unknown {
			t.Errorf("%s: got %s, want found=%v problem=%q allowAll=%v unknown=%v", c.domain, v, c.found, c.problem, c.allowAll, c.unknown)
		}
	}
}

func TestDMARCPolicy(t *testing.T) {
	cases := []struct {
		txts      []string
		subdomain bool
		policy    string
		ok        bool
	}{
		{[]string{"v=DMARC1; p=reject; rua=mailto:d@example.test"}, false, "reject", true},
		{[]string{"v=DMARC1;p=none"}, false, "none", true},
		{[]string{"v=DMARC1; p=quarantine; sp=none"}, true, "none", true}, // subdomain policy wins for subdomains
		{[]string{"v=DMARC1; p=quarantine; sp=none"}, false, "quarantine", true},
		{[]string{"v=DMARC1; rua=mailto:x@example.test"}, false, "", false},    // no p: invalid
		{[]string{"v=DMARC1; p=reject", "v=DMARC1; p=none"}, false, "", false}, // two records: no policy
		{[]string{"some-verification=xyz"}, false, "", false},
		{nil, false, "", false},
	}
	for _, c := range cases {
		p, ok := dmarcPolicy(c.txts, c.subdomain)
		if p != c.policy || ok != c.ok {
			t.Errorf("%v sub=%v: got %q %v", c.txts, c.subdomain, p, ok)
		}
	}
}
