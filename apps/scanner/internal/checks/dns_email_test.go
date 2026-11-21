package checks

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
)

// fakeDNS is an in-process DNS server playing both roles: the recursive
// resolver the scanner asks (records below) and the zones' nameserver.
type fakeDNS struct {
	mu        sync.Mutex
	records   map[string][]dns.RR // "name.|TYPE" → answer
	soaOwner  map[string]string   // name → zone apex (for SOA answers)
	servfail  map[string]bool     // "name.|TYPE" answered with SERVFAIL
	recursive bool                // answers out-of-zone RD queries (open resolver)
	axfr      map[string]bool     // zones that allow AXFR
	asked     []string
	addr      string
}

func newFakeDNS(t *testing.T) *fakeDNS {
	t.Helper()
	f := &fakeDNS{records: map[string][]dns.RR{}, soaOwner: map[string]string{}, servfail: map[string]bool{}, axfr: map[string]bool{}}
	// TCP first: on Windows some ephemeral UDP ports fall in TCP ranges reserved by Hyper-V.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.addr = ln.Addr().String()
	pc, err := net.ListenPacket("udp", f.addr)
	if err != nil {
		t.Fatal(err)
	}
	h := dns.HandlerFunc(f.serve)
	udp, tcp := &dns.Server{PacketConn: pc, Handler: h}, &dns.Server{Listener: ln, Handler: h}
	go func() { _ = udp.ActivateAndServe() }()
	go func() { _ = tcp.ActivateAndServe() }()
	t.Cleanup(func() { _ = udp.Shutdown(); _ = tcp.Shutdown() })
	return f
}

// configure changes the server's data under its lock (the server goroutines
// read it; network I/O is not a happens-before edge for the race detector).
func (f *fakeDNS) configure(setup func(*fakeDNS)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	setup(f)
}

// add must be called inside configure.
func (f *fakeDNS) add(rrs ...string) {
	for _, s := range rrs {
		rr, err := dns.NewRR(s)
		if err != nil {
			panic(err)
		}
		k := strings.ToLower(rr.Header().Name) + "|" + dns.TypeToString[rr.Header().Rrtype]
		f.records[k] = append(f.records[k], rr)
	}
}

func (f *fakeDNS) serve(w dns.ResponseWriter, r *dns.Msg) {
	f.mu.Lock()
	defer f.mu.Unlock()
	q := r.Question[0]
	name := strings.ToLower(q.Name)
	k := name + "|" + dns.TypeToString[q.Qtype]
	f.asked = append(f.asked, k)
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = f.recursive
	switch {
	case q.Qtype == dns.TypeAXFR:
		if !f.axfr[name] {
			m.Rcode = dns.RcodeRefused
			break
		}
		soa, _ := dns.NewRR(name + " 300 IN SOA ns. host. 1 7200 3600 1209600 300")
		m.Answer = append(m.Answer, soa)
		m.Answer = append(m.Answer, f.records[name+"|MX"]...)
	case f.servfail[k]:
		m.Rcode = dns.RcodeServerFailure
	case q.Qtype == dns.TypeSOA:
		if owner, ok := f.soaOwner[name]; ok {
			soa, _ := dns.NewRR(owner + " 300 IN SOA ns. host. 1 7200 3600 1209600 300")
			if strings.EqualFold(owner, name) {
				m.Answer = append(m.Answer, soa)
			} else {
				m.Ns = append(m.Ns, soa)
			}
		} else {
			m.Rcode = dns.RcodeNameError
		}
	default:
		rrs, known := f.records[k]
		switch {
		case known:
			m.Answer = rrs
		case f.hasName(name): // NODATA
		case name == "recursion-probe.example." && f.recursive:
			a, _ := dns.NewRR("recursion-probe.example. 60 IN A 192.0.2.1")
			m.Answer = append(m.Answer, a)
		default:
			m.Rcode = dns.RcodeNameError
		}
	}
	_ = w.WriteMsg(m)
}

func (f *fakeDNS) hasName(name string) bool {
	for k := range f.records {
		if strings.HasPrefix(k, name+"|") {
			return true
		}
	}
	_, ok := f.soaOwner[name]
	return ok
}

func dnsCheckTarget(t *testing.T, f *fakeDNS, host string) Target {
	t.Helper()
	_, port, _ := net.SplitHostPort(f.addr)
	client := probe.New(probe.Options{
		AllowPrivateHosts: []string{"127.0.0.1", host},
		HostRPS:           1000, HostBurst: 100, Timeout: 2 * time.Second,
		DNSServer: f.addr, DNSPort: port,
	})
	tg, err := NewTarget("https://"+host, client)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func runDNS(t *testing.T, f *fakeDNS, host string) ([]string, error) {
	t.Helper()
	fs, err := DNSEmail{RecursionProbe: "recursion-probe.example."}.Run(context.Background(), dnsCheckTarget(t, f, host))
	validateFindings(t, fs)
	ks := keysOf(fs)
	sort.Strings(ks)
	return ks, err
}

// apex zone "<host>" whose nameserver is the fake server itself (127.0.0.1).
func apex(f *fakeDNS, host string) {
	f.soaOwner[host+"."] = host + "."
	f.add(host + ". 300 IN NS 127.0.0.1.")
}

func TestDNSEmailCases(t *testing.T) {
	cases := []struct {
		name  string
		host  string
		setup func(f *fakeDNS)
		want  string
	}{
		{"well configured mail domain", "good.test", func(f *fakeDNS) {
			apex(f, "good.test")
			f.add(`good.test. 300 IN MX 10 mx.good.test.`, `good.test. 300 IN TXT "v=spf1 mx -all"`, `_dmarc.good.test. 300 IN TXT "v=DMARC1; p=reject"`)
		}, ""},
		{"MX without SPF", "nospf.test", func(f *fakeDNS) {
			apex(f, "nospf.test")
			f.add(`nospf.test. 300 IN MX 10 mx.nospf.test.`, `_dmarc.nospf.test. 300 IN TXT "v=DMARC1; p=reject"`)
		}, "spf_missing"},
		{"SPF +all", "plusall.test", func(f *fakeDNS) {
			apex(f, "plusall.test")
			f.add(`plusall.test. 300 IN MX 10 mx.plusall.test.`, `plusall.test. 300 IN TXT "v=spf1 mx +all"`, `_dmarc.plusall.test. 300 IN TXT "v=DMARC1; p=reject"`)
		}, "spf_allow_all"},
		{"SPF split mid-token across strings is ONE valid record", "chunked.test", func(f *fakeDNS) {
			apex(f, "chunked.test")
			f.add(`chunked.test. 300 IN MX 10 mx.chunked.test.`, `chunked.test. 300 IN TXT "v=spf1 ip4:192.0.2.0/24 inclu" "de:_spf.good.test -all"`,
				`_spf.good.test. 300 IN TXT "v=spf1 -all"`, `_dmarc.chunked.test. 300 IN TXT "v=DMARC1; p=reject"`)
		}, ""},
		{"two SPF records", "two.test", func(f *fakeDNS) {
			apex(f, "two.test")
			f.add(`two.test. 300 IN MX 10 mx.two.test.`, `two.test. 300 IN TXT "v=spf1 mx -all"`, `two.test. 300 IN TXT "v=spf1 a -all"`, `_dmarc.two.test. 300 IN TXT "v=DMARC1; p=reject"`)
		}, "spf_invalid"},
		{"no DMARC", "nodmarc.test", func(f *fakeDNS) {
			apex(f, "nodmarc.test")
			f.add(`nodmarc.test. 300 IN MX 10 mx.nodmarc.test.`, `nodmarc.test. 300 IN TXT "v=spf1 mx -all"`)
		}, "dmarc_missing"},
		{"DMARC p=none", "pnone.test", func(f *fakeDNS) {
			apex(f, "pnone.test")
			f.add(`pnone.test. 300 IN MX 10 mx.pnone.test.`, `pnone.test. 300 IN TXT "v=spf1 mx -all"`, `_dmarc.pnone.test. 300 IN TXT "v=DMARC1; p=none; rua=mailto:d@pnone.test"`)
		}, "dmarc_not_enforced"},
		{"null MX: accepts no mail, nothing to report", "nullmx.test", func(f *fakeDNS) {
			apex(f, "nullmx.test")
			f.add(`nullmx.test. 300 IN MX 0 .`)
		}, ""},
		{"no mail at all (no MX, no SPF)", "nomail.test", func(f *fakeDNS) {
			apex(f, "nomail.test")
			f.add(`nomail.test. 300 IN A 192.0.2.10`)
		}, ""},
		{"SPF lookup SERVFAIL is never 'missing'", "flaky.test", func(f *fakeDNS) {
			apex(f, "flaky.test")
			f.add(`flaky.test. 300 IN MX 10 mx.flaky.test.`, `_dmarc.flaky.test. 300 IN TXT "v=DMARC1; p=reject"`)
			f.servfail["flaky.test.|TXT"] = true
		}, ""},
		{"subdomain: DMARC from the organisational domain (sp applies)", "app.org.test", func(f *fakeDNS) {
			f.soaOwner["app.org.test."] = "org.test."
			f.add(`app.org.test. 300 IN MX 10 mx.org.test.`, `app.org.test. 300 IN TXT "v=spf1 mx -all"`, `_dmarc.org.test. 300 IN TXT "v=DMARC1; p=reject; sp=none"`)
		}, "dmarc_not_enforced"},
		{"open resolver and open zone transfer at the apex", "leaky.test", func(f *fakeDNS) {
			apex(f, "leaky.test")
			f.recursive = true
			f.axfr["leaky.test."] = true
			f.add(`leaky.test. 300 IN A 192.0.2.20`)
		}, "open_resolver,zone_transfer_open"},
	}
	for _, c := range cases {
		f := newFakeDNS(t)
		f.configure(c.setup)
		got, err := runDNS(t, f, c.host)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if strings.Join(got, ",") != c.want {
			t.Errorf("%s: got %v, want %q", c.name, got, c.want)
		}
	}
}

// A subdomain owner has not proven the parent zone: its nameservers are never
// asked anything (no recursion test, no AXFR), even if they are open.
func TestDNSEmailNeverTouchesParentZoneNameservers(t *testing.T) {
	f := newFakeDNS(t)
	f.configure(func(f *fakeDNS) {
		f.soaOwner["shop.parent.test."] = "parent.test."
		f.add(`parent.test. 300 IN NS 127.0.0.1.`, `shop.parent.test. 300 IN A 192.0.2.30`)
		f.recursive = true
		f.axfr["parent.test."] = true
	})
	got, err := runDNS(t, f, "shop.parent.test")
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v %v", got, err)
	}
	f.mu.Lock()
	asked := append([]string(nil), f.asked...)
	f.mu.Unlock()
	for _, q := range asked {
		if strings.HasSuffix(q, "|AXFR") || strings.HasPrefix(q, "recursion-probe.") || strings.HasSuffix(q, "|NS") {
			t.Fatalf("parent zone's nameserver was queried: %s", q)
		}
	}
}

func TestDNSEmailAllLookupsFailing(t *testing.T) {
	f := newFakeDNS(t)
	f.configure(func(f *fakeDNS) {
		for _, k := range []string{"down.test.|MX", "down.test.|TXT", "down.test.|SOA"} {
			f.servfail[k] = true
		}
	})
	_, err := runDNS(t, f, "down.test")
	if !errors.Is(err, errAllLookupsFailed) {
		t.Fatalf("want errAllLookupsFailed, got %v", err)
	}
}
