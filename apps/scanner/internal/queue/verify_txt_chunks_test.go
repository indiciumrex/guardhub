package queue

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
)

// A TXT record longer than 255 bytes is stored as several <character-string>s
// (RFC 1035 §3.3.14), and some DNS UIs split shorter values too. The
// ownership token must still match: the record's strings are concatenated
// without a separator (RFC 7208 §3.3). This is the "chunked TXT" defect of the
// websecurityscanner Python verifier (ADR-0004); here, through a real DNS
// server and Go's resolver, the joined value is what the verifier compares.
func TestVerifyDNSTXTSplitAcrossStrings(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if q.Qtype == dns.TypeTXT && q.Name == "_guardhub.verify.test." {
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{"guardhub-verify=ghv_split", "_in_two_strings"},
			})
		} else {
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", pc.LocalAddr().String())
	}}
	e := newEnv(t, []string{"verify.test"}, res)
	e.enqueue(t, verifyJob("https://verify.test", "ghv_split_in_two_strings"))
	e.processOne(t)
	if r := popReply(t, e, "gh:verify-reply:vjob"); !r.Verified || *r.Method != MethodDNSTXT {
		t.Fatalf("split TXT token not matched: %+v", r)
	}
}
