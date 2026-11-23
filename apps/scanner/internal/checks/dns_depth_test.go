package checks

import (
	"context"
	"crypto"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

var ddNow = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

func runDepth(t *testing.T, f *fakeDNS, host string) ([]string, error) {
	t.Helper()
	fs, err := DNSDepth{Now: func() time.Time { return ddNow }}.Run(context.Background(), dnsCheckTarget(t, f, host))
	validateFindings(t, fs)
	ks := keysOf(fs)
	sort.Strings(ks)
	return ks, err
}

// signedZone publishes a DNSKEY set signed by a fresh key, and (unless
// dsFromOtherKey) the matching DS. Returns nothing: it writes into f.
func signedZone(t *testing.T, f *fakeDNS, zone string, dsFromOtherKey bool, inception, expiration time.Time) {
	t.Helper()
	newKey := func() (*dns.DNSKEY, crypto.Signer) {
		k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: zone + ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
			Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
		priv, err := k.Generate(256)
		if err != nil {
			t.Fatal(err)
		}
		return k, priv.(crypto.Signer)
	}
	key, priv := newKey()
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: zone + ".", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		TypeCovered: dns.TypeDNSKEY, Algorithm: key.Algorithm, Labels: uint8(dns.CountLabel(zone + ".")),
		OrigTtl: 300, Expiration: uint32(expiration.Unix()), Inception: uint32(inception.Unix()),
		KeyTag: key.KeyTag(), SignerName: zone + "."}
	if err := sig.Sign(priv, []dns.RR{key}); err != nil {
		t.Fatal(err)
	}
	dsKey := key
	if dsFromOtherKey {
		dsKey, _ = newKey()
	}
	ds := dsKey.ToDS(dns.SHA256)
	f.configure(func(f *fakeDNS) {
		k := zone + ".|"
		f.records[k+"DNSKEY"] = []dns.RR{key, sig}
		f.records[k+"DS"] = []dns.RR{ds}
	})
}

// mailDomain: an apex zone that receives mail at mx.<host>, with CAA.
func mailDomain(f *fakeDNS, host string) {
	f.configure(func(f *fakeDNS) {
		apex(f, host)
		f.add(host+". 300 IN MX 10 mx."+host+".",
			host+". 300 IN CAA 0 issue \"letsencrypt.org\"",
			"mx."+host+". 300 IN A 192.0.2.25")
		f.soaOwner["mx."+host+"."] = host + "."
	})
}

func rsaKeyB64(bits int, pkcs1 bool) string {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.Add(n, big.NewInt(1))
	inner, _ := asn1.Marshal(struct {
		N *big.Int
		E int
	}{n, 65537})
	if pkcs1 {
		return base64.StdEncoding.EncodeToString(inner)
	}
	spki, _ := asn1.Marshal(struct {
		Algorithm struct {
			OID    asn1.ObjectIdentifier
			Params asn1.RawValue
		}
		Key asn1.BitString
	}{struct {
		OID    asn1.ObjectIdentifier
		Params asn1.RawValue
	}{oidRSAEncryption, asn1.RawValue{Tag: asn1.TagNull}}, asn1.BitString{Bytes: inner, BitLength: len(inner) * 8}})
	return base64.StdEncoding.EncodeToString(spki)
}

func TestDNSDepthCleanMailDomain(t *testing.T) {
	f := newFakeDNS(t)
	mailDomain(f, "good.test")
	signedZone(t, f, "good.test", false, ddNow.Add(-time.Hour), ddNow.Add(24*time.Hour))
	f.configure(func(f *fakeDNS) {
		f.add(`default._domainkey.good.test. 300 IN TXT "v=DKIM1; k=rsa; p=`+rsaKeyB64(2048, false)+`"`,
			`selector2._domainkey.good.test. 300 IN TXT "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="`)
	})
	// MTA-STS is absent here: the only finding is that.
	ks, err := runDepth(t, f, "good.test")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ks, ",") != "mta_sts_missing" {
		t.Fatalf("got %v", ks)
	}
}

func TestDNSDepthDNSSEC(t *testing.T) {
	cases := []struct {
		name      string
		otherDS   bool
		inc, exp  time.Time
		wantKey   string
		wantParam string
	}{
		{"valid chain", false, ddNow.Add(-time.Hour), ddNow.Add(time.Hour), "", ""},
		{"DS of another key", true, ddNow.Add(-time.Hour), ddNow.Add(time.Hour), "dnssec_broken", "ds_mismatch"},
		{"expired signature", false, ddNow.Add(-48 * time.Hour), ddNow.Add(-24 * time.Hour), "dnssec_broken", "signature_expired"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeDNS(t)
			f.configure(func(f *fakeDNS) {
				apex(f, "sec.test")
				f.add(`sec.test. 300 IN CAA 0 issue "letsencrypt.org"`)
			})
			signedZone(t, f, "sec.test", tc.otherDS, tc.inc, tc.exp)
			fs, err := DNSDepth{Now: func() time.Time { return ddNow }}.Run(context.Background(), dnsCheckTarget(t, f, "sec.test"))
			if err != nil {
				t.Fatal(err)
			}
			validateFindings(t, fs)
			if tc.wantKey == "" {
				requireKeys(t, fs)
				return
			}
			requireKeys(t, fs, tc.wantKey)
			if got := findKey(t, fs, tc.wantKey).Params["reason"]; got != tc.wantParam {
				t.Fatalf("reason %q, want %q", got, tc.wantParam)
			}
		})
	}
}

func TestDNSDepthUnsignedAndUnknownAreSilent(t *testing.T) {
	f := newFakeDNS(t)
	f.configure(func(f *fakeDNS) {
		apex(f, "plain.test")
		f.add(`plain.test. 300 IN CAA 0 issue "letsencrypt.org"`)
	})
	ks, err := runDepth(t, f, "plain.test")
	if err != nil || len(ks) != 0 {
		t.Fatalf("unsigned zone: %v %v", ks, err)
	}
	// SERVFAIL on the DS lookup and on CAA: nothing may be concluded.
	f.configure(func(f *fakeDNS) {
		f.servfail["plain.test.|DS"] = true
		delete(f.records, "plain.test.|CAA")
		f.servfail["plain.test.|CAA"] = true
	})
	ks, err = runDepth(t, f, "plain.test")
	if err != nil || len(ks) != 0 {
		t.Fatalf("lookup failures: %v %v", ks, err)
	}
}

func TestDNSDepthCAAClimb(t *testing.T) {
	f := newFakeDNS(t)
	f.configure(func(f *fakeDNS) {
		apex(f, "corp.test")
		f.soaOwner["www.corp.test."] = "corp.test."
		f.add("www.corp.test. 300 IN A 192.0.2.10")
	})
	ks, _ := runDepth(t, f, "www.corp.test")
	if strings.Join(ks, ",") != "caa_missing" {
		t.Fatalf("no CAA anywhere: %v", ks)
	}
	// a CAA record at the registrable domain covers its subdomains
	f.configure(func(f *fakeDNS) { f.add(`corp.test. 300 IN CAA 0 issue "pki.goog"`) })
	ks, _ = runDepth(t, f, "www.corp.test")
	if len(ks) != 0 {
		t.Fatalf("inherited CAA: %v", ks)
	}
}

func TestDNSDepthMTASTSRecordStates(t *testing.T) {
	f := newFakeDNS(t)
	mailDomain(f, "m.test")
	f.configure(func(f *fakeDNS) {
		f.add(`_mta-sts.m.test. 300 IN TXT "v=STSv1; id=20261123"`)
	})
	// the policy host does not exist: broken policy; TLS-RPT is missing too
	fs, err := DNSDepth{Now: func() time.Time { return ddNow }, MTASTSPort: "1"}.Run(context.Background(), dnsCheckTarget(t, f, "m.test"))
	if err != nil {
		t.Fatal(err)
	}
	validateFindings(t, fs)
	requireKeys(t, fs, "mta_sts_policy_broken", "tlsrpt_missing")
	if r := findKey(t, fs, "mta_sts_policy_broken").Params["reason"]; r != "https_unreachable" {
		t.Fatalf("reason %q", r)
	}
	f.configure(func(f *fakeDNS) { f.add(`_smtp._tls.m.test. 300 IN TXT "v=TLSRPTv1; rua=mailto:tls@m.test"`) })
	fs, _ = DNSDepth{Now: func() time.Time { return ddNow }, MTASTSPort: "1"}.Run(context.Background(), dnsCheckTarget(t, f, "m.test"))
	requireKeys(t, fs, "mta_sts_policy_broken")

	// two STSv1 records: senders ignore MTA-STS -> missing
	f.configure(func(f *fakeDNS) { f.add(`_mta-sts.m.test. 300 IN TXT "v=STSv1; id=2"`) })
	ks, _ := runDepth(t, f, "m.test")
	if strings.Join(ks, ",") != "mta_sts_missing" {
		t.Fatalf("two records: %v", ks)
	}
}

func TestDNSDepthNoMailNoMailFindings(t *testing.T) {
	f := newFakeDNS(t)
	f.configure(func(f *fakeDNS) {
		apex(f, "nomail.test")
		f.add("nomail.test. 300 IN MX 0 .", `nomail.test. 300 IN CAA 0 issue "letsencrypt.org"`)
	})
	ks, err := runDepth(t, f, "nomail.test")
	if err != nil || len(ks) != 0 {
		t.Fatalf("null MX: %v %v", ks, err)
	}
}

func TestDNSDepthDANE(t *testing.T) {
	f := newFakeDNS(t)
	mailDomain(f, "d.test")
	f.configure(func(f *fakeDNS) {
		f.add(`_mta-sts.d.test. 300 IN TXT "not sts"`,
			"_25._tcp.mx.d.test. 300 IN TLSA 3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
		f.soaOwner["_25._tcp.mx.d.test."] = "d.test."
	})
	ks, _ := runDepth(t, f, "d.test")
	if strings.Join(ks, ",") != "dane_unsigned,mta_sts_missing" {
		t.Fatalf("unsigned DANE: %v", ks)
	}
	signedZone(t, f, "d.test", false, ddNow.Add(-time.Hour), ddNow.Add(time.Hour))
	ks, _ = runDepth(t, f, "d.test")
	if strings.Join(ks, ",") != "mta_sts_missing" {
		t.Fatalf("signed DANE: %v", ks)
	}
}

func TestDNSDepthDKIM(t *testing.T) {
	f := newFakeDNS(t)
	f.configure(func(f *fakeDNS) {
		apex(f, "k.test")
		f.add(`k.test. 300 IN CAA 0 issue "letsencrypt.org"`,
			`default._domainkey.k.test. 300 IN TXT "v=DKIM1; k=rsa; p=`+rsaKeyB64(1024, false)+`"`,
			`selector1._domainkey.k.test. 300 IN TXT "v=DKIM1; p=`+rsaKeyB64(512, true)+`"`,
			`selector2._domainkey.k.test. 300 IN TXT "v=DKIM1; p="`,                    // revoked
			`s1._domainkey.k.test. 300 IN TXT "v=DKIM1; p=`+rsaKeyB64(1024, false)+`"`) // same key as default
	})
	fs, err := DNSDepth{Now: func() time.Time { return ddNow }}.Run(context.Background(), dnsCheckTarget(t, f, "k.test"))
	if err != nil {
		t.Fatal(err)
	}
	validateFindings(t, fs)
	requireKeys(t, fs, "dkim_weak_key", "dkim_key_too_short")
	if b := findKey(t, fs, "dkim_weak_key").Params; b["bits"] != "1024" || b["selector"] != "default" {
		t.Fatalf("weak: %v", b)
	}
	if b := findKey(t, fs, "dkim_key_too_short").Params; b["bits"] != "512" || b["selector"] != "selector1" {
		t.Fatalf("short: %v", b)
	}
}

func TestMTASTSPolicyParsing(t *testing.T) {
	pol, problem := parseMTASTSPolicy("version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmx: *.mx.example.net\r\nmax_age: 604800\r\n")
	if problem != "" || pol.mode != "enforce" {
		t.Fatalf("valid policy: %q %+v", problem, pol)
	}
	for mx, want := range map[string]bool{
		"mail.example.com": true, "MAIL.example.com.": true, "a.mx.example.net": true,
		"mx.example.net": false, "a.b.mx.example.net": false, "other.example.com": false,
	} {
		if got := pol.matches(mx); got != want {
			t.Errorf("matches(%q) = %v", mx, got)
		}
	}
	for _, bad := range []string{
		"version: STSv2\nmode: enforce\nmx: a\nmax_age: 1",
		"version: STSv1\nmode: strict\nmx: a\nmax_age: 1",
		"version: STSv1\nmode: enforce\nmax_age: 1",
		"version: STSv1\nmode: enforce\nmx: a\nmax_age: 99999999",
	} {
		if _, p := parseMTASTSPolicy(bad); p == "" {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, p := parseMTASTSPolicy("version: STSv1\nmode: none\nmax_age: 86400"); p != "" {
		t.Errorf("mode none without mx: %q", p)
	}
}

func TestMTASTSRecord(t *testing.T) {
	if r, _ := mtaSTSRecord([]string{"v=STSv1; id=2019-04-29;"}); r != "" {
		t.Error("id with non-alphanumerics accepted")
	}
	if r, _ := mtaSTSRecord([]string{"v=spf1 -all", "v=STSv1; id=abc123"}); r == "" {
		t.Error("valid record among other TXT rejected")
	}
}

// A lost UDP answer is retried once; a lookup that never answers is unknown
// (no finding derived from it) and never fails the whole check.
func TestDNSDepthLostDatagrams(t *testing.T) {
	f := newFakeDNS(t)
	f.configure(func(f *fakeDNS) {
		apex(f, "lossy.test")
		f.add("lossy.test. 300 IN MX 10 mx.lossy.test.")
		f.drop["lossy.test.|CAA"] = 1 // first CAA answer lost, the retry gets NODATA
	})
	ks, err := runDepth(t, f, "lossy.test")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ks, ",") != "caa_missing,mta_sts_missing" {
		t.Fatalf("one lost answer: %v", ks)
	}
	f.configure(func(f *fakeDNS) { f.drop["lossy.test.|CAA"] = -1 })
	ks, err = runDepth(t, f, "lossy.test")
	if err != nil {
		t.Fatalf("a lookup that never answers failed the check: %v", err)
	}
	if strings.Join(ks, ",") != "mta_sts_missing" {
		t.Fatalf("unanswered CAA must stay unknown: %v", ks)
	}
}
