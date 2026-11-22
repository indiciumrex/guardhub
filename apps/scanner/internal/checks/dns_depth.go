package checks

// dns_depth (ADR-0007): DNS and e-mail transport hardening beyond dns_email.
// Passive: record lookups through the recursive resolver (public data that
// any resolver or mail server reads) and, only when the domain publishes an
// MTA-STS record, one TLS handshake with and one GET of
// https://mta-sts.<host>/.well-known/mta-sts.txt, the file every sending mail
// server fetches (RFC 8461). Nothing is sent to the domain's mail servers.
//
//   - dnssec_broken: the parent publishes DS records for the host's zone, but
//     no DNSKEY matches them, or no matching key validly signs the DNSKEY set.
//     Validating resolvers (Google, Cloudflare, most ISPs) then refuse to
//     resolve the domain. Unsigned zones are not reported (dns_email doc).
//   - caa_missing: no CAA record from the host up to its registrable domain,
//     so every public CA may issue certificates for it (RFC 8659).
//   - mta_sts_missing / mta_sts_policy_broken / mta_sts_mx_mismatch /
//     mta_sts_testing: for a host that receives mail (MX, not null MX), the
//     state of its MTA-STS policy.
//   - tlsrpt_missing: MTA-STS is published but no TLS-RPT address receives
//     the reports of failed TLS deliveries (RFC 8460).
//   - dane_unsigned: an MX host publishes TLSA records (DANE, RFC 7672) but
//     its zone is not DNSSEC-signed, so senders ignore them.
//   - dkim_weak_key / dkim_key_too_short: an RSA DKIM key under one of a fixed
//     list of widely used selectors is shorter than 2048 / 1024 bits. Absence
//     of DKIM is never reported: without the real selector it is unprovable.
//
// A failed lookup (SERVFAIL, timeout) is never turned into "missing".

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"mime"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
)

// dkimSelectors: selectors used by the large mail providers and common
// defaults (Google Workspace, Microsoft 365, Mailchimp, Resend, cPanel, ...).
// A key found there is a fact; a key not found proves nothing.
var dkimSelectors = []string{"default", "dkim", "google", "k1", "k2", "mail", "resend", "s1", "s2", "selector1", "selector2", "smtp"}

const (
	dkimMinBits    = 1024 // RFC 8301 §3.2: verifiers MUST NOT accept shorter keys
	dkimGoodBits   = 2048 // RFC 8301 §3.2: signers SHOULD use at least 2048 bits
	maxDANEMXHosts = 4
	// mtaSTSMaxAge: RFC 8461 §3.2 caps max_age at 31557600 seconds.
	mtaSTSMaxAge = 31557600
)

var mtaSTSIDRe = regexp.MustCompile(`^[A-Za-z0-9]{1,32}$`)

// DNSDepth implements the dns_depth check.
type DNSDepth struct {
	// Now returns the current time (time.Now in production).
	Now func() time.Time
	// Roots verifies the MTA-STS policy host's certificate; nil means the
	// system roots.
	Roots *x509.CertPool
	// MTASTSPort is the HTTPS port of the policy host (default "443"; tests).
	MTASTSPort string
}

// ID implements Check.
func (DNSDepth) ID() string { return evidence.CheckDnsDepth }

func (c DNSDepth) now() time.Time {
	if c.Now == nil {
		return time.Now()
	}
	return c.Now()
}

// Run implements Check.
func (c DNSDepth) Run(ctx context.Context, t Target) ([]evidence.Finding, error) {
	host := t.Host()
	if net.ParseIP(strings.Trim(host, "[]")) != nil {
		return nil, nil // an IP address has no DNS records of its own
	}
	d := &dnsLookups{t: t}
	var out []evidence.Finding
	add := func(key string, params map[string]string, loc, payload string) {
		out = append(out, evidence.New(c.ID(), key, params, evidence.KindDnsRecord, loc, payload))
	}

	// 1. DNSSEC of the zone that holds host.
	if zone, err := d.zoneOf(ctx, host); err != nil {
		return nil, err
	} else if zone != "" {
		reason, payload, err := c.dnssec(ctx, d, zone)
		if err != nil {
			return nil, err
		}
		if reason != "" {
			add("dnssec_broken", map[string]string{"domain": zone, "reason": reason}, "DNSKEY "+zone, payload)
		}
	}

	// 2. CAA, from host up to its registrable domain (RFC 8659 §3).
	if _, payload, missing, err := c.caa(ctx, d, host); err != nil {
		return out, err
	} else if missing {
		add("caa_missing", map[string]string{"domain": host}, "CAA "+host, payload)
	}

	// 3. Mail transport: only for a host that receives mail.
	mx, mxSt, err := d.query(ctx, host, dns.TypeMX)
	if err != nil {
		return out, err
	}
	if nullMX, hasMX := classifyMX(mx); mxSt == lookupOK && hasMX && !nullMX {
		found, err := c.mailTransport(ctx, t, d, host, mxHosts(mx))
		if err != nil {
			return out, err
		}
		out = append(out, found...)
	}

	// 4. DKIM keys under well-known selectors.
	found, err := c.dkim(ctx, d, host)
	if err != nil {
		return out, err
	}
	out = append(out, found...)

	if d.answered == 0 && d.asked > 0 {
		return out, fmt.Errorf("dns_depth: every DNS lookup failed")
	}
	return out, nil
}

// ---- DNSSEC ----

// zoneOf returns the apex of the zone that holds name ("" when unknown). A
// name that is an alias (CNAME) lives in its parent's zone.
func (d *dnsLookups) zoneOf(ctx context.Context, name string) (string, error) {
	for range 2 {
		resp, st, err := d.queryCD(ctx, name, dns.TypeSOA)
		if err != nil || st == lookupUnknown || resp == nil {
			return "", err
		}
		alias := false
		for _, rr := range resp.Answer {
			switch v := rr.(type) {
			case *dns.SOA:
				if strings.EqualFold(v.Hdr.Name, dns.Fqdn(name)) {
					return strings.TrimSuffix(strings.ToLower(v.Hdr.Name), "."), nil
				}
			case *dns.CNAME:
				if strings.EqualFold(v.Hdr.Name, dns.Fqdn(name)) {
					alias = true
				}
			}
		}
		if alias {
			parent, ok := parentName(name)
			if !ok {
				return "", nil
			}
			name = parent
			continue
		}
		for _, rr := range resp.Ns { // NODATA / NXDOMAIN carry the zone's SOA
			if soa, ok := rr.(*dns.SOA); ok && dns.IsSubDomain(soa.Hdr.Name, dns.Fqdn(name)) {
				return strings.TrimSuffix(strings.ToLower(soa.Hdr.Name), "."), nil
			}
		}
		return "", nil
	}
	return "", nil
}

func parentName(name string) (string, bool) {
	_, rest, ok := strings.Cut(strings.TrimSuffix(name, "."), ".")
	return rest, ok && strings.Contains(rest, ".")
}

// supportedDS: digest types and algorithms GuardHub can recompute and verify.
var (
	supportedDSDigest  = map[uint8]bool{dns.SHA1: true, dns.SHA256: true, dns.SHA384: true}
	supportedDNSSECAlg = map[uint8]bool{
		dns.RSASHA1: true, dns.RSASHA1NSEC3SHA1: true, dns.RSASHA256: true, dns.RSASHA512: true,
		dns.ECDSAP256SHA256: true, dns.ECDSAP384SHA384: true, dns.ED25519: true,
	}
)

// dnssec returns a reason when zone's chain of trust from its parent is
// broken; "" when it is fine, unsigned, or cannot be judged.
func (c DNSDepth) dnssec(ctx context.Context, d *dnsLookups, zone string) (reason, payload string, err error) {
	dsResp, st, err := d.queryCD(ctx, zone, dns.TypeDS)
	if err != nil || st != lookupOK {
		return "", "", err
	}
	var dss []*dns.DS
	for _, rr := range dsResp.Answer {
		if ds, ok := rr.(*dns.DS); ok && strings.EqualFold(ds.Hdr.Name, dns.Fqdn(zone)) &&
			supportedDSDigest[ds.DigestType] && supportedDNSSECAlg[ds.Algorithm] {
			dss = append(dss, ds)
		}
	}
	if len(dss) == 0 {
		return "", "", nil // unsigned (or only algorithms we cannot check)
	}
	keyResp, st, err := d.queryCD(ctx, zone, dns.TypeDNSKEY)
	if err != nil || st == lookupUnknown || keyResp == nil {
		return "", "", err
	}
	var keys []dns.RR
	var sigs []*dns.RRSIG
	for _, rr := range keyResp.Answer {
		if !strings.EqualFold(rr.Header().Name, dns.Fqdn(zone)) {
			continue
		}
		switch v := rr.(type) {
		case *dns.DNSKEY:
			keys = append(keys, v)
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeDNSKEY {
				sigs = append(sigs, v)
			}
		}
	}
	dsText := make([]string, 0, len(dss))
	for _, ds := range dss {
		dsText = append(dsText, fmt.Sprintf("DS %d %d %d %s", ds.KeyTag, ds.Algorithm, ds.DigestType, strings.ToUpper(ds.Digest)))
	}
	base := fmt.Sprintf("Zone: %s\nDS records at the parent: %s", zone, strings.Join(dsText, "; "))
	if len(keys) == 0 {
		return "no_dnskey", base + "\nDNSKEY records in the zone: none", nil
	}
	var matched []*dns.DNSKEY
	var keyText []string
	for _, rr := range keys {
		k := rr.(*dns.DNSKEY)
		keyText = append(keyText, fmt.Sprintf("DNSKEY flags %d alg %d tag %d", k.Flags, k.Algorithm, k.KeyTag()))
		for _, ds := range dss {
			if k.KeyTag() == ds.KeyTag && k.Algorithm == ds.Algorithm {
				if got := k.ToDS(ds.DigestType); got != nil && strings.EqualFold(got.Digest, ds.Digest) {
					matched = append(matched, k)
					break
				}
			}
		}
	}
	base += "\nDNSKEY records in the zone: " + strings.Join(keyText, "; ")
	if len(matched) == 0 {
		return "ds_mismatch", base + "\nNo DNSKEY matches a DS record: validating resolvers reject the zone.", nil
	}
	if len(sigs) == 0 {
		return "", "", nil // the resolver strips signatures: cannot judge
	}
	now := c.now()
	expired := false
	for _, k := range matched {
		for _, sig := range sigs {
			if sig.KeyTag != k.KeyTag() || sig.Algorithm != k.Algorithm {
				continue
			}
			if sig.Verify(k, keys) != nil {
				continue
			}
			if sig.ValidityPeriod(now) {
				return "", "", nil
			}
			expired = true
		}
	}
	if expired {
		return "signature_expired", base + "\nThe DNSKEY set's signature by the DS-matched key is outside its validity period.", nil
	}
	return "dnskey_not_signed", base + "\nNo valid signature over the DNSKEY set by a DS-matched key.", nil
}

// ---- CAA ----

func (c DNSDepth) caa(ctx context.Context, d *dnsLookups, host string) (reg, payload string, missing bool, err error) {
	reg, perr := publicsuffix.EffectiveTLDPlusOne(host)
	if perr != nil {
		return "", "", false, nil
	}
	var checked []string
	for name := host; ; {
		resp, st, err := d.query(ctx, name, dns.TypeCAA)
		if err != nil || st == lookupUnknown {
			return "", "", false, err
		}
		checked = append(checked, name)
		if st == lookupOK {
			for _, rr := range resp.Answer {
				if _, ok := rr.(*dns.CAA); ok {
					return "", "", false, nil
				}
			}
		}
		if name == reg {
			break
		}
		parent, ok := parentName(name)
		if !ok {
			break
		}
		name = parent
	}
	return reg, "CAA lookups (none found): " + strings.Join(checked, ", ") +
		"\nWithout CAA, any public certificate authority may issue certificates for this domain.", true, nil
}

// ---- MTA-STS, TLS-RPT, DANE ----

func (c DNSDepth) mailTransport(ctx context.Context, t Target, d *dnsLookups, host string, mxs []string) ([]evidence.Finding, error) {
	var out []evidence.Finding
	add := func(key string, params map[string]string, kind evidence.Kind, loc, payload string) {
		out = append(out, evidence.New(c.ID(), key, params, kind, loc, payload))
	}
	mxList := evidence.Truncate(strings.Join(mxs, ", "), 300)

	txts, st, err := d.txt(ctx, "_mta-sts."+host)
	if err != nil {
		return nil, err
	}
	if st != lookupUnknown {
		record, why := mtaSTSRecord(txts)
		if record == "" {
			add("mta_sts_missing", map[string]string{"domain": host}, evidence.KindDnsRecord, "TXT _mta-sts."+host,
				"MX records: "+mxList+"\n"+why)
		} else {
			pol, reason, payload, err := c.fetchPolicy(ctx, t, host)
			if err != nil {
				return nil, err
			}
			polURL := "https://mta-sts." + host + "/.well-known/mta-sts.txt"
			switch {
			case reason != "":
				add("mta_sts_policy_broken", map[string]string{"domain": host, "reason": reason}, evidence.KindHttpResponse, polURL,
					"TXT _mta-sts."+host+": "+evidence.Truncate(record, 200)+"\n"+payload)
			case pol.mode == "testing":
				add("mta_sts_testing", map[string]string{"domain": host}, evidence.KindHttpResponse, polURL, payload)
			case pol.mode == "enforce":
				var unmatched []string
				for _, mx := range mxs {
					if !pol.matches(mx) {
						unmatched = append(unmatched, mx)
					}
				}
				if len(unmatched) > 0 {
					add("mta_sts_mx_mismatch", map[string]string{"domain": host, "mx": evidence.Truncate(strings.Join(unmatched, ", "), 200)},
						evidence.KindHttpResponse, polURL, payload+"\nMX records: "+mxList+"\nNot covered by the policy: "+strings.Join(unmatched, ", "))
				}
			}
			rpt, st, err := d.txt(ctx, "_smtp._tls."+host)
			if err != nil {
				return nil, err
			}
			if st != lookupUnknown && !hasTLSRPT(rpt) {
				add("tlsrpt_missing", map[string]string{"domain": host}, evidence.KindDnsRecord, "TXT _smtp._tls."+host,
					"MTA-STS record: "+evidence.Truncate(record, 200)+"\nNo TXT record starting with v=TLSRPTv1 at _smtp._tls."+host+".")
			}
		}
	}

	for i, mx := range mxs {
		if i == maxDANEMXHosts {
			break
		}
		name := "_25._tcp." + mx
		resp, st, err := d.queryCD(ctx, name, dns.TypeTLSA)
		if err != nil {
			return nil, err
		}
		if st != lookupOK || !hasRR[*dns.TLSA](resp, name) {
			continue
		}
		zone, err := d.zoneOf(ctx, mx)
		if err != nil {
			return nil, err
		}
		if zone == "" {
			continue
		}
		dsResp, st, err := d.queryCD(ctx, zone, dns.TypeDS)
		if err != nil {
			return nil, err
		}
		if st == lookupOK && !hasRR[*dns.DS](dsResp, zone) {
			add("dane_unsigned", map[string]string{"mx": mx}, evidence.KindDnsRecord, "TLSA "+name,
				fmt.Sprintf("TLSA records at %s: present\nZone of the MX host: %s\nDS records for %s at its parent: none (the zone is not DNSSEC-signed, so senders ignore the TLSA records)", name, zone, zone))
		}
	}
	return out, nil
}

func hasRR[T dns.RR](m *dns.Msg, owner string) bool {
	if m == nil {
		return false
	}
	for _, rr := range m.Answer {
		if _, ok := rr.(T); ok && strings.EqualFold(rr.Header().Name, dns.Fqdn(owner)) {
			return true
		}
	}
	return false
}

// mtaSTSRecord applies RFC 8461 §3.1: exactly one record beginning with
// "v=STSv1;" that has a valid id. Otherwise senders treat the domain as having
// no policy, and why says so.
func mtaSTSRecord(txts []string) (record, why string) {
	var sts []string
	for _, r := range txts {
		if strings.HasPrefix(r, "v=STSv1;") || r == "v=STSv1" {
			sts = append(sts, r)
		}
	}
	switch len(sts) {
	case 0:
		return "", "No TXT record starting with v=STSv1 at _mta-sts (no MTA-STS policy)."
	case 1:
	default:
		return "", fmt.Sprintf("%d TXT records start with v=STSv1 at _mta-sts: senders must then ignore MTA-STS (RFC 8461 §3.1).", len(sts))
	}
	for _, field := range strings.Split(sts[0], ";") {
		k, v, _ := strings.Cut(strings.TrimSpace(field), "=")
		if k == "id" && mtaSTSIDRe.MatchString(v) {
			return sts[0], ""
		}
	}
	return "", "TXT _mta-sts: " + evidence.Truncate(sts[0], 200) + "\nThe record has no valid id= field, so senders ignore it (RFC 8461 §3.1)."
}

func hasTLSRPT(txts []string) bool {
	for _, r := range txts {
		if strings.HasPrefix(r, "v=TLSRPTv1;") || r == "v=TLSRPTv1" {
			return true
		}
	}
	return false
}

type mtaSTSPolicy struct {
	mode string
	mx   []string
}

// matches applies RFC 8461 §4.1: an exact name, or "*.example.com" matching
// exactly one extra leftmost label.
func (p mtaSTSPolicy) matches(mx string) bool {
	mx = strings.ToLower(strings.TrimSuffix(mx, "."))
	for _, pat := range p.mx {
		pat = strings.ToLower(strings.TrimSuffix(pat, "."))
		if suffix, ok := strings.CutPrefix(pat, "*."); ok {
			label, rest, found := strings.Cut(mx, ".")
			if found && label != "" && rest == suffix {
				return true
			}
		} else if pat == mx {
			return true
		}
	}
	return false
}

// fetchPolicy reads https://mta-sts.<host>/.well-known/mta-sts.txt as a
// sending mail server does (RFC 8461 §3.3): valid certificate for the policy
// host, no redirects, HTTP 200, text/plain. reason is "" for a valid policy.
func (c DNSDepth) fetchPolicy(ctx context.Context, t Target, host string) (pol mtaSTSPolicy, reason, payload string, err error) {
	ph := "mta-sts." + host
	port := c.MTASTSPort
	if port == "" {
		port = "443"
	}
	res, err := t.Probe.InspectTLS(ctx, ph, port, probe.TLSOptions{})
	if err != nil {
		if isFatal(ctx, err) {
			return pol, "", "", err
		}
		return pol, "https_unreachable", "HTTPS connection to " + ph + " failed: " + evidence.Truncate(err.Error(), 200), nil
	}
	if len(res.PeerCertificates) == 0 {
		return pol, "https_unreachable", "HTTPS connection to " + ph + ": no certificate", nil
	}
	inter := x509.NewCertPool()
	for _, cert := range res.PeerCertificates[1:] {
		inter.AddCert(cert)
	}
	if _, verr := res.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: ph, Roots: c.Roots, Intermediates: inter, CurrentTime: c.now()}); verr != nil {
		return pol, "certificate_invalid", "Certificate of " + ph + " is not valid for it: " + evidence.Truncate(verr.Error(), 200), nil
	}
	hostPort := ph
	if port != "443" {
		hostPort += ":" + port
	}
	u := "https://" + hostPort + "/.well-known/mta-sts.txt"
	resp, err := t.Probe.GetNoFollow(ctx, u)
	if err != nil {
		if isFatal(ctx, err) {
			return pol, "", "", err
		}
		return pol, "https_unreachable", "GET " + u + " failed: " + evidence.Truncate(err.Error(), 200), nil
	}
	head := fmt.Sprintf("GET %s -> HTTP %d", u, resp.StatusCode)
	if resp.StatusCode != 200 {
		return pol, "http_status", head + " (senders need 200; redirects are not followed)", nil
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "text/plain" {
		return pol, "content_type", head + "\nContent-Type: " + evidence.Truncate(resp.Header.Get("Content-Type"), 100) + " (must be text/plain)", nil
	}
	body := evidence.Truncate(string(resp.Body), 1000)
	pol, problem := parseMTASTSPolicy(string(resp.Body))
	payload = head + "\nPolicy:\n" + body
	if problem != "" {
		return pol, "policy_invalid", payload + "\nProblem: " + problem, nil
	}
	return pol, "", payload, nil
}

// parseMTASTSPolicy parses the policy body (RFC 8461 §3.2): "key: value"
// lines; version STSv1, mode enforce|testing|none, max_age, and at least one
// mx unless mode is none.
func parseMTASTSPolicy(body string) (mtaSTSPolicy, string) {
	var pol mtaSTSPolicy
	fields := map[string]string{}
	for _, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k == "mx" {
			pol.mx = append(pol.mx, v)
			continue
		}
		if _, dup := fields[k]; !dup {
			fields[k] = v
		}
	}
	if fields["version"] != "STSv1" {
		return pol, "version is not STSv1"
	}
	pol.mode = fields["mode"]
	if pol.mode != "enforce" && pol.mode != "testing" && pol.mode != "none" {
		return pol, "mode must be enforce, testing or none"
	}
	age, err := strconv.Atoi(fields["max_age"])
	if err != nil || age < 0 || age > mtaSTSMaxAge {
		return pol, "max_age missing or out of range"
	}
	if pol.mode != "none" && len(pol.mx) == 0 {
		return pol, "no mx line"
	}
	return pol, ""
}

// ---- DKIM ----

func (c DNSDepth) dkim(ctx context.Context, d *dnsLookups, host string) ([]evidence.Finding, error) {
	var out []evidence.Finding
	seen := map[string]bool{}
	for _, sel := range dkimSelectors {
		name := sel + "._domainkey." + host
		txts, st, err := d.txt(ctx, name)
		if err != nil {
			return out, err
		}
		if st != lookupOK {
			continue
		}
		for _, rec := range txts {
			p, ok := dkimRSAKey(rec)
			if !ok || seen[p] {
				continue
			}
			seen[p] = true
			bits, ok := rsaKeyBits(p)
			if !ok || bits >= dkimGoodBits {
				continue
			}
			key := "dkim_weak_key"
			if bits < dkimMinBits {
				key = "dkim_key_too_short"
			}
			out = append(out, evidence.New(c.ID(), key, map[string]string{"selector": sel, "bits": strconv.Itoa(bits)},
				evidence.KindDnsRecord, "TXT "+name,
				fmt.Sprintf("DKIM record at %s: %s\nRSA key size: %d bits", name, evidence.Truncate(rec, 120), bits)))
		}
	}
	return out, nil
}

// dkimRSAKey returns the p= value of a DKIM key record (RFC 6376 §3.6.1) whose
// key type is RSA (the default). Revoked keys (empty p=) are skipped.
func dkimRSAKey(rec string) (string, bool) {
	tags := map[string]string{}
	for _, field := range strings.Split(rec, ";") {
		k, v, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		tags[strings.TrimSpace(k)] = strings.Join(strings.Fields(v), "")
	}
	if v, ok := tags["v"]; ok && v != "DKIM1" {
		return "", false
	}
	if k, ok := tags["k"]; ok && !strings.EqualFold(k, "rsa") {
		return "", false
	}
	p, ok := tags["p"]
	return p, ok && p != ""
}

// rsaKeyBits reads the modulus size of a base64 RSA public key in either
// SubjectPublicKeyInfo or PKCS#1 form. Parsed by hand so that the size of a
// key the crypto library refuses (below 1024 bits) can still be reported.
func rsaKeyBits(p string) (int, bool) {
	der, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		return 0, false
	}
	var spki struct {
		Algorithm struct {
			OID    asn1.ObjectIdentifier
			Params asn1.RawValue `asn1:"optional"`
		}
		Key asn1.BitString
	}
	inner := der
	if rest, err := asn1.Unmarshal(der, &spki); err == nil && len(rest) == 0 {
		if !spki.Algorithm.OID.Equal(oidRSAEncryption) {
			return 0, false
		}
		inner = spki.Key.Bytes
	}
	var pk struct {
		N *big.Int
		E int
	}
	if rest, err := asn1.Unmarshal(inner, &pk); err != nil || len(rest) != 0 || pk.N == nil || pk.N.Sign() <= 0 {
		return 0, false
	}
	return pk.N.BitLen(), true
}

var oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}

// queryCD is query with DNSSEC checking disabled (see probe.DNSQueryCD).
func (d *dnsLookups) queryCD(ctx context.Context, name string, qtype uint16) (*dns.Msg, lookupStatus, error) {
	d.asked++
	resp, err := d.t.Probe.DNSQueryCD(ctx, name, qtype)
	return d.classify(ctx, resp, err)
}
