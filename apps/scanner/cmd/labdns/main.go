// Command labdns generates the validation lab's throwaway DNSSEC keys at lab
// start-up (test_corpus/dns/dd, dns_depth): one key per signed lab zone, and
// the parent zone file with the DS records that delegate trust to them.
// Nothing it writes is committed; keys live only in the lab's volume.
//
//	labdns -out DIR -parent FILE zone:kind [zone:kind ...]
//
// FILE is the parent zone's template (its name is the zone file's base name
// without ".db"); DIR/<base> receives the template plus one DS record per zone.
// Kinds:
//
//	signed   DIR/K<zone>.key + .private (ECDSA P-256 KSK for CoreDNS's dnssec
//	         plugin) and a DS that matches it
//	broken   the same key, but the DS published at the parent is that of ANOTHER
//	         key: validating resolvers reject the zone (dnssec_broken)
package main

import (
	"crypto"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/miekg/dns"
)

func main() {
	out := flag.String("out", "", "output directory")
	parent := flag.String("parent", "", "parent zone template")
	flag.Parse()
	if *out == "" || *parent == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: labdns -out DIR -parent FILE zone:kind ...")
		os.Exit(2)
	}
	if err := run(*out, *parent, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "labdns:", err)
		os.Exit(1)
	}
}

func run(dir, parentTmpl string, specs []string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // lab volume, read by CoreDNS
		return err
	}
	base := filepath.Base(parentTmpl)
	parentOut := filepath.Join(dir, base)
	// Keep keys that running zones already serve (restart-safe, like labpki).
	if _, err := os.Stat(parentOut); err == nil {
		fmt.Println("labdns: keys already present, keeping them")
		return nil
	}
	parentZone := strings.TrimSuffix(base, ".db")
	tmpl, err := os.ReadFile(parentTmpl) //nolint:gosec // lab template path from the compose file
	if err != nil {
		return err
	}
	var ds strings.Builder
	ds.WriteString("\n; ---- DS records written by labdns at lab start ----\n")
	for _, spec := range specs {
		zone, kind, ok := strings.Cut(spec, ":")
		if !ok || !dns.IsSubDomain(dns.Fqdn(parentZone), dns.Fqdn(zone)) || zone == parentZone {
			return fmt.Errorf("bad spec %q (want <child of %s>:<signed|broken>)", spec, parentZone)
		}
		key, priv, err := newKey(zone)
		if err != nil {
			return err
		}
		if err := writeKey(dir, zone, key, priv); err != nil {
			return err
		}
		published := key
		switch kind {
		case "signed":
		case "broken":
			if published, _, err = newKey(zone); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s: unknown kind %q", spec, kind)
		}
		ds.WriteString(published.ToDS(dns.SHA256).String() + "\n")
	}
	return os.WriteFile(parentOut, append(tmpl, ds.String()...), 0o644) //nolint:gosec // public zone data
}

func newKey(zone string) (*dns.DNSKEY, crypto.PrivateKey, error) {
	k := &dns.DNSKEY{
		Hdr:   dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := k.Generate(256)
	return k, priv, err
}

// writeKey writes the BIND-format key pair CoreDNS's dnssec plugin reads
// ("key file DIR/K<zone>").
func writeKey(dir, zone string, k *dns.DNSKEY, priv crypto.PrivateKey) error {
	b := filepath.Join(dir, "K"+zone)
	if err := os.WriteFile(b+".key", []byte(k.String()+"\n"), 0o644); err != nil { //nolint:gosec // public key
		return err
	}
	// 0644: CoreDNS runs as another user; a throwaway key in a lab-only volume.
	return os.WriteFile(b+".private", []byte(k.PrivateKeyString(priv)), 0o644) //nolint:gosec // lab-only, see above
}
