// Command labpki generates the validation lab's throwaway PKI at lab start-up
// (test_corpus/): a lab root CA, an intermediate, and one certificate per lab
// TLS target with a deliberate property (valid, expired, wrong host, ...).
// Nothing it writes is committed; keys live only in the lab's volume.
//
//	labpki -out DIR name:kind [name:kind ...]
//
// Kinds:
//
//	valid        leaf for name, signed by the intermediate, full chain served
//	nochain      like valid, but the served file omits the intermediate
//	expired      valid chain, notAfter in the past
//	wronghost    valid chain, issued for "other.lab.test" only
//	selfsigned   self-signed leaf for name (not under the lab CA)
//	rsa1024      valid chain, 1024-bit RSA key
//	rsa2048      valid chain, 2048-bit RSA key (for static-RSA cipher suites)
//
// Like public CAs' certificates, every leaf names its issuer's location (AIA
// caIssuers), which tls_config uses to tell "intermediate not served" apart
// from "private CA".
//
// For each name it writes DIR/name.crt (chain to serve) and DIR/name.key;
// DIR/ca.pem is the lab root to trust.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type issuer struct {
	cert *x509.Certificate
	key  crypto.Signer
	der  []byte
}

func main() {
	out := flag.String("out", "", "output directory")
	flag.Parse()
	if *out == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: labpki -out DIR name:kind ...")
		os.Exit(2)
	}
	if err := run(*out, flag.Args(), time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "labpki:", err)
		os.Exit(1)
	}
}

func run(dir string, specs []string, now time.Time) error {
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // lab volume, read by nginx
		return err
	}
	// Never replace a PKI that running targets already serve: a new CA would make
	// every lab certificate "untrusted" for the runner.
	if _, err := os.Stat(filepath.Join(dir, "ca.pem")); err == nil {
		fmt.Println("labpki: PKI already present, keeping it")
		return nil
	}
	root, err := newCA("GuardHub Lab Root CA", nil, now)
	if err != nil {
		return err
	}
	inter, err := newCA("GuardHub Lab Intermediate CA", root, now)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, "ca.pem"), "CERTIFICATE", root.der); err != nil {
		return err
	}
	for _, spec := range specs {
		name, kind, ok := strings.Cut(spec, ":")
		if !ok || !strings.HasSuffix(name, ".lab.test") {
			return fmt.Errorf("bad spec %q (want <name>.lab.test:<kind>)", spec)
		}
		if err := leaf(dir, name, kind, root, inter, now); err != nil {
			return fmt.Errorf("%s: %w", spec, err)
		}
	}
	return nil
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n
}

func newCA(cn string, parent *issuer, now time.Time) (*issuer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"GuardHub validation lab"}},
		// Realistic CA lifetime: issued long before any lab leaf (an "expired" leaf
		// must have been signed while its CA was valid, as in the real world).
		NotBefore:             now.Add(-2 * 365 * 24 * time.Hour),
		NotAfter:              now.Add(3 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	signerCert, signerKey := tpl, crypto.Signer(key)
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signerCert, key.Public(), signerKey)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &issuer{cert: cert, key: key, der: der}, nil
}

func leaf(dir, name, kind string, root, inter *issuer, now time.Time) error {
	var key crypto.Signer
	var err error
	switch kind {
	case "rsa1024":
		key, err = rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // deliberately weak: lab target for the weak-key finding
	case "rsa2048":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		return err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    now.Add(-24 * time.Hour),
		NotAfter:     now.Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// as public CAs do: where to fetch the issuer (never fetched in the lab)
		IssuingCertificateURL: []string{"http://pki.lab.test/intermediate.crt"},
	}
	signer, chain := inter, true
	switch kind {
	case "valid", "rsa1024", "rsa2048":
	case "nochain":
		chain = false
	case "expired":
		tpl.NotBefore, tpl.NotAfter = now.Add(-120*24*time.Hour), now.Add(-30*24*time.Hour)
	case "wronghost":
		tpl.Subject.CommonName, tpl.DNSNames = "other.lab.test", []string{"other.lab.test"}
	case "selfsigned":
		signer, chain = nil, false
		tpl.IssuingCertificateURL = nil
	default:
		return fmt.Errorf("unknown kind %q", kind)
	}
	var der []byte
	if signer == nil {
		der, err = x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	} else {
		der, err = x509.CreateCertificate(rand.Reader, tpl, signer.cert, key.Public(), signer.key)
	}
	if err != nil {
		return err
	}
	blocks := []*pem.Block{{Type: "CERTIFICATE", Bytes: der}}
	if chain {
		blocks = append(blocks, &pem.Block{Type: "CERTIFICATE", Bytes: inter.der})
	}
	var crt []byte
	for _, b := range blocks {
		crt = append(crt, pem.EncodeToMemory(b)...)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".crt"), crt, 0o644); err != nil { //nolint:gosec // public certificate
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	// 0644: the lab's nginx workers run as another user; the key is a throwaway in a lab-only volume.
	return writePEM(filepath.Join(dir, name+".key"), "PRIVATE KEY", keyDER)
}

func writePEM(path, typ string, der []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o644) //nolint:gosec // lab-only, see leaf()
}
