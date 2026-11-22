package checks

import (
	"crypto/x509"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
)

// Options configures the production checks. The zero value is production:
// system roots for certificate verification.
type Options struct {
	// Roots verifies certificate chains; nil = the system roots. The
	// validation lab passes its own CA (test_corpus), production never does.
	Roots *x509.CertPool
	// DNSRecursionProbe is the out-of-zone name dns_email asks nameservers
	// (default "example.com."; the internet-less lab uses a lab name).
	DNSRecursionProbe string
	// CTURL is the Certificate Transparency search endpoint of
	// subdomain_takeover ("" = crt.sh, "off" = DNS-only discovery; the lab
	// uses its own stand-in).
	CTURL string
}

// Registry maps check ids to checks. Adding a check = new file + one line in
// Default().
type Registry struct {
	byID  map[string]Check
	order []string
}

// NewRegistry builds a registry from checks, in the given order. It panics
// on duplicate ids or ids missing from check-ids.json (programming errors).
func NewRegistry(cs ...Check) *Registry {
	r := &Registry{byID: make(map[string]Check, len(cs))}
	for _, c := range cs {
		id := c.ID()
		if _, ok := evidence.FindingKeys[id]; !ok {
			panic("checks: id not in check-ids.json: " + id)
		}
		if _, dup := r.byID[id]; dup {
			panic("checks: duplicate check id: " + id)
		}
		r.byID[id] = c
		r.order = append(r.order, id)
	}
	return r
}

// Default returns every production check in catalog order.
func Default() *Registry { return DefaultWith(Options{}) }

// DefaultWith is Default with injected options (validation lab).
func DefaultWith(o Options) *Registry {
	tlsCert := NewTLSCert()
	tlsCert.Roots = o.Roots
	return NewRegistry(
		ExposedEnv{},
		SecurityHeaders{},
		tlsCert,
		OpenAdmin{},
		DefaultCreds{},
		InfoLeak{},
		TLSConfig{Roots: o.Roots},
		HTTPHardening{},
		DNSEmail{RecursionProbe: o.DNSRecursionProbe},
		SubdomainTakeover{CTURL: o.CTURL},
		TLSDepth{Roots: o.Roots},
		HeaderQuality{},
	)
}

// Get returns the check with id.
func (r *Registry) Get(id string) (Check, bool) {
	c, ok := r.byID[id]
	return c, ok
}

// IDs returns the registered ids in registration order.
func (r *Registry) IDs() []string {
	return append([]string(nil), r.order...)
}
