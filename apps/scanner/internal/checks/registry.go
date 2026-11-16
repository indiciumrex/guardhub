package checks

import "github.com/hksolutions/guardhub/apps/scanner/internal/evidence"

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
func Default() *Registry {
	return NewRegistry(
		ExposedEnv{},
		SecurityHeaders{},
		NewTLSCert(),
		OpenAdmin{},
		DefaultCreds{},
		InfoLeak{},
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
