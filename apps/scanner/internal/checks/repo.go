package checks

// Repo checks (check-ids.json "target": "repo", ADR-0006) scan an in-memory
// snapshot of a connected repository instead of a live site. They have their
// own registry so a site scan can never run them and a repo scan runs only
// them.

import (
	"context"
	"net/http"
	"time"

	"github.com/hksolutions/guardhub/apps/scanner/internal/deps"
	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/repo"
)

// RepoCheck is a check over a repository snapshot. Like site checks it is
// deterministic for the same snapshot (and the same advisory database), and
// it returns its findings even together with an error (partial results).
type RepoCheck interface {
	ID() string
	RunRepo(ctx context.Context, snap *repo.Snapshot) ([]evidence.Finding, error)
}

// RepoRegistry maps repo check ids to checks.
type RepoRegistry struct {
	byID  map[string]RepoCheck
	order []string
}

// NewRepoRegistry builds a registry; it panics on ids that are not repo
// checks in check-ids.json, or duplicates (programming errors).
func NewRepoRegistry(cs ...RepoCheck) *RepoRegistry {
	r := &RepoRegistry{byID: make(map[string]RepoCheck, len(cs))}
	for _, c := range cs {
		id := c.ID()
		if !evidence.RepoChecks[id] {
			panic("checks: not a repo check in check-ids.json: " + id)
		}
		if _, dup := r.byID[id]; dup {
			panic("checks: duplicate repo check id: " + id)
		}
		r.byID[id] = c
		r.order = append(r.order, id)
	}
	return r
}

// RepoOptions configures the production repo checks.
type RepoOptions struct {
	OSVURL    string            // "" = https://api.osv.dev (the lab uses its replay stand-in)
	Transport http.RoundTripper // egress transport (probe.NewEgressTransport)
	Timeout   time.Duration     // per OSV request
	MaxVulns  int               // advisory detail fetches per scan
}

// DefaultRepoMaxVulns caps advisory detail fetches per repo scan.
const DefaultRepoMaxVulns = 400

// DefaultRepo returns every production repo check in catalog order.
func DefaultRepo(o RepoOptions) *RepoRegistry {
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}
	if o.MaxVulns <= 0 {
		o.MaxVulns = DefaultRepoMaxVulns
	}
	return NewRepoRegistry(
		DependencyVulns{OSV: deps.NewOSV(o.OSVURL, o.Transport, o.Timeout, o.MaxVulns)},
		RepoSecrets{},
	)
}

// Get returns the repo check with id.
func (r *RepoRegistry) Get(id string) (RepoCheck, bool) {
	c, ok := r.byID[id]
	return c, ok
}

// IDs returns the registered ids in registration order.
func (r *RepoRegistry) IDs() []string {
	return append([]string(nil), r.order...)
}
