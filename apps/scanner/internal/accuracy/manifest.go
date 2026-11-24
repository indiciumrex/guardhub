// Package accuracy measures how accurate each check is against the validation
// lab (test_corpus/): every lab target has a hand-written manifest saying which
// findings MUST appear (ground truth, each with a reason) and which may appear
// (tolerated, also with a reason). Everything else a check reports there is a
// false positive. Scoring and rendering are pure functions: no network here.
//
// The manifests are the oracle. They are written from the lab's own
// configuration (synthetic targets) or from behaviour verified by hand
// (third-party vulnerable apps), never from scanner output.
package accuracy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
)

// Manifest is the ground truth for one lab target.
type Manifest struct {
	Target      string        `yaml:"target"`
	Origin      string        `yaml:"origin"` // a site target (*.lab.test origin)
	Repo        string        `yaml:"repo"`   // or a repository target ("lab/<dir>", test_corpus/repos)
	Description string        `yaml:"description"`
	Checks      []string      `yaml:"checks"` // check ids scored on this target
	Expect      []Expectation `yaml:"expect"`
	Tolerate    []Expectation `yaml:"tolerate"`
	// Active marks an active-test target (ADR-0008, Gate M: scanner
	// activelab): its checks are all active checks; a passive manifest may
	// list none. Sessions names the lab-made session file (two consented
	// test accounts, JSON {"a":{...},"b":{...}}), relative to the manifests.
	Active   bool   `yaml:"active,omitempty"`
	Sessions string `yaml:"sessions,omitempty"`
	// Start lists same-origin paths (with their query) where an active
	// target's discovery starts besides "/": the lab's route list for pages no
	// link reaches (a single-page app's API, a login-only lesson).
	Start []string `yaml:"start,omitempty"`
	// OracleDisputed lists independent-oracle alerts judged wrong, each with
	// its evidence (Gate M's ZAP comparison, test_corpus/oracles/zap). It never
	// changes the scanner's score; it only explains a disagreement.
	OracleDisputed []Disputed `yaml:"oracle_disputed,omitempty"`
}

// Disputed is one oracle alert judged wrong and why.
type Disputed struct {
	Check    string `yaml:"check"`
	Location string `yaml:"location"`
	Why      string `yaml:"why"`
}

// Expectation names one finding. Location, when set, must match exactly;
// when empty, any location of that check/key matches (one finding).
//
// Outside marks a real issue that lies beyond what the check DECLARES it
// covers (e.g. a product missing from a fixed catalogue). Missing it still
// shows as a false negative and lowers "recall (all)", but not the recall the
// gate uses. Use it only with a reason that names the declared scope.
type Expectation struct {
	Check    string `yaml:"check"`
	Key      string `yaml:"key"`
	Location string `yaml:"location,omitempty"`
	// Params, when set, must all equal the finding's params (e.g. the
	// fixed version dependency_vulns recommends): wrong advice is a miss.
	Params  map[string]string `yaml:"params,omitempty"`
	Outside bool              `yaml:"outside,omitempty"`
	Why     string            `yaml:"why"`
}

func (e Expectation) matches(f evidence.Finding) bool {
	if f.CheckID != e.Check || f.FindingKey != e.Key || (e.Location != "" && f.Evidence.Location != e.Location) {
		return false
	}
	for k, v := range e.Params {
		if f.Params[k] != v {
			return false
		}
	}
	return true
}

// LoadManifests reads every *.yaml in dir, validates them and returns them
// sorted by target.
func LoadManifests(dir string) ([]Manifest, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("accuracy: no manifests in %s", dir)
	}
	seen := map[string]bool{}
	var out []Manifest
	for _, p := range paths {
		raw, err := os.ReadFile(p) //nolint:gosec // lab manifests from the repository
		if err != nil {
			return nil, err
		}
		var m Manifest
		dec := yaml.NewDecoder(strings.NewReader(string(raw)))
		dec.KnownFields(true)
		if err := dec.Decode(&m); err != nil {
			return nil, fmt.Errorf("accuracy: %s: %w", filepath.Base(p), err)
		}
		if err := m.Validate(); err != nil {
			return nil, fmt.Errorf("accuracy: %s: %w", filepath.Base(p), err)
		}
		if seen[m.Target] {
			return nil, fmt.Errorf("accuracy: duplicate target %q", m.Target)
		}
		seen[m.Target] = true
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out, nil
}

// IsRepo reports a repository target.
func (m Manifest) IsRepo() bool { return m.Repo != "" }

// Validate rejects manifests that would make the score meaningless: unknown
// ids/keys, expectations without a reason, expectations for unscored checks.
func (m Manifest) Validate() error {
	if m.Target == "" || (m.Origin == "") == (m.Repo == "") {
		return errors.New("target and exactly one of origin (site) or repo (repository) are required")
	}
	if m.Repo != "" && m.Repo != "lab/"+m.Target {
		return fmt.Errorf("repo must be lab/%s (test_corpus/repos/%s)", m.Target, m.Target)
	}
	if len(m.Checks) == 0 {
		return errors.New("checks: list the check ids scored on this target")
	}
	scored := map[string]bool{}
	for _, id := range m.Checks {
		if _, ok := evidence.FindingKeys[id]; !ok {
			return fmt.Errorf("checks: unknown check id %q", id)
		}
		if evidence.RepoChecks[id] != m.IsRepo() || evidence.ActiveChecks[id] != m.Active {
			return fmt.Errorf("checks: %q cannot run on this kind of target", id)
		}
		scored[id] = true
	}
	for _, list := range [][]Expectation{m.Expect, m.Tolerate} {
		for _, e := range list {
			keys, ok := evidence.FindingKeys[e.Check]
			if !ok {
				return fmt.Errorf("unknown check id %q", e.Check)
			}
			if _, ok := keys[e.Key]; !ok {
				return fmt.Errorf("unknown finding key %s/%s", e.Check, e.Key)
			}
			if !scored[e.Check] {
				return fmt.Errorf("%s/%s: check %q is not in checks", e.Check, e.Key, e.Check)
			}
			if strings.TrimSpace(e.Why) == "" {
				return fmt.Errorf("%s/%s: why is required (the ground truth needs a reason)", e.Check, e.Key)
			}
		}
	}
	return nil
}
