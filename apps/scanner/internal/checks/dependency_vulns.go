package checks

// dependency_vulns: exact dependency versions from lockfiles matched against
// OSV advisories (ADR-0006 §7, §8; docs/checks/dependency_vulns.md). One
// finding per (manifest, package): "this package has these advisories,
// upgrade to this version". Severity reflects exposure: runtime vs
// development-only, then the advisories' ratings; never critical.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hksolutions/guardhub/apps/scanner/internal/deps"
	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/repo"
)

// DependencyVulns implements dependency_vulns.
type DependencyVulns struct {
	OSV *deps.OSV
}

// ErrManifestUnreadable: a lockfile could not be parsed (others still were).
var ErrManifestUnreadable = errors.New("a dependency lockfile could not be parsed")

// maxAdvisoryParam bounds the advisories list in params (schema: 256 chars).
const maxAdvisoryIDs = 8

// ID implements RepoCheck.
func (DependencyVulns) ID() string { return evidence.CheckDependencyVulns }

// RunRepo implements RepoCheck.
func (c DependencyVulns) RunRepo(ctx context.Context, snap *repo.Snapshot) ([]evidence.Finding, error) {
	pkgs, manifestErrs := deps.FromSnapshot(snap)
	var findings []evidence.Finding
	var runErr error
	if len(pkgs) > 0 {
		matches, err := c.OSV.Matches(ctx, pkgs)
		if err != nil {
			return nil, err // without matches nothing can be said: the check failed
		}
		var ids []string
		for _, m := range matches {
			ids = append(ids, m...)
		}
		records, err := c.OSV.Vulns(ctx, ids)
		if err != nil && !errors.Is(err, deps.ErrTooManyAdvisories) {
			return nil, err
		}
		runErr = err
		for i, pkg := range pkgs {
			if len(matches[i]) == 0 {
				continue
			}
			var recs []*deps.Vuln
			complete := true
			for _, id := range matches[i] {
				r, ok := records[id]
				if !ok {
					complete = false
					continue
				}
				recs = append(recs, r)
			}
			if !complete {
				continue // over the advisory cap: reported as incomplete, never guessed
			}
			verdict, ok := deps.Assess(pkg, recs)
			if !ok {
				continue // every matched advisory was withdrawn
			}
			findings = append(findings, dependencyFinding(snap, pkg, verdict))
		}
	}
	switch {
	case snap.Truncated:
		runErr = errors.Join(runErr, repo.ErrTooLarge)
	case len(manifestErrs) > 0:
		names := make([]string, len(manifestErrs))
		for i, e := range manifestErrs {
			names[i] = e.Manifest
		}
		runErr = errors.Join(runErr, fmt.Errorf("%w: %s", ErrManifestUnreadable, strings.Join(names, ", ")))
	}
	return findings, runErr
}

// DependencyKey picks the finding key (and so the severity) for a package
// verdict. Exported for the documentation tests.
func DependencyKey(pkg deps.Package, v deps.Verdict) string {
	switch {
	case v.Malicious():
		return "vulnerable_dependency_high" // a known-malicious release runs code on install, dev or not
	case pkg.Dev:
		return "vulnerable_dev_dependency"
	case v.Fixed == "":
		return "vulnerable_dependency_no_fix"
	case v.MaxRating() >= deps.RatingHigh:
		return "vulnerable_dependency_high"
	case v.MaxRating() == deps.RatingModerate || v.AnyUnrated():
		return "vulnerable_dependency_medium"
	default:
		return "vulnerable_dependency_low"
	}
}

func dependencyFinding(snap *repo.Snapshot, pkg deps.Package, v deps.Verdict) evidence.Finding {
	key := DependencyKey(pkg, v)
	ids := v.IDs()
	shown := ids
	if len(shown) > maxAdvisoryIDs {
		shown = append(append([]string(nil), ids[:maxAdvisoryIDs]...), fmt.Sprintf("+%d", len(ids)-maxAdvisoryIDs))
	}
	params := map[string]string{
		"package":    pkg.Name,
		"version":    pkg.Version,
		"ecosystem":  pkg.Ecosystem,
		"manifest":   pkg.Manifest,
		"advisories": strings.Join(shown, ", "),
	}
	if key != "vulnerable_dependency_no_fix" {
		fixed := v.Fixed
		if fixed == "" {
			fixed = "-" // a dev dependency with no fixed release yet (docs/checks/dependency_vulns.md)
		}
		params["fixed_version"] = fixed
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s@%s in %s (commit %s)\n", pkg.Ecosystem, pkg.Name, pkg.Version, pkg.Manifest, shortSHA(snap.Commit))
	if pkg.Dev {
		b.WriteString("development dependency only\n")
	}
	for _, is := range v.Issues {
		fix := is.Fixed
		if fix == "" {
			fix = "no fixed version"
		}
		label := ratingLabel(is.Rating)
		if is.Malicious {
			label = "malicious package"
		}
		fmt.Fprintf(&b, "%s: %s, fixed in %s\n", is.ID, label, fix)
	}
	location := repo.BlobURL(snap.Repo, pkg.Manifest) + "#" + pkg.Name
	return evidence.New(evidence.CheckDependencyVulns, key, params, evidence.KindDependency, location, strings.TrimRight(b.String(), "\n"))
}

func ratingLabel(r deps.Rating) string {
	switch r {
	case deps.RatingCritical:
		return "critical"
	case deps.RatingHigh:
		return "high"
	case deps.RatingModerate:
		return "moderate"
	case deps.RatingLow:
		return "low"
	}
	return "unrated"
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
