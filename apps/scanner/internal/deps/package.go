// Package deps turns a repository snapshot into exact dependency versions
// (lockfiles only, never guessed from ranges) and matches them against OSV
// advisories (ADR-0006 §7, §8). Parsing is pure; only osv.go talks to the
// network.
package deps

import (
	"regexp"
	"sort"
	"strings"

	"github.com/hksolutions/guardhub/apps/scanner/internal/repo"
)

// OSV ecosystem names.
const (
	EcosystemNPM  = "npm"
	EcosystemPyPI = "PyPI"
)

// Package is one exact dependency version found in one manifest.
type Package struct {
	Ecosystem string
	Name      string // as written in the lockfile (PyPI: normalised, PEP 503)
	Version   string
	Dev       bool   // reachable only through development dependencies
	Manifest  string // repository-relative path of the lockfile
}

// Key identifies a package within a manifest (version deliberately left
// out: a partial upgrade stays the same finding).
func (p Package) Key() string { return p.Manifest + "#" + p.Name }

// ManifestError records a lockfile that could not be parsed. Findings of the
// other manifests are still reported; the check reports the parse failures
// as an incomplete scan.
type ManifestError struct {
	Manifest string
	Err      error
}

// FromSnapshot extracts every exact package version from the snapshot's
// lockfiles, deduplicated per manifest (a package that is both a dev and a
// runtime dependency counts as runtime). The result is sorted.
func FromSnapshot(s *repo.Snapshot) ([]Package, []ManifestError) {
	var all []Package
	var errs []ManifestError
	for _, f := range s.Files {
		var pkgs []Package
		var err error
		switch base := baseName(f.Path); {
		case base == "package-lock.json" || base == "npm-shrinkwrap.json":
			pkgs, err = parsePackageLock(f.Data)
		case base == "uv.lock":
			pkgs, err = parseUVLock(f.Data)
		case base == "poetry.lock":
			pkgs, err = parsePoetryLock(f.Data)
		case base == "Pipfile.lock":
			pkgs, err = parsePipfileLock(f.Data)
		case repo.IsRequirementsFile(f.Path):
			pkgs = parseRequirements(f.Data, isDevRequirements(f.Path))
		default:
			continue
		}
		if err != nil {
			errs = append(errs, ManifestError{Manifest: f.Path, Err: err})
			continue
		}
		for i := range pkgs {
			pkgs[i].Manifest = f.Path
		}
		all = append(all, dedupe(pkgs)...)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Manifest != all[j].Manifest {
			return all[i].Manifest < all[j].Manifest
		}
		if all[i].Name != all[j].Name {
			return all[i].Name < all[j].Name
		}
		return all[i].Version < all[j].Version
	})
	return all, errs
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// dedupe merges duplicate name@version entries of one manifest; runtime
// wins over dev.
func dedupe(pkgs []Package) []Package {
	idx := map[string]int{}
	var out []Package
	for _, p := range pkgs {
		k := p.Name + "@" + p.Version
		if i, ok := idx[k]; ok {
			out[i].Dev = out[i].Dev && p.Dev
			continue
		}
		idx[k] = len(out)
		out = append(out, p)
	}
	return out
}

var pep503Re = regexp.MustCompile(`[-_.]+`)

// NormalizePyPI is the PEP 503 normalised project name.
func NormalizePyPI(name string) string {
	return pep503Re.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
}

// NormalizeName normalises a package name for comparisons in ecosystem eco.
func NormalizeName(eco, name string) string {
	if eco == EcosystemPyPI {
		return NormalizePyPI(name)
	}
	return name
}
