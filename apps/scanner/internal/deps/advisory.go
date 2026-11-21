package deps

// From OSV records to one verdict per package (ADR-0006 §7, §8): advisories
// that alias each other are one issue; each issue gets a rating (GitHub
// Advisory rating, else CVSS v3 base score) and the version that fixes it
// for this package; the package gets the lowest version that fixes every
// fixable issue.

import (
	"sort"
	"strings"
)

// Rating is an advisory's qualitative severity.
type Rating int

// Ratings, ordered.
const (
	RatingUnrated Rating = iota
	RatingLow
	RatingModerate
	RatingHigh
	RatingCritical
)

// Issue is one vulnerability (a group of aliasing advisories) of a package.
type Issue struct {
	ID        string // display id: CVE alias, else GHSA, else the OSV id
	Rating    Rating
	Malicious bool   // an OpenSSF malicious-package record (MAL-…)
	Fixed     string // lowest version fixing it for this package; "" = none known
}

// Verdict is the outcome for one vulnerable package.
type Verdict struct {
	Issues []Issue // sorted by display id
	// Fixed is the lowest version that fixes every issue that has a fix
	// ("" when none has one).
	Fixed string
	// Unfixed counts issues with no fixed version.
	Unfixed int
}

// MaxRating is the highest rating among the issues.
func (v Verdict) MaxRating() Rating {
	r := RatingUnrated
	for _, i := range v.Issues {
		if i.Rating > r {
			r = i.Rating
		}
	}
	return r
}

// AnyUnrated reports whether some issue has no rating.
func (v Verdict) AnyUnrated() bool {
	for _, i := range v.Issues {
		if i.Rating == RatingUnrated && !i.Malicious {
			return true
		}
	}
	return false
}

// Malicious reports whether some issue is a malicious-package record.
func (v Verdict) Malicious() bool {
	for _, i := range v.Issues {
		if i.Malicious {
			return true
		}
	}
	return false
}

// IDs returns the display ids.
func (v Verdict) IDs() []string {
	out := make([]string, len(v.Issues))
	for i, is := range v.Issues {
		out[i] = is.ID
	}
	return out
}

// Assess builds the verdict for pkg from the records OSV matched to it.
// Withdrawn records are ignored; ok is false when nothing is left.
func Assess(pkg Package, records []*Vuln) (Verdict, bool) {
	var live []*Vuln
	for _, r := range records {
		if r != nil && r.Withdrawn == "" {
			live = append(live, r)
		}
	}
	if len(live) == 0 {
		return Verdict{}, false
	}
	var v Verdict
	for _, group := range groupAliases(live) {
		is := Issue{ID: displayID(group), Rating: groupRating(group)}
		fixKnown := false
		for _, r := range group {
			if strings.HasPrefix(r.ID, "MAL-") {
				is.Malicious = true
			}
			if f, ok := fixedVersion(pkg, r); ok {
				// Aliases should agree; when they do not, the higher fix is safe.
				if !fixKnown || greater(pkg.Ecosystem, f, is.Fixed) {
					is.Fixed = f
				}
				fixKnown = true
			}
		}
		v.Issues = append(v.Issues, is)
	}
	sort.Slice(v.Issues, func(i, j int) bool { return v.Issues[i].ID < v.Issues[j].ID })
	for _, is := range v.Issues {
		if is.Fixed == "" {
			v.Unfixed++
			continue
		}
		if v.Fixed == "" || greater(pkg.Ecosystem, is.Fixed, v.Fixed) {
			v.Fixed = is.Fixed
		}
	}
	return v, true
}

func greater(eco, a, b string) bool {
	c, ok := Compare(eco, a, b)
	return ok && c > 0
}

// groupAliases unions records whose id or aliases overlap.
func groupAliases(records []*Vuln) [][]*Vuln {
	parent := make([]int, len(records))
	for i := range parent {
		parent[i] = i
	}
	find := func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	owner := map[string]int{}
	for i, r := range records {
		for _, name := range append([]string{r.ID}, r.Aliases...) {
			if j, ok := owner[name]; ok {
				parent[find(i)] = find(j)
			} else {
				owner[name] = i
			}
		}
	}
	groups := map[int][]*Vuln{}
	var order []int
	for i, r := range records {
		root := find(i)
		if _, ok := groups[root]; !ok {
			order = append(order, root)
		}
		groups[root] = append(groups[root], r)
	}
	out := make([][]*Vuln, 0, len(order))
	for _, root := range order {
		out = append(out, groups[root])
	}
	return out
}

// displayID prefers a CVE id, then a GHSA id, then the smallest OSV id.
func displayID(group []*Vuln) string {
	var all []string
	for _, r := range group {
		all = append(all, r.ID)
		all = append(all, r.Aliases...)
	}
	sort.Strings(all)
	for _, prefix := range []string{"CVE-", "GHSA-"} {
		for _, id := range all {
			if strings.HasPrefix(id, prefix) {
				return id
			}
		}
	}
	ids := make([]string, len(group))
	for i, r := range group {
		ids[i] = r.ID
	}
	sort.Strings(ids)
	return ids[0]
}

// groupRating rates one issue (aliasing records): the GitHub Advisory
// rating when any record of the group carries one, else the highest CVSS v3
// base score among all its vectors. An alias that only has a CVSS vector
// never overrides GitHub's rating (validation lab: CVE-2024-56326 is MODERATE
// at GitHub while its PYSEC alias's local-attack vector scores 7.8).
func groupRating(group []*Vuln) Rating {
	ghsa, cvss := RatingUnrated, RatingUnrated
	for _, r := range group {
		if rt := advisoryRating(r); rt > ghsa {
			ghsa = rt
		}
		if rt := cvssRating(r); rt > cvss {
			cvss = rt
		}
	}
	if ghsa != RatingUnrated {
		return ghsa
	}
	return cvss
}

// rating rates a single record (GitHub Advisory rating, else CVSS v3).
func rating(r *Vuln) Rating { return groupRating([]*Vuln{r}) }

// advisoryRating is the record's GitHub Advisory Database rating, if any.
func advisoryRating(r *Vuln) Rating {
	switch strings.ToUpper(strings.TrimSpace(r.DatabaseSpecific.Severity)) {
	case "CRITICAL":
		return RatingCritical
	case "HIGH":
		return RatingHigh
	case "MODERATE", "MEDIUM":
		return RatingModerate
	case "LOW":
		return RatingLow
	}
	return RatingUnrated
}

// cvssRating is the highest rating among the record's CVSS v3 vectors.
func cvssRating(r *Vuln) Rating {
	best := RatingUnrated
	for _, s := range r.Severity {
		if s.Type != "CVSS_V3" {
			continue
		}
		if score, ok := CVSS3BaseScore(s.Score); ok {
			if rt := RatingFromScore(score); rt > best {
				best = rt
			}
		}
	}
	return best
}

// fixedVersion returns the version that fixes record r for pkg: the "fixed"
// event closing the range that contains pkg.Version; else (OSV matched the
// version through its explicit list, or a range we could not place it in)
// the lowest "fixed" event above pkg.Version. ok is false when the record
// names no fix above the version.
func fixedVersion(pkg Package, r *Vuln) (string, bool) {
	name := NormalizeName(pkg.Ecosystem, pkg.Name)
	var fallback string
	for _, a := range r.Affected {
		if a.Package.Ecosystem != pkg.Ecosystem || NormalizeName(pkg.Ecosystem, a.Package.Name) != name {
			continue
		}
		for _, rg := range a.Ranges {
			if rg.Type != "ECOSYSTEM" && rg.Type != "SEMVER" {
				continue
			}
			if fix, in := rangeFix(pkg.Ecosystem, pkg.Version, rg); in {
				if fix != "" {
					return fix, true
				}
				continue
			}
			for _, ev := range rg.Events {
				f, ok := ev["fixed"]
				if !ok || !greater(pkg.Ecosystem, f, pkg.Version) {
					continue
				}
				if fallback == "" || greater(pkg.Ecosystem, fallback, f) {
					fallback = f
				}
			}
		}
	}
	return fallback, fallback != ""
}

type event struct {
	kind, version string // introduced | fixed | last_affected | limit
}

// rangeFix walks a range's events in version order (OSV spec: events may be
// listed unsorted) and reports whether version lies inside an affected
// interval; fix is that interval's "fixed" ("" when it ends with
// last_affected or is open).
func rangeFix(eco, version string, rg Range) (fix string, in bool) {
	var evs []event
	for _, e := range rg.Events {
		for _, k := range []string{"introduced", "fixed", "last_affected", "limit"} {
			if v, ok := e[k]; ok {
				evs = append(evs, event{kind: k, version: v})
			}
		}
	}
	less := func(a, b string) bool {
		if a == b {
			return false
		}
		if a == "0" {
			return true
		}
		if b == "0" {
			return false
		}
		c, ok := Compare(eco, a, b)
		return ok && c < 0
	}
	for _, e := range evs {
		if e.version != "0" {
			if _, ok := Compare(eco, e.version, e.version); !ok {
				return "", false // an unparsable event: cannot place the version
			}
		}
	}
	sort.SliceStable(evs, func(i, j int) bool { return less(evs[i].version, evs[j].version) })
	open, start := false, ""
	for _, e := range evs {
		switch e.kind {
		case "introduced":
			if !open {
				open, start = true, e.version
			}
		case "fixed", "limit":
			if open && !less(version, start) && less(version, e.version) {
				if e.kind == "fixed" {
					return e.version, true
				}
				return "", true
			}
			open = false
		case "last_affected":
			if open && !less(version, start) && !less(e.version, version) {
				return "", true
			}
			open = false
		}
	}
	if open && !less(version, start) {
		return "", true
	}
	return "", false
}
