package deps

// Version ordering per ecosystem: SemVer 2.0 precedence for npm, PEP 440
// for PyPI. Used only to place a version inside OSV ranges and to pick the
// lowest fixed version; a version that does not parse is "unknown", never
// guessed.

import (
	"regexp"
	"strconv"
	"strings"
)

// Compare orders a and b in ecosystem eco: -1, 0, +1. ok is false when
// either does not parse.
func Compare(eco, a, b string) (int, bool) {
	switch eco {
	case EcosystemNPM:
		va, ok1 := parseSemver(a)
		vb, ok2 := parseSemver(b)
		if !ok1 || !ok2 {
			return 0, false
		}
		return va.compare(vb), true
	case EcosystemPyPI:
		va, ok1 := parsePEP440(a)
		vb, ok2 := parsePEP440(b)
		if !ok1 || !ok2 {
			return 0, false
		}
		return va.compare(vb), true
	}
	return 0, false
}

// ---------------------------------------------------------------- semver

type semver struct {
	major, minor, patch uint64
	pre                 []string // dot-separated pre-release identifiers
}

var semverRe = regexp.MustCompile(`^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

func parseSemver(s string) (semver, bool) {
	m := semverRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return semver{}, false
	}
	var v semver
	var err error
	if v.major, err = strconv.ParseUint(m[1], 10, 64); err != nil {
		return semver{}, false
	}
	if v.minor, err = strconv.ParseUint(m[2], 10, 64); err != nil {
		return semver{}, false
	}
	if v.patch, err = strconv.ParseUint(m[3], 10, 64); err != nil {
		return semver{}, false
	}
	if m[4] != "" {
		v.pre = strings.Split(m[4], ".")
	}
	return v, true
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func (a semver) compare(b semver) int {
	if c := cmpUint(a.major, b.major); c != 0 {
		return c
	}
	if c := cmpUint(a.minor, b.minor); c != 0 {
		return c
	}
	if c := cmpUint(a.patch, b.patch); c != 0 {
		return c
	}
	// A pre-release sorts before the release.
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		x, y := a.pre[i], b.pre[i]
		nx, ex := strconv.ParseUint(x, 10, 64)
		ny, ey := strconv.ParseUint(y, 10, 64)
		switch {
		case ex == nil && ey == nil:
			if c := cmpUint(nx, ny); c != 0 {
				return c
			}
		case ex == nil: // numeric identifiers sort before alphanumeric ones
			return -1
		case ey == nil:
			return 1
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		}
	}
	return cmpUint(uint64(len(a.pre)), uint64(len(b.pre)))
}

// ---------------------------------------------------------------- PEP 440

type pep440 struct {
	epoch   uint64
	release []uint64 // trailing zeros stripped (1.0 == 1.0.0)
	preKind int      // 0 none, 1 a, 2 b, 3 rc
	preNum  uint64
	hasPost bool
	post    uint64
	hasDev  bool
	dev     uint64
}

// The canonical PEP 440 regex (packaging.version.VERSION_PATTERN), without
// the local segment's contents mattering for ordering here.
var pep440Re = regexp.MustCompile(`(?i)^\s*v?(?:(\d+)!)?(\d+(?:\.\d+)*)` +
	`(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d+)?)?` +
	`(?:-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d+)?)?` +
	`(?:[-_.]?(dev)[-_.]?(\d+)?)?` +
	`(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?\s*$`)

func parsePEP440(s string) (pep440, bool) {
	m := pep440Re.FindStringSubmatch(s)
	if m == nil {
		return pep440{}, false
	}
	num := func(x string) (uint64, bool) {
		if x == "" {
			return 0, true
		}
		n, err := strconv.ParseUint(x, 10, 64)
		return n, err == nil
	}
	var v pep440
	var ok bool
	if v.epoch, ok = num(m[1]); !ok {
		return pep440{}, false
	}
	for _, part := range strings.Split(m[2], ".") {
		n, ok := num(part)
		if !ok {
			return pep440{}, false
		}
		v.release = append(v.release, n)
	}
	for len(v.release) > 1 && v.release[len(v.release)-1] == 0 {
		v.release = v.release[:len(v.release)-1]
	}
	if m[3] != "" {
		switch strings.ToLower(m[3]) {
		case "a", "alpha":
			v.preKind = 1
		case "b", "beta":
			v.preKind = 2
		default: // c, rc, pre, preview
			v.preKind = 3
		}
		if v.preNum, ok = num(m[4]); !ok {
			return pep440{}, false
		}
	}
	switch {
	case m[5] != "":
		v.hasPost = true
		if v.post, ok = num(m[5]); !ok {
			return pep440{}, false
		}
	case m[6] != "":
		v.hasPost = true
		if v.post, ok = num(m[7]); !ok {
			return pep440{}, false
		}
	}
	if m[8] != "" {
		v.hasDev = true
		if v.dev, ok = num(m[9]); !ok {
			return pep440{}, false
		}
	}
	return v, true
}

// compare follows packaging's _cmpkey: epoch, release, then
// pre (a dev-only release sorts before any pre-release; no pre sorts after),
// post (none sorts first), dev (none sorts last).
func (a pep440) compare(b pep440) int {
	if c := cmpUint(a.epoch, b.epoch); c != 0 {
		return c
	}
	for i := 0; i < len(a.release) || i < len(b.release); i++ {
		var x, y uint64
		if i < len(a.release) {
			x = a.release[i]
		}
		if i < len(b.release) {
			y = b.release[i]
		}
		if c := cmpUint(x, y); c != 0 {
			return c
		}
	}
	if c := cmpInt(a.preRank(), b.preRank()); c != 0 {
		return c
	}
	if a.preKind != 0 && b.preKind != 0 {
		if c := cmpUint(a.preNum, b.preNum); c != 0 {
			return c
		}
	}
	if c := cmpInt(boolRank(a.hasPost), boolRank(b.hasPost)); c != 0 {
		return c
	}
	if a.hasPost && b.hasPost {
		if c := cmpUint(a.post, b.post); c != 0 {
			return c
		}
	}
	if c := cmpInt(-boolRank(a.hasDev), -boolRank(b.hasDev)); c != 0 {
		return c
	}
	if a.hasDev && b.hasDev {
		return cmpUint(a.dev, b.dev)
	}
	return 0
}

// preRank: dev-only release (-1) < a (1) < b (2) < rc (3) < final (4).
func (a pep440) preRank() int {
	switch {
	case a.preKind == 0 && !a.hasPost && a.hasDev:
		return -1
	case a.preKind == 0:
		return 4
	}
	return a.preKind
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
