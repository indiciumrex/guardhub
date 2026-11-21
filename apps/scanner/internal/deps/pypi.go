package deps

// PyPI manifests with exact versions: requirements*.txt (== pins only),
// Pipfile.lock, poetry.lock and uv.lock.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// requirementPinRe matches "name[extras] == version" (also "==="), with an
// optional environment marker or hash options after it.
var requirementPinRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9!+._-]+)\s*(?:;.*|\\)?$`)

var devRequirementsRe = regexp.MustCompile(`(?i)(^|[-_.])(dev|develop|development|test|tests|testing|lint|docs?|ci)([-_.]|$)`)

// isDevRequirements: requirements-dev.txt, requirements/test.txt, … are
// development-only by the common naming convention (docs/checks/dependency_vulns.md).
func isDevRequirements(p string) bool {
	base := strings.TrimSuffix(strings.ToLower(path.Base(p)), ".txt")
	base = strings.TrimPrefix(base, "requirements")
	return devRequirementsRe.MatchString(base)
}

func parseRequirements(data []byte, dev bool) []Package {
	var out []Package
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue // comments and options (-r, -e, --hash continuation lines, …)
		}
		if i := strings.Index(line, " --hash"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		m := requirementPinRe.FindStringSubmatch(line)
		if m == nil {
			continue // a range, a URL or a VCS requirement: never guessed (ADR-0006 §7)
		}
		if _, ok := parsePEP440(m[2]); !ok {
			continue
		}
		out = append(out, Package{Ecosystem: EcosystemPyPI, Name: NormalizePyPI(m[1]), Version: m[2], Dev: dev})
	}
	return out
}

type pipfileLock struct {
	Default map[string]pipfileEntry `json:"default"`
	Develop map[string]pipfileEntry `json:"develop"`
}

type pipfileEntry struct {
	Version string `json:"version"`
}

func parsePipfileLock(data []byte) ([]Package, error) {
	var lock pipfileLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	var out []Package
	add := func(entries map[string]pipfileEntry, dev bool) {
		for name, e := range entries {
			v := strings.TrimPrefix(strings.TrimPrefix(e.Version, "=="), "=")
			if _, ok := parsePEP440(v); !ok || !strings.HasPrefix(e.Version, "==") {
				continue // git/path entries have no version
			}
			out = append(out, Package{Ecosystem: EcosystemPyPI, Name: NormalizePyPI(name), Version: v, Dev: dev})
		}
	}
	add(lock.Default, false)
	add(lock.Develop, true)
	return out, nil
}

type poetryLock struct {
	Package []struct {
		Name     string `toml:"name"`
		Version  string `toml:"version"`
		Category string `toml:"category"`
		Source   struct {
			Type string `toml:"type"`
		} `toml:"source"`
	} `toml:"package"`
}

// parsePoetryLock: lock format 1.x marks dev packages with category="dev";
// format 2.x dropped categories (groups live in pyproject.toml), so its
// packages count as runtime, the conservative choice for severity.
func parsePoetryLock(data []byte) ([]Package, error) {
	var lock poetryLock
	if _, err := toml.Decode(string(data), &lock); err != nil {
		return nil, err
	}
	var out []Package
	for _, p := range lock.Package {
		switch p.Source.Type {
		case "", "legacy": // PyPI or a PyPI-compatible index
		default:
			continue // git, directory, file, url: not a registry release
		}
		if _, ok := parsePEP440(p.Version); !ok {
			continue
		}
		out = append(out, Package{Ecosystem: EcosystemPyPI, Name: NormalizePyPI(p.Name), Version: p.Version, Dev: p.Category == "dev"})
	}
	return out, nil
}

type uvDep struct {
	Name string `toml:"name"`
}

type uvPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
	Source  struct {
		Registry  string `toml:"registry"`
		Editable  string `toml:"editable"`
		Virtual   string `toml:"virtual"`
		Directory string `toml:"directory"`
		Path      string `toml:"path"`
		Git       string `toml:"git"`
		URL       string `toml:"url"`
	} `toml:"source"`
	Dependencies         []uvDep            `toml:"dependencies"`
	OptionalDependencies map[string][]uvDep `toml:"optional-dependencies"`
	DevDependencies      map[string][]uvDep `toml:"dev-dependencies"`
}

type uvLock struct {
	Package []uvPackage `toml:"package"`
}

// parseUVLock reads uv.lock. Dev-ness is computed from the graph: packages
// reachable from a workspace member's dependencies or optional extras are
// runtime; packages reachable only from its dev-dependency groups are dev.
func parseUVLock(data []byte) ([]Package, error) {
	var lock uvLock
	if _, err := toml.Decode(string(data), &lock); err != nil {
		return nil, err
	}
	byName := map[string][]int{}
	for i, p := range lock.Package {
		n := NormalizePyPI(p.Name)
		byName[n] = append(byName[n], i)
	}
	runtime := map[int]bool{}
	var visit func(name string)
	visit = func(name string) {
		for _, i := range byName[NormalizePyPI(name)] {
			if runtime[i] {
				continue
			}
			runtime[i] = true
			p := lock.Package[i]
			for _, d := range p.Dependencies {
				visit(d.Name)
			}
			for _, extra := range sortedKeys(p.OptionalDependencies) {
				for _, d := range p.OptionalDependencies[extra] {
					visit(d.Name)
				}
			}
		}
	}
	roots := 0
	for _, p := range lock.Package {
		if p.Source.Editable != "" || p.Source.Virtual != "" {
			roots++
			visit(p.Name)
		}
	}
	var out []Package
	for i, p := range lock.Package {
		if p.Source.Registry == "" {
			continue // workspace members, git, path, url sources: not registry releases
		}
		if _, ok := parsePEP440(p.Version); !ok {
			continue
		}
		// Without a workspace root the graph says nothing: count everything
		// as runtime (the conservative choice for severity).
		out = append(out, Package{Ecosystem: EcosystemPyPI, Name: NormalizePyPI(p.Name), Version: p.Version, Dev: roots > 0 && !runtime[i]})
	}
	return out, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
