package deps

// npm lockfiles: package-lock.json / npm-shrinkwrap.json, lockfileVersion
// 1 ("dependencies" tree) and 2/3 ("packages" map keyed by install path).

import (
	"encoding/json"
	"errors"
	"strings"
)

type npmLock struct {
	LockfileVersion int                   `json:"lockfileVersion"`
	Packages        map[string]npmPackage `json:"packages"`
	Dependencies    map[string]npmDepV1   `json:"dependencies"`
}

type npmPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dev     bool   `json:"dev"`
	Link    bool   `json:"link"`
}

type npmDepV1 struct {
	Version      string              `json:"version"`
	Dev          bool                `json:"dev"`
	Dependencies map[string]npmDepV1 `json:"dependencies"`
}

var errNotLockfile = errors.New("not a package lockfile")

func parsePackageLock(data []byte) ([]Package, error) {
	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	var out []Package
	if len(lock.Packages) > 0 {
		for key, p := range lock.Packages {
			name := npmNameFromPath(key)
			if name == "" || p.Link || !exactNPMVersion(p.Version) {
				continue // the root project, a workspace link, or a non-registry source
			}
			if p.Name != "" && strings.Contains(key, "node_modules/") && p.Name != name {
				name = p.Name // an aliased install ("npm:pkg@x"): the real package
			}
			out = append(out, Package{Ecosystem: EcosystemNPM, Name: name, Version: p.Version, Dev: p.Dev})
		}
		return out, nil
	}
	if lock.Dependencies == nil {
		if lock.LockfileVersion == 0 {
			return nil, errNotLockfile
		}
		return nil, nil
	}
	var walk func(deps map[string]npmDepV1)
	walk = func(deps map[string]npmDepV1) {
		for name, d := range deps {
			if exactNPMVersion(d.Version) {
				out = append(out, Package{Ecosystem: EcosystemNPM, Name: name, Version: d.Version, Dev: d.Dev})
			}
			walk(d.Dependencies)
		}
	}
	walk(lock.Dependencies)
	return out, nil
}

// npmNameFromPath returns the package name of a v2/v3 "packages" key
// ("node_modules/a/node_modules/@s/b" → "@s/b"), or "" for keys that are not
// installed packages (the root "" or a workspace folder).
func npmNameFromPath(key string) string {
	i := strings.LastIndex(key, "node_modules/")
	if i < 0 {
		return ""
	}
	return key[i+len("node_modules/"):]
}

// exactNPMVersion accepts registry versions only: no URLs, git refs, file:
// links or aliases (they have no OSV advisories under this name).
func exactNPMVersion(v string) bool {
	if v == "" || strings.ContainsAny(v, ":/ ") {
		return false
	}
	_, ok := parseSemver(v)
	return ok
}
