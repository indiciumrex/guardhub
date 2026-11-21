package checks

// repo_secrets: credentials committed to the default branch of a connected
// repository (ADR-0006 §9; docs/checks/repo_secrets.md). Provider rules
// (secret_rules.go) plus a stricter generic keyword+entropy rule. Fake keys
// are filtered out: placeholder values everywhere, and every test, fixture
// and example path. Evidence holds the rule, file, line and the last four
// characters, never the value or the line.

import (
	"context"
	"fmt"
	"math"
	"path"
	"sort"
	"strings"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/repo"
)

// RepoSecrets implements repo_secrets.
type RepoSecrets struct{}

// ID implements RepoCheck.
func (RepoSecrets) ID() string { return evidence.CheckRepoSecrets }

type secretHit struct {
	rule       string
	key        string
	paramName  string // secret_type or variable
	paramValue string
	file       string
	line       int
	values     map[string]bool
	firstValue string
}

// RunRepo implements RepoCheck.
func (RepoSecrets) RunRepo(ctx context.Context, snap *repo.Snapshot) ([]evidence.Finding, error) {
	var hits []*secretHit
	for _, f := range snap.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !secretScannable(f.Path) {
			continue
		}
		hits = append(hits, scanFileForSecrets(f)...)
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].file != hits[j].file {
			return hits[i].file < hits[j].file
		}
		return hits[i].rule < hits[j].rule
	})
	findings := make([]evidence.Finding, 0, len(hits))
	for _, h := range hits {
		params := map[string]string{
			h.paramName: h.paramValue,
			"file":      h.file,
			"line":      fmt.Sprint(h.line),
			"count":     fmt.Sprint(len(h.values)),
		}
		payload := fmt.Sprintf("rule %s at %s:%d (commit %s): value %s", h.rule, h.file, h.line, shortSHA(snap.Commit), evidence.MaskSecret(h.firstValue))
		if n := len(h.values); n > 1 {
			payload += fmt.Sprintf(" and %d more in this file", n-1)
		}
		location := repo.BlobURL(snap.Repo, h.file) + "#" + h.rule
		findings = append(findings, evidence.New(evidence.CheckRepoSecrets, h.key, params, evidence.KindRepoFile, location, payload))
	}
	if snap.Truncated {
		return findings, repo.ErrTooLarge
	}
	return findings, nil
}

func scanFileForSecrets(f repo.File) []*secretHit {
	text := string(f.Data)
	byRule := map[string]*secretHit{}
	var order []string
	ruleLines := map[int]bool{} // lines a provider rule matched: no generic finding there
	record := func(rule, key, paramName, paramValue string, offset int, value string) {
		h, ok := byRule[rule]
		if !ok {
			h = &secretHit{rule: rule, key: key, paramName: paramName, paramValue: paramValue, file: f.Path,
				line: lineAt(text, offset), values: map[string]bool{}, firstValue: value}
			byRule[rule] = h
			order = append(order, rule)
		}
		h.values[value] = true
	}
	for _, r := range secretRules {
		if !containsAny(text, r.keywords) {
			continue
		}
		for _, idx := range r.re.FindAllStringSubmatchIndex(text, -1) {
			if idx[2*r.group] < 0 {
				continue
			}
			value := text[idx[2*r.group]:idx[2*r.group+1]]
			m := submatches(text, idx)
			if r.accept != nil && !r.accept(m) {
				continue
			}
			if r.id == "private_key" {
				value = strings.NewReplacer(`\n`, "", `\r`, "", "\n", "", "\r", "", " ", "", "\t", "").Replace(value)
			}
			if placeholderValue(value, false) || (r.minEntropy > 0 && shannon(value) < r.minEntropy) {
				continue
			}
			ruleLines[lineAt(text, idx[0])] = true
			record(r.id, r.key, "secret_type", r.secretType, idx[0], value)
		}
	}
	for _, idx := range genericSecretRe.FindAllStringSubmatchIndex(text, -1) {
		name := text[idx[2]:idx[3]]
		value := text[idx[4]:idx[5]]
		line := lineAt(text, idx[0])
		if ruleLines[line] || genericNameExcluded.MatchString(name) || !genericValue(value) {
			continue
		}
		record("generic", "generic_secret", "variable", name, idx[0], value)
	}
	out := make([]*secretHit, 0, len(order))
	for _, rule := range order {
		out = append(out, byRule[rule])
	}
	return out
}

func submatches(text string, idx []int) []string {
	m := make([]string, len(idx)/2)
	for i := range m {
		if idx[2*i] >= 0 {
			m[i] = text[idx[2*i]:idx[2*i+1]]
		}
	}
	return m
}

func containsAny(s string, subs []string) bool {
	if len(subs) == 0 {
		return true
	}
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func lineAt(text string, offset int) int {
	return strings.Count(text[:offset], "\n") + 1
}

// ----------------------------------------------------------- which files

// testPathParts: directories whose files are tests, fixtures or examples.
// Credentials there are taken to be fakes (the Phase 3 prompt names them as
// false positives); a real key in a test file is a documented miss.
var testPathParts = map[string]bool{
	"test": true, "tests": true, "__tests__": true, "spec": true, "specs": true, "testdata": true,
	"test_data": true, "test-data": true, "fixtures": true, "fixture": true, "__fixtures__": true,
	"mocks": true, "mock": true, "__mocks__": true, "examples": true, "example": true,
	"samples": true, "sample": true, "e2e": true, "cypress": true, "playwright": true, "testing": true,
}

// secretScannable reports whether a file is scanned for secrets.
func secretScannable(p string) bool {
	lp := strings.ToLower(p)
	for _, part := range strings.Split(path.Dir(lp), "/") {
		if testPathParts[part] {
			return false
		}
	}
	base := path.Base(lp)
	switch {
	case repo.IsLockfile(p), strings.HasSuffix(base, ".lock"), base == "go.sum":
		return false // integrity hashes, not secrets
	case strings.HasSuffix(base, ".min.js"), strings.HasSuffix(base, ".min.css"), strings.HasSuffix(base, ".map"), strings.HasSuffix(base, ".svg"):
		return false // minified or generated
	case strings.HasSuffix(base, "_test.go"), strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".py"),
		strings.HasSuffix(base, "_test.py"), base == "conftest.py",
		strings.Contains(base, ".test."), strings.Contains(base, ".spec."):
		return false
	case strings.Contains(base, "example"), strings.Contains(base, "sample"), strings.Contains(base, ".template"),
		strings.Contains(base, ".tmpl"), strings.HasSuffix(base, ".dist"):
		return false // .env.example, config.sample.json, …
	}
	return true
}

// ----------------------------------------------------------- which values

var placeholderWords = []string{
	"example", "sample", "dummy", "fake", "placeholder", "your", "xxxx", "changeme", "change_me", "change-me",
	"redacted", "insert", "replace", "todo", "notreal", "not_real", "not-real", "mock", "secret_here", "here",
	"<", ">", "${", "{{", "%s", "%(", "****", "...",
}

// genericPlaceholderWords also mark generic values (provider values never
// legitimately contain them, generic ones often do when they are fake).
var genericPlaceholderWords = []string{
	"secret", "password", "passwd", "test", "demo", "default", "local", "development", "admin", "qwerty", "letmein",
}

var sequences = []string{"0123456789", "123456", "abcdef", "abcdefgh", "qwerty"}

// placeholderValue reports values that are visibly not real credentials.
func placeholderValue(v string, generic bool) bool {
	lv := strings.ToLower(v)
	for _, w := range placeholderWords {
		if strings.Contains(lv, w) {
			return true
		}
	}
	if generic {
		for _, w := range genericPlaceholderWords {
			if strings.Contains(lv, w) {
				return true
			}
		}
	}
	for _, s := range sequences {
		if strings.Contains(lv, s) {
			return true
		}
	}
	run, prev := 0, rune(0)
	distinct := map[rune]bool{}
	for _, r := range v {
		distinct[r] = true
		if r == prev {
			run++
			if run >= 5 {
				return true
			}
		} else {
			run, prev = 1, r
		}
	}
	return len(v) >= 16 && len(distinct) < 8
}

// genericValue: a quoted value assigned to a secret-sounding name is
// reported only if it looks like a random credential: long enough, mixed,
// high-entropy, not a path/URL/expression and not a placeholder.
func genericValue(v string) bool {
	if len(v) < 16 || strings.ContainsAny(v, "()$ /\\") || strings.HasPrefix(strings.ToLower(v), "http") {
		return false
	}
	if placeholderValue(v, true) {
		return false
	}
	classes := 0
	for _, has := range []func(rune) bool{
		func(r rune) bool { return r >= 'a' && r <= 'z' },
		func(r rune) bool { return r >= 'A' && r <= 'Z' },
		func(r rune) bool { return r >= '0' && r <= '9' },
		func(r rune) bool { return strings.ContainsRune("+-_=.!@#%^&*~:;,?", r) },
	} {
		if strings.IndexFunc(v, has) >= 0 {
			classes++
		}
	}
	return classes >= 2 && strings.IndexFunc(v, func(r rune) bool { return r >= '0' && r <= '9' }) >= 0 && shannon(v) >= 3.5
}

// shannon is the Shannon entropy of s in bits per character.
func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	n := 0
	for _, r := range s {
		counts[r]++
		n++
	}
	var h float64
	for _, c := range counts {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}
