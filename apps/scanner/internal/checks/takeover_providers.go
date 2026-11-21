package checks

// The curated provider list of subdomain_takeover (takeover_providers.yaml,
// embedded at build time). Rules for what may be listed are in the YAML.

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed takeover_providers.yaml
var takeoverProvidersYAML []byte

type takeoverKind string

const (
	takeoverHTTP     takeoverKind = "http"
	takeoverNXDomain takeoverKind = "nxdomain"
)

type takeoverProvider struct {
	Name         string       `yaml:"name"`
	Kind         takeoverKind `yaml:"kind"`
	CNAMEs       []string     `yaml:"cnames"`
	CNAMERegex   string       `yaml:"cname_regex"`
	Regex        bool         `yaml:"regex"`
	Fingerprints []string     `yaml:"fingerprints"`

	cnameRe *regexp.Regexp
	fpRes   []*regexp.Regexp
}

type takeoverCatalog struct {
	Version   int                `yaml:"version"`
	Reviewed  string             `yaml:"reviewed"`
	Providers []takeoverProvider `yaml:"providers"`
}

// takeoverProviders is parsed once; a broken file is a programming error
// (caught by TestTakeoverProvidersLoad and at scanner start).
var takeoverProviders = mustLoadTakeoverProviders(takeoverProvidersYAML)

func mustLoadTakeoverProviders(raw []byte) []takeoverProvider {
	ps, err := loadTakeoverProviders(raw)
	if err != nil {
		panic(err)
	}
	return ps
}

func loadTakeoverProviders(raw []byte) ([]takeoverProvider, error) {
	var cat takeoverCatalog
	if err := yaml.Unmarshal(raw, &cat); err != nil {
		return nil, fmt.Errorf("takeover providers: %w", err)
	}
	if cat.Version != 1 || len(cat.Providers) == 0 {
		return nil, fmt.Errorf("takeover providers: unsupported version %d or empty list", cat.Version)
	}
	for i := range cat.Providers {
		p := &cat.Providers[i]
		if p.Name == "" || len(p.CNAMEs) == 0 {
			return nil, fmt.Errorf("takeover providers: %q needs a name and at least one cname", p.Name)
		}
		for j, c := range p.CNAMEs {
			p.CNAMEs[j] = strings.ToLower(strings.Trim(c, ". "))
			if !strings.Contains(p.CNAMEs[j], ".") {
				return nil, fmt.Errorf("takeover providers: %s: cname %q is not a domain", p.Name, c)
			}
		}
		if p.CNAMERegex != "" {
			re, err := regexp.Compile(p.CNAMERegex)
			if err != nil {
				return nil, fmt.Errorf("takeover providers: %s: %w", p.Name, err)
			}
			p.cnameRe = re
		}
		switch p.Kind {
		case takeoverNXDomain:
			if len(p.Fingerprints) != 0 {
				return nil, fmt.Errorf("takeover providers: %s: an nxdomain provider has no HTTP fingerprints", p.Name)
			}
		case takeoverHTTP:
			if len(p.Fingerprints) == 0 {
				return nil, fmt.Errorf("takeover providers: %s: an http provider needs a fingerprint", p.Name)
			}
			for _, fp := range p.Fingerprints {
				// Short fingerprints match ordinary pages: refuse them.
				if len(strings.TrimSpace(fp)) < 12 {
					return nil, fmt.Errorf("takeover providers: %s: fingerprint %q is too generic", p.Name, fp)
				}
				if p.Regex {
					re, err := regexp.Compile(fp)
					if err != nil {
						return nil, fmt.Errorf("takeover providers: %s: %w", p.Name, err)
					}
					p.fpRes = append(p.fpRes, re)
				}
			}
		default:
			return nil, fmt.Errorf("takeover providers: %s: unknown kind %q", p.Name, p.Kind)
		}
	}
	return cat.Providers, nil
}

// matches reports whether a CNAME target lies inside the provider: equal to a
// listed domain or below it on a label boundary ("x.s3.amazonaws.com", never
// "evils3.amazonaws.com.attacker.test").
func (p *takeoverProvider) matches(target string) bool {
	target = strings.ToLower(strings.TrimSuffix(target, "."))
	for _, c := range p.CNAMEs {
		if target == c || strings.HasSuffix(target, "."+c) {
			return true
		}
	}
	return p.cnameRe != nil && p.cnameRe.MatchString(target)
}

// fingerprint returns the provider's "unclaimed" fingerprint found in body.
func (p *takeoverProvider) fingerprint(body []byte) (string, bool) {
	if p.Regex {
		for _, re := range p.fpRes {
			if m := re.Find(body); m != nil {
				return re.String(), true
			}
		}
		return "", false
	}
	for _, fp := range p.Fingerprints {
		if strings.Contains(string(body), fp) {
			return fp, true
		}
	}
	return "", false
}

// providerFor returns the curated provider any hop of the CNAME chain points
// into, or nil.
func providerFor(chain []string) *takeoverProvider {
	for _, target := range chain {
		for i := range takeoverProviders {
			if takeoverProviders[i].matches(target) {
				return &takeoverProviders[i]
			}
		}
	}
	return nil
}
