// Package labfixture generates the planted secrets of the validation lab and
// the repo_secrets tests (ADR-0006 §10). Values are derived from a seed, so
// they are deterministic (manifests can pin their last four characters) but
// never appear in the repository: GuardHub's own secret scan and GitHub's
// push protection keep meaning something. None of them is a real credential.
// Production code never imports this package.
package labfixture

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

const (
	alnum    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	upperNum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b64      = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	hexLower = "0123456789abcdef"
	letters  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// Chars returns n characters of alphabet derived from seed (SHA-256 in
// counter mode; modulo bias is irrelevant for fixtures).
func Chars(seed, alphabet string, n int) string {
	var b strings.Builder
	var counter uint64
	for b.Len() < n {
		var c [8]byte
		binary.BigEndian.PutUint64(c[:], counter)
		sum := sha256.Sum256(append([]byte(seed+"|"), c[:]...))
		for _, x := range sum {
			if b.Len() == n {
				break
			}
			b.WriteByte(alphabet[int(x)%len(alphabet)])
		}
		counter++
	}
	return b.String()
}

// generators: kind → value. Kinds are what lab templates name
// ({{secret:<kind>:<seed>}}).
var generators = map[string]func(seed string) string{
	"aws_secret_access_key": func(s string) string { return Chars(s, b64, 40) },
	"github_pat":            func(s string) string { return "ghp_" + Chars(s, alnum, 36) },
	"gitlab_pat":            func(s string) string { return "glpat-" + Chars(s, alnum, 20) },
	"slack_token":           func(s string) string { return "xoxb-" + Chars(s+"1", "0123456789", 12) + "-" + Chars(s+"2", alnum, 24) },
	"slack_webhook": func(s string) string {
		return "https://hooks.slack.com/services/T" + Chars(s+"t", upperNum, 10) + "/B" + Chars(s+"b", upperNum, 10) + "/" + Chars(s, alnum, 24)
	},
	"stripe_live_secret": func(s string) string { return "sk_" + "live_" + Chars(s, alnum, 32) },
	"stripe_test_secret": func(s string) string { return "sk_" + "test_" + Chars(s, alnum, 32) },
	"npm_token":          func(s string) string { return "npm_" + Chars(s, alnum, 36) },
	"sendgrid_key":       func(s string) string { return "SG." + Chars(s+"a", alnum, 22) + "." + Chars(s+"b", alnum, 43) },
	"openai_key": func(s string) string {
		return "sk-proj-" + Chars(s+"a", alnum, 24) + "T3Blbk" + "FJ" + Chars(s+"b", alnum, 24)
	},
	"digitalocean_token": func(s string) string { return "dop_" + "v1_" + Chars(s, hexLower, 64) },
	"huggingface_token":  func(s string) string { return "hf_" + Chars(s, letters, 34) },
	"telegram_bot_token": func(s string) string { return Chars(s+"n", "123456789", 9) + ":AA" + Chars(s, alnum, 33) },
	"password":           func(s string) string { return Chars(s, alnum, 20) },
	"generic":            func(s string) string { return Chars(s+"g", alnum, 32) },
	"private_key":        privateKey,
}

// privateKey is a PEM-shaped block of random base64 (not a parseable key:
// the rule matches the structure, and nothing can use it).
func privateKey(seed string) string {
	var lines []string
	const kind = "RSA " + "PRIVATE KEY" // split: no key-shaped literal in the repository
	lines = append(lines, "-----BEGIN "+kind+"-----")
	body := Chars(seed, b64, 64*12)
	for i := 0; i < len(body); i += 64 {
		lines = append(lines, body[i:i+64])
	}
	lines = append(lines, "-----END "+kind+"-----")
	return strings.Join(lines, "\n")
}

// Secret returns the fixture value of kind for seed.
func Secret(kind, seed string) (string, error) {
	g, ok := generators[kind]
	if !ok {
		return "", fmt.Errorf("labfixture: unknown secret kind %q", kind)
	}
	return g(seed), nil
}

// MustSecret is Secret for tests.
func MustSecret(kind, seed string) string {
	v, err := Secret(kind, seed)
	if err != nil {
		panic(err)
	}
	return v
}

// Kinds lists the known kinds (sorted).
func Kinds() []string {
	out := make([]string, 0, len(generators))
	for k := range generators {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
