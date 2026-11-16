// Package evidence holds the finding contract (contract_gen.go, generated from
// packages/shared/finding.schema.json) and the helpers every check uses to
// build findings: secret masking, payload truncation and stable fingerprints.
// Nothing in here touches the network.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	// MaxPayloadLen is the schema limit for Evidence.RedactedPayload.
	MaxPayloadLen = 2048
	// MaxLocationLen is the schema limit for Evidence.Location.
	MaxLocationLen = 2048
	// MaxParamLen is the schema limit for a single params value.
	MaxParamLen = 256
	// Mask is the prefix that replaces the hidden part of a secret.
	Mask = "****"
	// minRevealLen: values shorter than this are fully masked, because
	// showing their last 4 characters would reveal most of the secret.
	minRevealLen = 9
)

// Fingerprint returns sha256 hex of "check_id|finding_key|location". It is
// stable across scans, so the API can diff scans.
func Fingerprint(checkID, findingKey, location string) string {
	sum := sha256.Sum256([]byte(checkID + "|" + findingKey + "|" + location))
	return hex.EncodeToString(sum[:])
}

// New builds a Finding with the catalog's default severity, truncated
// params/payload/location and its fingerprint. It panics if the check id or
// finding key is not declared in check-ids.json: that is a programming error,
// caught by tests and by the scan runner's recover.
func New(checkID, findingKey string, params map[string]string, kind Kind, location, payload string) Finding {
	keys, ok := FindingKeys[checkID]
	if !ok {
		panic(fmt.Sprintf("evidence: unknown check id %q", checkID))
	}
	sev, ok := keys[findingKey]
	if !ok {
		panic(fmt.Sprintf("evidence: unknown finding key %q for check %q", findingKey, checkID))
	}
	clean := make(map[string]string, len(params))
	for k, v := range params {
		clean[k] = Truncate(v, MaxParamLen)
	}
	location = Truncate(location, MaxLocationLen)
	return Finding{
		CheckID:    checkID,
		FindingKey: findingKey,
		Severity:   sev,
		Params:     clean,
		Evidence: Evidence{
			Kind:            kind,
			Location:        location,
			RedactedPayload: Truncate(payload, MaxPayloadLen),
		},
		Fingerprint: Fingerprint(checkID, findingKey, location),
	}
}

// Truncate shortens s to at most maxLen bytes without splitting a UTF-8
// rune. When it cuts, the result ends with "…" (still within maxLen).
func Truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	const ellipsis = "…"
	cut := maxLen - len(ellipsis)
	if cut < 0 {
		cut = 0
	}
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + ellipsis
}

// MaskSecret hides a secret value, keeping only its last 4 characters
// ("****abcd"). Short values (< 9 chars) are fully masked, because their
// last 4 characters would give away most of the secret. Surrounding quotes
// are ignored. The empty value stays empty.
func MaskSecret(v string) string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, `"'`)
	if v == "" {
		return ""
	}
	r := []rune(v)
	if len(r) < minRevealLen {
		return Mask
	}
	return Mask + string(r[len(r)-4:])
}

var assignmentRe = regexp.MustCompile(`^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.\-]*\s*[=:]\s*)(.*)$`)

// MaskAssignment masks the value of a "KEY=VALUE" / "key = value" /
// "key: value" line. Lines without an assignment are returned unchanged
// unless they look like a bare secret, in which case they are masked whole.
func MaskAssignment(line string) string {
	line = strings.TrimRight(line, "\r")
	if m := assignmentRe.FindStringSubmatch(line); m != nil {
		return m[1] + MaskSecret(m[2])
	}
	return line
}

// MaskLines masks every assignment in text and keeps at most maxLines
// non-empty lines, adding a "… (N more lines)" marker when it drops some.
func MaskLines(text string, maxLines int) string {
	var out []string
	dropped := 0
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.TrimSpace(l) == "" {
			continue
		}
		if len(out) >= maxLines {
			dropped++
			continue
		}
		out = append(out, Truncate(MaskAssignment(l), 200))
	}
	if dropped > 0 {
		out = append(out, fmt.Sprintf("… (%d more lines)", dropped))
	}
	return strings.Join(out, "\n")
}

var urlCredRe = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://)[^/@\s:]+:[^/@\s]+@`)

// MaskURLCredentials replaces "scheme://user:pass@" with "scheme://****@".
func MaskURLCredentials(s string) string {
	return urlCredRe.ReplaceAllString(s, "${1}"+Mask+"@")
}
