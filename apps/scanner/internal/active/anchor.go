package active

import (
	"net/url"
	"regexp"
	"strings"
)

// Anchor shapes: what the parameter's own value must look like before it may
// stand in for {orig}. Neither admits a quote, a space, a semicolon, a comment
// or any SQL syntax, so the anchor is always one literal operand and the
// reviewed text around it is the only logic sent (ADR-0008 §5).
const (
	AnchorNumber = "number" // digits only
	AnchorWord   = "word"   // letters, digits and @ . _ -
)

var anchorShapes = map[string]*regexp.Regexp{
	AnchorNumber: regexp.MustCompile(`^[0-9]{1,18}$`),
	AnchorWord:   regexp.MustCompile(`^[A-Za-z0-9@._-]{1,64}$`),
}

// AnchorFallback replaces a value of any other shape (or none).
const AnchorFallback = "1"

// anchor is the {orig} value for payloads of shape kind on param of target.
func anchor(kind string, target *url.URL, param string) string {
	re, ok := anchorShapes[kind]
	if !ok || target == nil {
		return AnchorFallback
	}
	if v := target.Query().Get(param); re.MatchString(v) && !strings.Contains(v, "--") {
		return v
	}
	return AnchorFallback
}
