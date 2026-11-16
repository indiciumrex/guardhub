package observability

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/getsentry/sentry-go"
)

// Filtered replaces every removed value.
const Filtered = "[Filtered]"

// sensitiveKeys are matched case-insensitively with "-" treated as "_".
var sensitiveKeys = map[string]bool{}

func init() {
	for _, k := range []string{
		"authorization", "proxy-authorization", "cookie", "cookies", "set-cookie",
		"x-scan-token", "x-guardhub-csrf", "x-forwarded-for", "x-real-ip", "forwarded",
		"remote_addr", "ip_address", "client_ip", "password", "passwd", "secret", "token",
		"access_token", "refresh_token", "api_key", "apikey", "totp", "code", "otp", "jwt",
		"session", "gh_session", "dsn", "redis_url", "query_string", "body",
	} {
		sensitiveKeys[normKey(k)] = true
	}
}

// safeHeaders are the only request headers kept on an event.
var safeHeaders = map[string]bool{
	"user-agent": true, "accept": true, "accept-language": true, "content-type": true, "content-length": true,
}

var (
	reUserinfo = regexp.MustCompile(`\b([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s@]*@`)
	reQuery    = regexp.MustCompile(`\b([a-zA-Z][a-zA-Z0-9+.-]*://[^\s?#"'<>]*)\?[^\s#"'<>]*`)
	reJWT      = regexp.MustCompile(`\beyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]{5,}`)
	reGHToken  = regexp.MustCompile(`\bgh[a-z]_[A-Za-z0-9_-]{8,}`)
	reBearer   = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`)
	reEmail    = regexp.MustCompile(`\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b`)
	reIPv4     = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
)

func normKey(k string) string { return strings.ReplaceAll(strings.ToLower(k), "-", "_") }

func isSensitive(k string) bool { return sensitiveKeys[normKey(k)] }

// ScrubText removes URL credentials, query strings, tokens, e-mail and IPv4
// addresses from free text (messages, error strings).
func ScrubText(s string) string {
	s = reUserinfo.ReplaceAllString(s, "${1}"+Filtered+"@")
	s = reQuery.ReplaceAllString(s, "${1}?"+Filtered)
	s = reJWT.ReplaceAllString(s, Filtered)
	s = reGHToken.ReplaceAllString(s, Filtered)
	s = reBearer.ReplaceAllString(s, "${1} "+Filtered)
	s = reEmail.ReplaceAllString(s, Filtered)
	return reIPv4.ReplaceAllString(s, Filtered)
}

func scrubAny(v interface{}) interface{} {
	switch t := v.(type) {
	case string:
		return ScrubText(t)
	case map[string]interface{}:
		return scrubMap(t)
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, x := range t {
			out[i] = scrubAny(x)
		}
		return out
	case []string:
		out := make([]string, len(t))
		for i, x := range t {
			out[i] = ScrubText(x)
		}
		return out
	default:
		return v
	}
}

func scrubMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		if isSensitive(k) {
			out[k] = Filtered
			continue
		}
		out[k] = scrubAny(v)
	}
	return out
}

func stripURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return Filtered
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	return u.String()
}

func scrubStacktrace(st *sentry.Stacktrace) {
	if st == nil {
		return
	}
	for i := range st.Frames {
		st.Frames[i].Vars = nil
	}
}

func scrubBreadcrumb(b *sentry.Breadcrumb) *sentry.Breadcrumb {
	if b == nil {
		return nil
	}
	b.Message = ScrubText(b.Message)
	b.Data = scrubMap(b.Data)
	return b
}

// Scrub is the privacy filter applied to every event before it is sent.
func Scrub(e *sentry.Event) *sentry.Event {
	if e == nil {
		return nil
	}
	e.User = sentry.User{} // no ids, e-mails or IP addresses
	if e.Request != nil {
		req := &sentry.Request{Method: e.Request.Method}
		if e.Request.URL != "" {
			req.URL = stripURL(e.Request.URL)
		}
		for k, v := range e.Request.Headers {
			if safeHeaders[strings.ToLower(k)] {
				if req.Headers == nil {
					req.Headers = map[string]string{}
				}
				req.Headers[k] = ScrubText(v)
			}
		}
		// Data (body), QueryString, Cookies and Env (REMOTE_ADDR) are never kept.
		e.Request = req
	}
	e.Message = ScrubText(e.Message)
	for i := range e.Exception {
		e.Exception[i].Value = ScrubText(e.Exception[i].Value)
		scrubStacktrace(e.Exception[i].Stacktrace)
	}
	for i := range e.Threads {
		scrubStacktrace(e.Threads[i].Stacktrace)
	}
	for name, c := range e.Contexts {
		e.Contexts[name] = scrubMap(c)
	}
	for k, v := range e.Tags {
		if isSensitive(k) {
			e.Tags[k] = Filtered
		} else {
			e.Tags[k] = ScrubText(v)
		}
	}
	for _, b := range e.Breadcrumbs {
		scrubBreadcrumb(b)
	}
	return e
}
