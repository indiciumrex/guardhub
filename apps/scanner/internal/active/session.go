package active

import (
	"errors"
	"strings"
)

// Session is one consented test account of the customer (ADR-0008 §5, IDOR):
// the customer creates two accounts of their own on their own site and hands
// GuardHub their session cookies for one scan. Only Name reaches the request
// log; Cookie and Marker never do.
type Session struct {
	Name   string // "A" or "B": what the request log records
	Cookie string // the Cookie header value, sent only to the scope's origin
	// Marker is text that appears on this account's own data and nowhere
	// public (e.g. the test account's unique e-mail address).
	Marker string
}

// Validate refuses a session that could smuggle headers or match everything.
func (s *Session) Validate() error {
	if s == nil {
		return errors.New("active: nil session")
	}
	if s.Name == "" || s.Cookie == "" || len(strings.TrimSpace(s.Marker)) < 6 {
		return errors.New("active: a session needs a name, a cookie and a marker of at least 6 characters")
	}
	if strings.ContainsAny(s.Cookie+s.Name, "\r\n") || len(s.Cookie) > 4096 {
		return errors.New("active: session cookie must be a single header line under 4 KiB")
	}
	return nil
}

// AsSession sends r with session s's cookie (nil: anonymous). Requests stay
// GET-only and scope-checked like any other; redirects keep the session only
// within the scope (Client.Send never leaves it).
func AsSession(r Request, s *Session) Request {
	r.session = s
	return r
}
