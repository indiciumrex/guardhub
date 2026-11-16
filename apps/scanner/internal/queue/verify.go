package queue

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/hksolutions/guardhub/apps/scanner/internal/checks"
	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
)

// Ownership proof locations (ADR-0001).
const (
	wellKnownPath  = "/.well-known/guardhub-verify.txt"
	metaName       = "guardhub-verification"
	dnsValuePrefix = "guardhub-verify="
	dnsLabel       = "_guardhub."
)

var (
	metaTagRe = regexp.MustCompile(`(?is)<meta\b[^>]*>`)
	attrRe    = regexp.MustCompile(`(?is)([a-z][a-z0-9_:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>/]+))`)
)

// verifyOutcome is the result of an ownership check before it is sent.
type verifyOutcome struct {
	method string // "" when not verified
	errMsg string // "" when verified
}

// runVerify checks the ownership proof for a verify job and replies.
func (s *Service) runVerify(jobCtx context.Context, job Job) error {
	vctx, cancel := context.WithTimeout(jobCtx, s.verifyDeadline())
	defer cancel()
	client := s.NewVerifyProbe()
	defer client.Close()

	origin, _ := checks.ParseOrigin(job.Target) // validated by ParseJob
	out := verifyOwnership(vctx, client, origin.Scheme+"://"+origin.Host, strings.ToLower(origin.Hostname()), job.Token)
	if jobCtx.Err() != nil {
		return errShutdown
	}
	return s.replyVerify(jobCtx, job, out)
}

func (s *Service) replyVerify(ctx context.Context, job Job, out verifyOutcome) error {
	reply := VerifyReply{V: ProtocolVersion, JobID: job.JobID, Verified: out.method != ""}
	if out.method != "" {
		reply.Method = strPtr(out.method)
	} else {
		reply.Error = strPtr(out.errMsg)
	}
	if err := pushVerifyReply(ctx, s.RDB, job.ReplyKey, reply); err != nil {
		return fmt.Errorf("push verify reply: %w", err)
	}
	s.log().Info("verify done", "job_id", job.JobID, "target", job.Target, "verified", reply.Verified, "method", out.method, "error_code", out.errMsg)
	return nil
}

// verifyOwnership tries, in order: the well-known file, the meta tag on the
// home page, then DNS TXT on _guardhub.<host> and <host>.
func verifyOwnership(ctx context.Context, c *probe.Client, origin, host, token string) verifyOutcome {
	if err := c.CheckHost(ctx, host); err != nil {
		return verifyFailure(ctx, err)
	}

	httpFailures := 0
	var lastErr error
	if resp, err := c.Get(ctx, origin+wellKnownPath); err != nil {
		if errors.Is(err, probe.ErrBlockedAddress) || ctx.Err() != nil {
			return verifyFailure(ctx, err)
		}
		httpFailures, lastErr = httpFailures+1, err
	} else if resp.StatusCode == 200 && wellKnownMatches(resp.Body, token) {
		return verifyOutcome{method: MethodWellKnown}
	}

	if resp, err := c.Get(ctx, origin+"/"); err != nil {
		if errors.Is(err, probe.ErrBlockedAddress) || ctx.Err() != nil {
			return verifyFailure(ctx, err)
		}
		httpFailures, lastErr = httpFailures+1, err
	} else if resp.StatusCode == 200 && metaTagMatches(resp.Body, token) {
		return verifyOutcome{method: MethodMetaTag}
	}

	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err != nil { // DNS only for hostnames
		for _, name := range []string{dnsLabel + host, host} {
			records, err := c.LookupTXT(ctx, name)
			if err != nil {
				if ctx.Err() != nil {
					return verifyFailure(ctx, err)
				}
				continue
			}
			if txtMatches(records, token) {
				return verifyOutcome{method: MethodDNSTXT}
			}
		}
	}

	if httpFailures == 2 {
		return verifyFailure(ctx, lastErr)
	}
	return verifyOutcome{errMsg: VerifyErrNotFound}
}

func verifyFailure(ctx context.Context, err error) verifyOutcome {
	switch {
	case errors.Is(err, probe.ErrBlockedAddress):
		return verifyOutcome{errMsg: VerifyErrBlocked}
	case ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded):
		return verifyOutcome{errMsg: VerifyErrTimeout}
	default:
		return verifyOutcome{errMsg: VerifyErrUnreachable}
	}
}

func equalToken(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// wellKnownMatches: trimmed body equals the token, or one line equals it.
func wellKnownMatches(body []byte, token string) bool {
	text := strings.TrimSpace(string(body))
	if equalToken(text, token) {
		return true
	}
	for _, line := range strings.Split(text, "\n") {
		if equalToken(strings.TrimSpace(line), token) {
			return true
		}
	}
	return false
}

// metaTagMatches finds <meta name="guardhub-verification" content="TOKEN">
// with attributes in any order and either quote style.
func metaTagMatches(body []byte, token string) bool {
	for _, tag := range metaTagRe.FindAll(body, -1) {
		var name, content string
		for _, m := range attrRe.FindAllSubmatch(tag, -1) {
			val := string(m[2]) + string(m[3]) + string(m[4])
			switch strings.ToLower(string(m[1])) {
			case "name":
				name = val
			case "content":
				content = val
			}
		}
		if strings.EqualFold(strings.TrimSpace(name), metaName) && equalToken(strings.TrimSpace(content), token) {
			return true
		}
	}
	return false
}

// txtMatches: a TXT record equal to "guardhub-verify=TOKEN".
func txtMatches(records []string, token string) bool {
	for _, r := range records {
		if equalToken(strings.TrimSpace(r), dnsValuePrefix+token) {
			return true
		}
	}
	return false
}
