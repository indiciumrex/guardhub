package checks

// exposed_env: looks for publicly downloadable secret files (.env variants,
// the .git directory, AWS credentials). Detection is by file content, never
// by status code; the evidence shows at most a few lines with every value
// masked to its last 4 characters.

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
)

// ExposedEnv implements the exposed_env check.
type ExposedEnv struct{}

// ID implements Check.
func (ExposedEnv) ID() string { return evidence.CheckExposedEnv }

// envPaths are probed in this order.
var envPaths = []string{"/.env", "/.env.local", "/.env.production", "/.env.backup"}

const maxEvidenceLines = 5

var (
	envLineRe    = regexp.MustCompile(`^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S`)
	gitHeadRe    = regexp.MustCompile(`^(ref: refs/[^\s]+|[0-9a-f]{40})$`)
	awsKeyLineRe = regexp.MustCompile(`(?im)^\s*aws_access_key_id\s*=\s*\S+`)
)

// Run implements Check.
func (c ExposedEnv) Run(ctx context.Context, t Target) ([]evidence.Finding, error) {
	f := newFetcher(t)
	base, err := f.baseline(ctx)
	if err != nil {
		return nil, err
	}
	var out []evidence.Finding

	for _, p := range envPaths {
		resp, err := f.get(ctx, p)
		if err != nil {
			return out, err
		}
		if count, ok := envFileSignature(resp, base); ok {
			out = append(out, evidence.New(c.ID(), "env_file_exposed",
				map[string]string{"path": p, "secret_count": strconv.Itoa(count)},
				evidence.KindHttpResponse, t.URL(p), maskedExcerpt(resp.Body)))
		}
	}

	// One Git finding is enough: config is only probed if HEAD is not exposed.
	if resp, err := f.get(ctx, "/.git/HEAD"); err != nil {
		return out, err
	} else if gitHeadSignature(resp, base) {
		out = append(out, evidence.New(c.ID(), "git_repository_exposed", map[string]string{"path": "/.git/HEAD"},
			evidence.KindHttpResponse, t.URL("/.git/HEAD"), maskedExcerpt(resp.Body)))
	} else {
		resp, err := f.get(ctx, "/.git/config")
		if err != nil {
			return out, err
		}
		if gitConfigSignature(resp, base) {
			out = append(out, evidence.New(c.ID(), "git_repository_exposed", map[string]string{"path": "/.git/config"},
				evidence.KindHttpResponse, t.URL("/.git/config"), maskedExcerpt(resp.Body)))
		}
	}

	resp, err := f.get(ctx, "/.aws/credentials")
	if err != nil {
		return out, err
	}
	if awsCredentialsSignature(resp, base) {
		out = append(out, evidence.New(c.ID(), "cloud_credentials_exposed", map[string]string{"path": "/.aws/credentials"},
			evidence.KindHttpResponse, t.URL("/.aws/credentials"), maskedExcerpt(resp.Body)))
	}
	return out, f.done()
}

// usableFileResponse filters out errors, HTML pages (SPA/soft-404 shells)
// and the site's generic unknown-path answer.
func usableFileResponse(resp, base *probe.Response) bool {
	return resp != nil && resp.StatusCode == 200 && len(resp.Body) > 0 &&
		!looksLikeHTML(resp.Body) && !sameAsBaseline(resp, base)
}

// envFileSignature returns the number of KEY=VALUE lines when the body is
// really a dotenv file: at least one assignment, and assignments make up at
// least half of the non-comment lines.
func envFileSignature(resp, base *probe.Response) (int, bool) {
	if !usableFileResponse(resp, base) {
		return 0, false
	}
	assignments, other := 0, 0
	for _, l := range strings.Split(string(resp.Body), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if envLineRe.MatchString(l) {
			assignments++
		} else {
			other++
		}
	}
	return assignments, assignments > 0 && assignments >= other
}

func gitHeadSignature(resp, base *probe.Response) bool {
	return usableFileResponse(resp, base) && gitHeadRe.MatchString(strings.TrimSpace(string(resp.Body)))
}

func gitConfigSignature(resp, base *probe.Response) bool {
	return usableFileResponse(resp, base) && strings.Contains(string(resp.Body), "[core]")
}

func awsCredentialsSignature(resp, base *probe.Response) bool {
	return usableFileResponse(resp, base) && awsKeyLineRe.Match(resp.Body)
}

// maskedExcerpt shows at most maxEvidenceLines non-comment lines with every
// value masked and URL credentials hidden. It never returns a raw secret.
func maskedExcerpt(body []byte) string {
	var lines []string
	for _, l := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		lines = append(lines, evidence.MaskURLCredentials(l))
	}
	return evidence.MaskLines(strings.Join(lines, "\n"), maxEvidenceLines)
}
