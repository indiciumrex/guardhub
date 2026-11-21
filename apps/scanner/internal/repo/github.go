package repo

// GitHub REST client for repo scans (ADR-0006 §2, §6). It uses one
// installation access token minted by the API for exactly one repository
// with contents:read, sends only GETs plus the final token revocation, and
// never writes anything.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// DefaultGitHubAPI is the production API base URL.
const DefaultGitHubAPI = "https://api.github.com"

// codeloadHost serves the tarballs GitHub's API redirects to.
const codeloadHost = "codeload.github.com"

// UserAgent identifies GuardHub to GitHub and OSV.
const UserAgent = "GuardHub-Scanner/1.0 (+https://guardhub.dev/scanner)"

var fullNameRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$`)

// ValidFullName reports whether s is a well-formed "owner/name".
func ValidFullName(s string) bool {
	if !fullNameRe.MatchString(s) {
		return false
	}
	name := s[strings.IndexByte(s, '/')+1:]
	return name != "." && name != ".."
}

// Errors a repo scan maps to scan error codes.
var (
	// ErrAccess: the token cannot read the repository (deleted, renamed
	// away, removed from the installation, app uninstalled) or is invalid.
	ErrAccess = errors.New("repository not accessible")
	// ErrUpstream: GitHub answered with an unexpected status.
	ErrUpstream = errors.New("unexpected answer from GitHub")
	// ErrEmptyRepository: the repository has no commits.
	ErrEmptyRepository = errors.New("repository is empty")
)

// GitHub talks to one GitHub API base with one token.
type GitHub struct {
	API   string // base URL without trailing slash
	Token string
	HTTP  *http.Client
}

// NewGitHub builds a client on transport. Redirects are followed only to the
// API host itself or codeload.github.com (the tarball host), at most three,
// and the Authorization header is dropped whenever the host changes.
func NewGitHub(api, token string, transport http.RoundTripper, timeout time.Duration) *GitHub {
	api = strings.TrimRight(api, "/")
	apiURL, _ := url.Parse(api)
	apiHost := ""
	if apiURL != nil {
		apiHost = apiURL.Host
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("%w: too many redirects", ErrUpstream)
			}
			host := req.URL.Host
			if host != apiHost && host != codeloadHost {
				return fmt.Errorf("%w: redirect to unexpected host %q", ErrUpstream, host)
			}
			if req.URL.Scheme != "https" && host == codeloadHost {
				return fmt.Errorf("%w: insecure redirect", ErrUpstream)
			}
			if host != via[0].URL.Host {
				req.Header.Del("Authorization")
			}
			return nil
		},
	}
	return &GitHub{API: api, Token: token, HTTP: client}
}

func (g *GitHub) request(ctx context.Context, method, p, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, g.API+p, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+g.Token)
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", UserAgent)
	return g.HTTP.Do(req)
}

func statusErr(resp *http.Response, what string) error {
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return fmt.Errorf("%w: %s: HTTP %d", ErrAccess, what, resp.StatusCode)
	case http.StatusConflict: // "Git Repository is empty."
		return fmt.Errorf("%w: %s", ErrEmptyRepository, what)
	default:
		return fmt.Errorf("%w: %s: HTTP %d", ErrUpstream, what, resp.StatusCode)
	}
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
}

// Snapshot reads the default branch of fullName into memory.
func (g *GitHub) Snapshot(ctx context.Context, fullName string, lim Limits) (*Snapshot, error) {
	if !ValidFullName(fullName) {
		return nil, fmt.Errorf("%w: invalid repository name", ErrAccess)
	}
	branch, err := g.defaultBranch(ctx, fullName)
	if err != nil {
		return nil, err
	}
	sha, err := g.commitSHA(ctx, fullName, branch)
	if err != nil {
		return nil, err
	}
	resp, err := g.request(ctx, http.MethodGet, "/repos/"+fullName+"/tarball/"+sha, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return nil, statusErr(resp, "tarball")
	}
	snap, err := ReadTarball(resp.Body, lim)
	if err != nil {
		return nil, err
	}
	snap.Repo, snap.Commit = fullName, sha
	return snap, nil
}

func (g *GitHub) defaultBranch(ctx context.Context, fullName string) (string, error) {
	resp, err := g.request(ctx, http.MethodGet, "/repos/"+fullName, "application/vnd.github+json")
	if err != nil {
		return "", err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return "", statusErr(resp, "repository")
	}
	var meta struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&meta); err != nil || meta.DefaultBranch == "" {
		return "", fmt.Errorf("%w: repository metadata", ErrUpstream)
	}
	return meta.DefaultBranch, nil
}

var shaRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

func (g *GitHub) commitSHA(ctx context.Context, fullName, branch string) (string, error) {
	resp, err := g.request(ctx, http.MethodGet, "/repos/"+fullName+"/commits/"+url.PathEscape(branch), "application/vnd.github.sha")
	if err != nil {
		return "", err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return "", statusErr(resp, "commit")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return "", err
	}
	sha := strings.TrimSpace(string(raw))
	if !shaRe.MatchString(sha) {
		return "", fmt.Errorf("%w: commit sha", ErrUpstream)
	}
	return sha, nil
}

// Revoke invalidates the token at GitHub (DELETE /installation/token). The
// scan calls it when it ends, success or not; the token would expire within
// the hour anyway.
func (g *GitHub) Revoke(ctx context.Context) error {
	resp, err := g.request(ctx, http.MethodDelete, "/installation/token", "application/vnd.github+json")
	if err != nil {
		return err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("%w: revoke: HTTP %d", ErrUpstream, resp.StatusCode)
	}
	return nil
}

// BlobURL is the stable, human-facing location of a file in the repository
// (no commit, no line: evidence locations must stay the same across commits
// so scan diffs work; the commit and line are in the evidence payload).
func BlobURL(fullName, p string) string {
	return "https://github.com/" + fullName + "/blob/HEAD/" + p
}
