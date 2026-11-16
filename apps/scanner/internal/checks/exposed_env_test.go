package checks

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
)

const envBody = `# production settings
DB_PASSWORD=sup3r-s3cret-password-abcd
STRIPE_SECRET_KEY="sk_live_51HxYzQwErTyUiOp9xyz"
export AWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
APP_NAME=acme
DEBUG=false
SESSION_SECRET=0123456789abcdef0123456789abcdef
JWT_SECRET=another-very-long-secret-0000
`

var rawSecrets = []string{
	"sup3r-s3cret-password-abcd", "sk_live_51HxYzQwErTyUiOp9xyz", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	"0123456789abcdef0123456789abcdef", "another-very-long-secret-0000", "AKIAIOSFODNN7EXAMPLE",
	"wJalrXUtnFEMI/K7MDENG/bPxRfiCYzzzzzzzzzz", "ghp_tokenvalue1234567",
}

func TestExposedEnvPositive(t *testing.T) {
	srv := site(t, false, map[string]http.HandlerFunc{
		"/.env":             text(envBody),
		"/.git/HEAD":        text("ref: refs/heads/main\n"),
		"/.git/config":      text("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://deploy:ghp_tokenvalue1234567@github.com/acme/app.git\n"),
		"/.aws/credentials": text("[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = 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\n"),
	})
	fs := run(t, ExposedEnv{}, srv.URL)
	requireKeys(t, fs, "env_file_exposed", "git_repository_exposed", "cloud_credentials_exposed")

	env := findKey(t, fs, "env_file_exposed")
	if env.Params["path"] != "/.env" || env.Params["secret_count"] != "7" {
		t.Fatalf("params = %v", env.Params)
	}
	if !strings.Contains(env.Evidence.RedactedPayload, "DB_PASSWORD=****abcd") {
		t.Fatalf("expected masked line, got %q", env.Evidence.RedactedPayload)
	}
	if n := strings.Count(env.Evidence.RedactedPayload, "\n") + 1; n > 6 {
		t.Fatalf("evidence too long: %d lines", n)
	}
	if git := findKey(t, fs, "git_repository_exposed"); git.Params["path"] != "/.git/HEAD" {
		t.Fatalf("git path %v", git.Params)
	}

	// No raw secret may appear anywhere in the serialised findings.
	js, _ := json.Marshal(fs)
	for _, s := range rawSecrets {
		if strings.Contains(string(js), s) {
			t.Fatalf("raw secret %q leaked: %s", s, js)
		}
	}
}

func TestExposedEnvGitConfigOnlyMasksCredentials(t *testing.T) {
	srv := site(t, false, map[string]http.HandlerFunc{
		"/.git/config": text("[core]\n\tbare = false\n[remote \"origin\"]\n\turl = https://deploy:ghp_tokenvalue1234567@github.com/acme/app.git\n"),
	})
	fs := run(t, ExposedEnv{}, srv.URL)
	requireKeys(t, fs, "git_repository_exposed")
	f := fs[0]
	if f.Params["path"] != "/.git/config" || strings.Contains(f.Evidence.RedactedPayload, "ghp_tokenvalue1234567") {
		t.Fatalf("bad finding %+v", f)
	}
}

func TestExposedEnvNegative(t *testing.T) {
	// Soft-404 SPA: every path answers 200 with the HTML shell.
	srv := site(t, true, nil)
	requireKeys(t, run(t, ExposedEnv{}, srv.URL))

	// Catch-all that answers the same plain text for every path.
	catchAll := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("MAINTENANCE=true\n"))
	}))
	defer catchAll.Close()
	requireKeys(t, run(t, ExposedEnv{}, catchAll.URL))

	// Real 404s, and files that exist but are not env files.
	srv2 := site(t, false, map[string]http.HandlerFunc{
		"/.env":             text("this is not an env file\njust some words\nhere\n"),
		"/.git/HEAD":        text("not a git head"),
		"/.aws/credentials": html("<html><body>aws_access_key_id = nope</body></html>"),
	})
	requireKeys(t, run(t, ExposedEnv{}, srv2.URL))

	// 403 with env-looking content is not exposure.
	srv3 := site(t, false, map[string]http.HandlerFunc{
		"/.env": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("A=1\n"))
		},
	})
	requireKeys(t, run(t, ExposedEnv{}, srv3.URL))
}

func TestCheckStopsOnBudget(t *testing.T) {
	srv := site(t, false, nil)
	c := probe.New(probe.Options{AllowPrivateHosts: []string{"127.0.0.1"}, HostRPS: 1000, HostBurst: 100, MaxRequests: 2})
	tg, _ := NewTarget(srv.URL, c)
	_, err := ExposedEnv{}.Run(context.Background(), tg)
	if !errors.Is(err, probe.ErrBudgetExceeded) {
		t.Fatalf("expected budget error, got %v", err)
	}
	if c.RequestsUsed() != 2 {
		t.Fatalf("used %d", c.RequestsUsed())
	}
}

func TestCheckReportsUnreachable(t *testing.T) {
	srv := site(t, false, nil)
	url := srv.URL
	srv.Close()
	tg := targetFor(t, url)
	if _, err := (ExposedEnv{}).Run(context.Background(), tg); !errors.Is(err, ErrTargetUnreachable) {
		t.Fatalf("expected unreachable, got %v", err)
	}
}
