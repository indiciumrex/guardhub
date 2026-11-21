package repo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type entry struct {
	name     string
	body     string
	typeflag byte
}

func tarball(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		tf := e.typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: tf}
		if tf == tar.TypeSymlink {
			hdr.Size, hdr.Linkname = 0, e.body
		}
		if tf == tar.TypeDir {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if tf == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func paths(s *Snapshot) []string {
	out := make([]string, len(s.Files))
	for i, f := range s.Files {
		out[i] = f.Path
	}
	return out
}

func TestReadTarballKeepsOnlySafeTextFiles(t *testing.T) {
	data := tarball(t,
		entry{name: "o-r-abc/", typeflag: tar.TypeDir},
		entry{name: "o-r-abc/src/app.js", body: "const x = 1\n"},
		entry{name: "o-r-abc/../../etc/passwd", body: "root:x"},
		entry{name: "o-r-abc/a/../../escape", body: "nope"},
		entry{name: "o-r-abc/link", body: "/etc/passwd", typeflag: tar.TypeSymlink},
		entry{name: "o-r-abc/node_modules/lodash/index.js", body: "vendored"},
		entry{name: "o-r-abc/web/node_modules/x/package-lock.json", body: "{}"},
		entry{name: "o-r-abc/img.png", body: "\x89PNG\r\n\x1a\n\x00\x00"},
		entry{name: "o-r-abc/package-lock.json", body: `{"lockfileVersion":3}`},
		entry{name: "rootfile", body: "outside the top dir"},
	)
	s, err := ReadTarball(bytes.NewReader(data), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(paths(s), ","); got != "package-lock.json,src/app.js" {
		t.Fatalf("kept %q", got)
	}
	if s.Truncated {
		t.Fatal("not truncated")
	}
	if f, ok := s.File("src/app.js"); !ok || string(f.Data) != "const x = 1\n" {
		t.Fatal("File lookup")
	}
}

func TestReadTarballCaps(t *testing.T) {
	lim := DefaultLimits()
	lim.File, lim.Lockfile, lim.Total, lim.MaxFiles = 10, 100, 25, 100
	data := tarball(t,
		entry{name: "r/big.txt", body: strings.Repeat("a", 11)},           // over the file cap: skipped, counted
		entry{name: "r/package-lock.json", body: strings.Repeat("{", 20)}, // lockfile cap is larger
		entry{name: "r/b.txt", body: "12345"},
		entry{name: "r/c.txt", body: "123456"}, // would pass the total: truncated
	)
	s, err := ReadTarball(bytes.NewReader(data), lim)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Truncated || s.SkippedLarge != 1 || strings.Join(paths(s), ",") != "b.txt,package-lock.json" {
		t.Fatalf("snapshot = %+v %v", s, paths(s))
	}
	lim = DefaultLimits()
	lim.Stream = 64 // the compressed stream itself is capped
	s, err = ReadTarball(bytes.NewReader(tarball(t, entry{name: "r/a.txt", body: strings.Repeat("x", 5000)})), lim)
	if err == nil && !s.Truncated {
		t.Fatal("a capped stream must truncate or fail")
	}
}

func TestReadTarballGarbage(t *testing.T) {
	if _, err := ReadTarball(strings.NewReader("not gzip"), DefaultLimits()); !errors.Is(err, ErrBadArchive) {
		t.Fatalf("err = %v", err)
	}
}

func TestLockfileNames(t *testing.T) {
	yes := []string{"package-lock.json", "a/npm-shrinkwrap.json", "uv.lock", "x/poetry.lock", "Pipfile.lock",
		"requirements.txt", "requirements-dev.txt", "requirements/base.txt"}
	no := []string{"package.json", "yarn.lock", "notes.txt", "docs/requirements.md", "pyproject.toml"}
	for _, p := range yes {
		if !IsLockfile(p) {
			t.Errorf("%s should be a lockfile", p)
		}
	}
	for _, p := range no {
		if IsLockfile(p) {
			t.Errorf("%s should not be a lockfile", p)
		}
	}
}

func TestValidFullName(t *testing.T) {
	for _, ok := range []string{"octo/repo", "a-b/c.d_e", "x/.github"} {
		if !ValidFullName(ok) {
			t.Errorf("%s should be valid", ok)
		}
	}
	for _, bad := range []string{"", "octo", "octo/", "/repo", "a/b/c", "-x/y", "x/..", "x/.", "x/y?z", "x/y z"} {
		if ValidFullName(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

const sha = "0123456789abcdef0123456789abcdef01234567"

func fakeGitHub(t *testing.T, tarData []byte, revoked *int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	auth := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /repos/o/r", func(w http.ResponseWriter, r *http.Request) {
		if auth(w, r) {
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
		}
	})
	mux.HandleFunc("GET /repos/o/r/commits/main", func(w http.ResponseWriter, r *http.Request) {
		if auth(w, r) && r.Header.Get("Accept") == "application/vnd.github.sha" {
			_, _ = w.Write([]byte(sha))
		}
	})
	mux.HandleFunc("GET /repos/o/r/tarball/"+sha, func(w http.ResponseWriter, r *http.Request) {
		if auth(w, r) {
			http.Redirect(w, r, "/codeload/o/r/"+sha, http.StatusFound)
		}
	})
	mux.HandleFunc("GET /codeload/o/r/"+sha, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(tarData) })
	mux.HandleFunc("GET /repos/o/elsewhere/tarball/"+sha, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example/x", http.StatusFound)
	})
	mux.HandleFunc("GET /repos/o/gone", func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	mux.HandleFunc("GET /repos/o/empty", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"default_branch":"main"}`))
	})
	mux.HandleFunc("GET /repos/o/empty/commits/main", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Git Repository is empty.", http.StatusConflict)
	})
	mux.HandleFunc("DELETE /installation/token", func(w http.ResponseWriter, r *http.Request) {
		if auth(w, r) {
			*revoked++
			w.WriteHeader(http.StatusNoContent)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestGitHubSnapshotAndRevoke(t *testing.T) {
	revoked := 0
	srv := fakeGitHub(t, tarball(t, entry{name: "o-r-0123456/main.py", body: "print(1)\n"}), &revoked)
	g := NewGitHub(srv.URL+"/", "tok", http.DefaultTransport, 5*time.Second)
	s, err := g.Snapshot(context.Background(), "o/r", DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if s.Repo != "o/r" || s.Commit != sha || strings.Join(paths(s), ",") != "main.py" {
		t.Fatalf("snapshot = %+v", s)
	}
	if err := g.Revoke(context.Background()); err != nil || revoked != 1 {
		t.Fatalf("revoke: %v (%d)", err, revoked)
	}
}

func TestGitHubErrors(t *testing.T) {
	revoked := 0
	srv := fakeGitHub(t, nil, &revoked)
	g := NewGitHub(srv.URL, "tok", http.DefaultTransport, 5*time.Second)
	if _, err := g.Snapshot(context.Background(), "o/gone", DefaultLimits()); !errors.Is(err, ErrAccess) {
		t.Errorf("gone: %v", err)
	}
	if _, err := g.Snapshot(context.Background(), "o/empty", DefaultLimits()); !errors.Is(err, ErrEmptyRepository) {
		t.Errorf("empty: %v", err)
	}
	if _, err := g.Snapshot(context.Background(), "../etc", DefaultLimits()); !errors.Is(err, ErrAccess) {
		t.Errorf("invalid name: %v", err)
	}
	bad := NewGitHub(srv.URL, "wrong", http.DefaultTransport, 5*time.Second)
	if _, err := bad.Snapshot(context.Background(), "o/r", DefaultLimits()); !errors.Is(err, ErrAccess) {
		t.Errorf("bad token: %v", err)
	}
}

func TestGitHubRedirectPolicy(t *testing.T) {
	var sawAuth string
	other := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { sawAuth = r.Header.Get("Authorization") }))
	defer other.Close()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusFound)
	}))
	defer api.Close()
	g := NewGitHub(api.URL, "tok", http.DefaultTransport, 5*time.Second)
	resp, err := g.request(context.Background(), http.MethodGet, "/x", "application/json")
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || !errors.Is(err, ErrUpstream) {
		t.Fatalf("a redirect to an unexpected host must fail: %v", err)
	}
	if sawAuth != "" {
		t.Fatal("the token must never reach another host")
	}
}
