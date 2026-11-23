// Command labrepo is the validation lab's stand-in for GitHub and OSV
// (test_corpus/repos, test_corpus/osv; ADR-0006 §10). It never runs in
// production.
//
//	labrepo serve       --repos DIR --osv DIR [--listen :80]
//	labrepo record      --repos DIR --osv DIR [--osv-url https://api.osv.dev] [--keep]
//	labrepo materialize --repos DIR --out DIR
//
// serve: a GitHub REST subset for repositories "lab/<dir>" (metadata, commit,
// tarball, token revocation; bearer token "lab-token") and an OSV replay
// (querybatch, vulns) that answers ONLY from recorded answers: a query that
// was never recorded is an error (HTTP 500), so a lab run can never pass on
// an answer nobody checked.
//
// record: asks the real OSV API, once, every query the lab repositories
// lead to, and writes the answers (index.json + vulns/<id>.json). The
// recording is committed; the lab then replays it offline. Queries listed in
// <osv>/site-queries.txt ("ecosystem|name|version" per line: the JavaScript
// libraries the site targets load, for js_libraries) are recorded too. With
// --keep, answers already recorded are kept as they are and only new queries
// are asked (so adding a lab target does not re-date the existing answers).
//
// materialize: writes the lab repositories with their planted secrets
// filled in, for the independent tools (gitleaks, osv-scanner).
//
// Planted secrets are templates in the repository files,
// {{secret:<kind>:<seed>}}, filled by internal/labfixture at serve time, so
// no credential-shaped string is ever committed.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1" //nolint:gosec // a fake, deterministic commit id
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/hksolutions/guardhub/apps/scanner/internal/deps"
	"github.com/hksolutions/guardhub/apps/scanner/internal/labfixture"
	"github.com/hksolutions/guardhub/apps/scanner/internal/repo"
)

// LabToken is the only token the stand-in accepts.
const LabToken = "lab-token"

// LabOwner is the owner of every lab repository.
const LabOwner = "lab"

var templateRe = regexp.MustCompile(`\{\{secret:([a-z_]+):([A-Za-z0-9_-]+)\}\}`)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: labrepo serve|record|materialize [flags]")
	}
	fl := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	repos := fl.String("repos", "", "directory with one sub-directory per lab repository")
	osvDir := fl.String("osv", "", "directory with the OSV recording (index.json, vulns/)")
	listen := fl.String("listen", ":80", "serve: listen address")
	osvURL := fl.String("osv-url", deps.DefaultOSVURL, "record: the real OSV API")
	out := fl.String("out", "", "materialize: output directory")
	keep := fl.Bool("keep", false, "record: keep the recorded answers, ask only new queries")
	_ = fl.Parse(os.Args[2:])
	if *repos == "" {
		log.Fatal("--repos is required")
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(*listen, *repos, *osvDir)
	case "record":
		err = record(*repos, *osvDir, *osvURL, *keep)
	case "materialize":
		err = materialize(*repos, *out)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		log.Fatal(err)
	}
}

// ---------------------------------------------------------------- repos

func commitSHA(name string) string {
	sum := sha1.Sum([]byte(LabOwner + "/" + name)) //nolint:gosec // fake commit id
	return hex.EncodeToString(sum[:])
}

func fill(data []byte) ([]byte, error) {
	var ferr error
	outData := templateRe.ReplaceAllFunc(data, func(m []byte) []byte {
		sub := templateRe.FindSubmatch(m)
		v, err := labfixture.Secret(string(sub[1]), string(sub[2]))
		if err != nil {
			ferr = err
			return m
		}
		return []byte(v)
	})
	return outData, ferr
}

// repoFiles returns the files of one lab repository (relative paths, slash
// separated, sorted) with templates filled.
func repoFiles(dir string) (map[string][]byte, []string, error) {
	files := map[string][]byte{}
	var names []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(p) //nolint:gosec // lab fixtures from the repository
		if err != nil {
			return err
		}
		filled, err := fill(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		rel = filepath.ToSlash(rel)
		files[rel] = filled
		names = append(names, rel)
		return nil
	})
	sort.Strings(names)
	return files, names, err
}

func tarballOf(name, dir string) ([]byte, error) {
	files, names, err := repoFiles(dir)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	top := LabOwner + "-" + name + "-" + commitSHA(name)[:7] + "/"
	mod := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := tw.WriteHeader(&tar.Header{Name: top, Typeflag: tar.TypeDir, Mode: 0o755, ModTime: mod}); err != nil {
		return nil, err
	}
	for _, n := range names {
		data := files[n]
		if err := tw.WriteHeader(&tar.Header{Name: top + n, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data)), ModTime: mod}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func repoDir(root, name string) (string, bool) {
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`).MatchString(name) {
		return "", false
	}
	d := filepath.Join(root, name)
	st, err := os.Stat(d)
	return d, err == nil && st.IsDir()
}

// ---------------------------------------------------------------- serve

type osvIndex struct {
	Source  string              `json:"source"`
	Queries map[string][]string `json:"queries"` // "ecosystem|name|version" → advisory ids
}

func queryKey(eco, name, version string) string { return eco + "|" + name + "|" + version }

func serve(listen, reposRoot, osvDir string) error {
	var idx osvIndex
	raw, err := os.ReadFile(filepath.Join(osvDir, "index.json")) //nolint:gosec // lab recording
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &idx); err != nil {
		return err
	}
	mux := http.NewServeMux()
	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+LabToken {
				http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("GET /repos/{owner}/{name}", authed(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := repoDir(reposRoot, r.PathValue("name")); !ok || r.PathValue("owner") != LabOwner {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"default_branch": "main", "full_name": LabOwner + "/" + r.PathValue("name")})
	}))
	mux.HandleFunc("GET /repos/{owner}/{name}/commits/{ref}", authed(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := repoDir(reposRoot, r.PathValue("name")); !ok || r.PathValue("owner") != LabOwner || r.PathValue("ref") != "main" {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(commitSHA(r.PathValue("name"))))
	}))
	mux.HandleFunc("GET /repos/{owner}/{name}/tarball/{ref}", authed(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if _, ok := repoDir(reposRoot, name); !ok || r.PathValue("owner") != LabOwner || r.PathValue("ref") != commitSHA(name) {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		// Like GitHub: a redirect to the archive URL (here: same host).
		http.Redirect(w, r, "/_codeload/"+name+"/"+commitSHA(name), http.StatusFound)
	}))
	mux.HandleFunc("GET /_codeload/{name}/{sha}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		dir, ok := repoDir(reposRoot, name)
		if !ok || r.PathValue("sha") != commitSHA(name) {
			http.NotFound(w, r)
			return
		}
		// (Cross-host token stripping is unit-tested in internal/repo; here
		// the archive is on the same host, as API-internal redirects are.)
		data, err := tarballOf(name, dir)
		if err != nil {
			log.Printf("tarball %s: %v", name, err)
			http.Error(w, "fixture error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-gzip")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("DELETE /installation/token", authed(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Queries []struct {
				Package struct{ Name, Ecosystem string } `json:"package"`
				Version string                           `json:"version"`
			} `json:"queries"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		type vuln struct {
			ID string `json:"id"`
		}
		type result struct {
			Vulns []vuln `json:"vulns,omitempty"`
		}
		resp := struct {
			Results []result `json:"results"`
		}{}
		for _, q := range body.Queries {
			k := queryKey(q.Package.Ecosystem, q.Package.Name, q.Version)
			ids, ok := idx.Queries[k]
			if !ok {
				log.Printf("UNRECORDED OSV query %s (run `labrepo record`)", k)
				http.Error(w, "unrecorded query "+k, http.StatusInternalServerError)
				return
			}
			var res result
			for _, id := range ids {
				res.Vulns = append(res.Vulns, vuln{id})
			}
			resp.Results = append(resp.Results, res)
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if strings.ContainsAny(id, `/\`) || strings.Contains(id, "..") {
			http.NotFound(w, r)
			return
		}
		data, err := os.ReadFile(filepath.Join(osvDir, "vulns", id+".json")) //nolint:gosec // id checked above
		if err != nil {
			log.Printf("UNRECORDED OSV record %s", id)
			http.Error(w, "unrecorded record", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	log.Printf("labrepo serving %s (OSV recording: %s, %d queries)", listen, idx.Source, len(idx.Queries))
	srv := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return srv.ListenAndServe()
}

// ---------------------------------------------------------------- record

func record(reposRoot, osvDir, osvURL string, keep bool) error {
	if osvDir == "" {
		return errors.New("--osv is required")
	}
	entries, err := os.ReadDir(reposRoot)
	if err != nil {
		return err
	}
	var all []deps.Package
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		data, err := tarballOf(e.Name(), filepath.Join(reposRoot, e.Name()))
		if err != nil {
			return err
		}
		// The same path as a scan: tarball → snapshot → lockfile parsing.
		snap, err := repo.ReadTarball(bytes.NewReader(data), repo.DefaultLimits())
		if err != nil {
			return err
		}
		pkgs, errs := deps.FromSnapshot(snap)
		if len(errs) > 0 {
			log.Printf("%s: unreadable manifests (recorded as such): %v", e.Name(), errs)
		}
		all = append(all, pkgs...)
	}
	site, err := siteQueries(filepath.Join(osvDir, "site-queries.txt"))
	if err != nil {
		return err
	}
	all = append(all, site...)
	old := osvIndex{Queries: map[string][]string{}}
	if keep {
		raw, err := os.ReadFile(filepath.Join(osvDir, "index.json")) //nolint:gosec // lab recording
		if err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &old); err != nil {
			return err
		}
	}
	uniq := map[string]deps.Package{}
	for _, p := range all {
		if _, done := old.Queries[queryKey(p.Ecosystem, p.Name, p.Version)]; done {
			continue
		}
		uniq[queryKey(p.Ecosystem, p.Name, p.Version)] = deps.Package{Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version}
	}
	keys := make([]string, 0, len(uniq))
	for k := range uniq {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pkgs := make([]deps.Package, len(keys))
	for i, k := range keys {
		pkgs[i] = uniq[k]
	}
	client := deps.NewOSV(osvURL, http.DefaultTransport, 60*time.Second, 0)
	ctx := context.Background()
	matches, err := client.Matches(ctx, pkgs)
	if err != nil {
		return err
	}
	stamp := osvURL + " recorded " + time.Now().UTC().Format("2006-01-02")
	idx := osvIndex{Source: stamp, Queries: map[string][]string{}}
	if keep {
		idx = old
		if len(keys) > 0 {
			idx.Source = old.Source + "; new queries " + stamp
		}
	}
	var ids []string
	for i, k := range keys {
		idx.Queries[k] = append([]string{}, matches[i]...)
		ids = append(ids, matches[i]...)
	}
	vulnDir := filepath.Join(osvDir, "vulns")
	if !keep {
		if err := os.RemoveAll(vulnDir); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(vulnDir, 0o755); err != nil { //nolint:gosec // lab fixtures
		return err
	}
	recs, err := client.Vulns(ctx, ids)
	if err != nil {
		return err
	}
	for id := range recs {
		if _, err := os.Stat(filepath.Join(vulnDir, id+".json")); keep && err == nil {
			continue // already recorded: kept byte for byte
		}
		raw, err := fetchRaw(ctx, osvURL+"/v1/vulns/"+id)
		if err != nil {
			return err
		}
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, raw, "", " "); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(vulnDir, id+".json"), append(pretty.Bytes(), '\n'), 0o644); err != nil { //nolint:gosec // lab fixtures
			return err
		}
	}
	out, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	log.Printf("recorded %d queries, %d advisories", len(keys), len(recs))
	return os.WriteFile(filepath.Join(osvDir, "index.json"), append(out, '\n'), 0o644) //nolint:gosec // lab fixtures
}

// siteQueries reads "ecosystem|name|version" lines ("#" comments); a missing
// file is no queries.
func siteQueries(path string) ([]deps.Package, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // lab recording
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []deps.Package
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) != 3 {
			return nil, fmt.Errorf("%s: bad line %q (want ecosystem|name|version)", path, line)
		}
		out = append(out, deps.Package{Ecosystem: parts[0], Name: parts[1], Version: parts[2]})
	}
	return out, nil
}

// fetchRaw keeps the record byte-for-byte as OSV serves it (the decoded
// struct drops fields the scanner does not use).
func fetchRaw(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", repo.UserAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(resp.Body)
	return buf.Bytes(), err
}

// ---------------------------------------------------------------- materialize

func materialize(reposRoot, out string) error {
	if out == "" {
		return errors.New("--out is required")
	}
	entries, err := os.ReadDir(reposRoot)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		files, names, err := repoFiles(filepath.Join(reposRoot, e.Name()))
		if err != nil {
			return err
		}
		for _, n := range names {
			dst := filepath.Join(out, e.Name(), filepath.FromSlash(n))
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil { //nolint:gosec // lab output
				return err
			}
			if err := os.WriteFile(dst, files[n], 0o644); err != nil { //nolint:gosec // lab output
				return err
			}
		}
	}
	return nil
}
