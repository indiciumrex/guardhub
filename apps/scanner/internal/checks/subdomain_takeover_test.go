package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
)

// takeoverWeb plays the CT search service (path /ct) and the providers' web
// front (by Host header).
type takeoverWeb struct {
	mu       sync.Mutex
	ct       []string          // names the CT service returns
	ctStatus int               // 0 = 200
	pages    map[string]string // host → body (status 404 unless it starts with "200 ")
	ctQuery  string
	hosts    []string
	methods  []string
}

func (w *takeoverWeb) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.methods = append(w.methods, r.Method)
	if r.URL.Path == "/ct" {
		w.ctQuery = r.URL.Query().Get("q")
		if w.ctStatus != 0 {
			rw.WriteHeader(w.ctStatus)
			return
		}
		var entries []map[string]any
		for i, n := range w.ct {
			entries = append(entries, map[string]any{"id": i, "common_name": n, "name_value": n + "\n" + n})
		}
		_ = json.NewEncoder(rw).Encode(entries)
		return
	}
	h := strings.TrimPrefix(r.URL.Path, "/site/")
	w.hosts = append(w.hosts, h)
	body, ok := w.pages[h]
	switch {
	case !ok:
		rw.WriteHeader(http.StatusNotFound)
		_, _ = rw.Write([]byte("<html><body>Not Found</body></html>"))
	case strings.HasPrefix(body, "200 "):
		_, _ = rw.Write([]byte(body[4:]))
	default:
		rw.WriteHeader(http.StatusNotFound)
		_, _ = rw.Write([]byte(body))
	}
}

type takeoverEnv struct {
	dns *fakeDNS
	web *takeoverWeb
	srv *httptest.Server
}

func newTakeoverEnv(t *testing.T) *takeoverEnv {
	t.Helper()
	e := &takeoverEnv{dns: newFakeDNS(t), web: &takeoverWeb{pages: map[string]string{}}}
	e.srv = httptest.NewServer(e.web)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *takeoverEnv) run(t *testing.T, host string, ctURL string) ([]evidence.Finding, *probe.Client, error) {
	t.Helper()
	if ctURL == "" {
		ctURL = e.srv.URL + "/ct"
	}
	client := probe.New(probe.Options{
		AllowPrivateHosts: []string{"127.0.0.1"},
		HostRPS:           1000, HostBurst: 100, Timeout: 2 * time.Second, MaxRequests: 500,
		DNSServer: e.dns.addr,
	})
	t.Cleanup(client.Close)
	tg, err := NewTarget("https://"+host, client)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := SubdomainTakeover{CTURL: ctURL, fetchURL: func(scheme, name string) string {
		if scheme != "http" {
			return "https://127.0.0.1:1/" // nothing listens: like a provider without TLS
		}
		return e.srv.URL + "/site/" + name
	}}.Run(context.Background(), tg)
	validateFindings(t, fs)
	return fs, client, err
}

func findingSummary(fs []evidence.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.FindingKey+":"+f.Params["subdomain"])
	}
	sort.Strings(out)
	return out
}

func TestSubdomainTakeoverCases(t *testing.T) {
	const host = "example.test"
	cases := []struct {
		name  string
		ct    []string
		dns   []string
		pages map[string]string
		want  string // comma-joined "key:subdomain", sorted
	}{
		{"S3 bucket gone (CT) -> high", []string{"assets.example.test"},
			[]string{"assets.example.test. 300 IN CNAME assets.example.test.s3.amazonaws.com.", "assets.example.test.s3.amazonaws.com. 300 IN A 192.0.2.10"},
			map[string]string{"assets.example.test": `<?xml version="1.0"?><Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>`},
			"unclaimed_resource:assets.example.test"},
		{"S3 bucket exists (private, AccessDenied) -> nothing", []string{"files.example.test"},
			[]string{"files.example.test. 300 IN CNAME files.s3.eu-west-1.amazonaws.com.", "files.s3.eu-west-1.amazonaws.com. 300 IN A 192.0.2.10"},
			map[string]string{"files.example.test": `<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`},
			""},
		{"claimed Bitbucket site -> nothing", []string{"docs.example.test"},
			[]string{"docs.example.test. 300 IN CNAME acme.bitbucket.io.", "acme.bitbucket.io. 300 IN A 192.0.2.11"},
			map[string]string{"docs.example.test": "200 <html><title>Acme docs</title></html>"},
			""},
		{"claimed site whose 200 page mentions the fingerprint -> nothing", []string{"docs.example.test"},
			[]string{"docs.example.test. 300 IN CNAME acme.bitbucket.io.", "acme.bitbucket.io. 300 IN A 192.0.2.11"},
			map[string]string{"docs.example.test": "200 <p>Seeing Repository not found? Check the repository name.</p>"},
			""},
		{"Azure name deleted (NXDOMAIN) -> high", []string{"app.example.test"},
			[]string{"app.example.test. 300 IN CNAME acme-old.azurewebsites.net."},
			nil, "unclaimed_resource:app.example.test"},
		{"Azure name alive -> nothing", []string{"app.example.test"},
			[]string{"app.example.test. 300 IN CNAME acme.azurewebsites.net.", "acme.azurewebsites.net. 300 IN A 192.0.2.12"},
			nil, ""},
		{"edge-case provider (GitHub Pages) with its fingerprint -> nothing", []string{"blog.example.test"},
			[]string{"blog.example.test. 300 IN CNAME acme.github.io.", "acme.github.io. 300 IN A 192.0.2.13"},
			map[string]string{"blog.example.test": "There isn't a GitHub Pages site here."},
			""},
		{"unlisted provider showing a listed fingerprint -> nothing", []string{"help.example.test"},
			[]string{"help.example.test. 300 IN CNAME acme.pages-host.test.", "acme.pages-host.test. 300 IN A 192.0.2.14"},
			map[string]string{"help.example.test": "Repository not found"},
			""},
		{"listed suffix only as a label prefix (bitbucket.io.evil.test) -> nothing", []string{"x.example.test"},
			[]string{"x.example.test. 300 IN CNAME acme.bitbucket.io.evil.test.", "acme.bitbucket.io.evil.test. 300 IN A 192.0.2.15"},
			map[string]string{"x.example.test": "Repository not found"},
			""},
		{"CNAME to a missing name of another domain -> low", []string{"old.example.test"},
			[]string{"old.example.test. 300 IN CNAME site.gone-cdn.test."},
			nil, "dangling_cname:old.example.test"},
		{"CNAME to a missing name in the owner's own domain -> nothing", []string{"legacy.example.test"},
			[]string{"legacy.example.test. 300 IN CNAME gone.example.test."},
			nil, ""},
		{"plain A record, and a CT name that no longer exists -> nothing", []string{"www.example.test", "removed.example.test"},
			[]string{"www.example.test. 300 IN A 192.0.2.16"},
			nil, ""},
		{"two-hop chain into S3, gone -> high", []string{"cdn.example.test"},
			[]string{"cdn.example.test. 300 IN CNAME edge.example.test.", "edge.example.test. 300 IN CNAME b.s3-website-us-east-1.amazonaws.com.", "b.s3-website-us-east-1.amazonaws.com. 300 IN A 192.0.2.17"},
			map[string]string{"cdn.example.test": "<html><h1>404 Not Found</h1><ul><li>Code: NoSuchBucket</li><li>Message: The specified bucket does not exist</li></ul></html>"},
			"unclaimed_resource:cdn.example.test"},
		{"common name found without CT (blog) -> high", nil,
			[]string{"blog.example.test. 300 IN CNAME acme.surge.sh.", "acme.surge.sh. 300 IN A 192.0.2.18"},
			map[string]string{"blog.example.test": "project not found"},
			"unclaimed_resource:blog.example.test"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newTakeoverEnv(t)
			e.dns.configure(func(f *fakeDNS) { f.add(c.dns...) })
			e.web.ct, e.web.pages = c.ct, c.pages
			if e.web.pages == nil {
				e.web.pages = map[string]string{}
			}
			fs, _, err := e.run(t, host, "")
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(findingSummary(fs), ","); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
			for _, f := range fs {
				wantSev := map[string]string{"unclaimed_resource": "high", "dangling_cname": "low"}[f.FindingKey]
				if string(f.Severity) != wantSev {
					t.Errorf("%s severity %s", f.FindingKey, f.Severity)
				}
			}
			if e.web.ctQuery != "%."+host {
				t.Errorf("CT query %q", e.web.ctQuery)
			}
			for _, m := range e.web.methods {
				if m != http.MethodGet {
					t.Errorf("non-GET request sent: %s", m)
				}
			}
		})
	}
}

// §9.2: CT names outside the verified host (parent, siblings, look-alikes)
// are dropped unread: no DNS query, no HTTP request, no finding.
func TestSubdomainTakeoverStaysInScope(t *testing.T) {
	e := newTakeoverEnv(t)
	out := []string{"example.test", "other.example.test", "evilshop.example.test", "shop.example.test.evil.test", "x.other.test"}
	e.dns.configure(func(f *fakeDNS) {
		for _, n := range out {
			f.add(n + ". 300 IN CNAME gone.azurewebsites.net.")
		}
	})
	e.web.ct = append([]string{"*.shop.example.test"}, out...)
	fs, _, err := e.run(t, "shop.example.test", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("out-of-scope names reported: %v", findingSummary(fs))
	}
	e.dns.mu.Lock()
	defer e.dns.mu.Unlock()
	for _, q := range e.dns.asked {
		name := strings.TrimSuffix(strings.SplitN(q, "|", 2)[0], ".")
		if name != "shop.example.test" && !strings.HasSuffix(name, ".shop.example.test") {
			t.Errorf("queried an out-of-scope name: %s", q)
		}
	}
	e.web.mu.Lock()
	defer e.web.mu.Unlock()
	if len(e.web.hosts) != 0 {
		t.Errorf("HTTP sent to %v", e.web.hosts)
	}
}

// A failing CT service is not an error: discovery falls back to DNS names.
func TestSubdomainTakeoverCTDownFallsBackToDNS(t *testing.T) {
	e := newTakeoverEnv(t)
	e.web.ctStatus = http.StatusBadGateway
	e.dns.configure(func(f *fakeDNS) {
		f.add("docs.example.test. 300 IN CNAME acme.bitbucket.io.", "acme.bitbucket.io. 300 IN A 192.0.2.11")
	})
	e.web.pages["docs.example.test"] = "Repository not found"
	fs, _, err := e.run(t, "example.test", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(findingSummary(fs), ","); got != "unclaimed_resource:docs.example.test" {
		t.Errorf("got %q", got)
	}
}

func TestSubdomainTakeoverCTOff(t *testing.T) {
	e := newTakeoverEnv(t)
	e.web.ct = []string{"assets.example.test"}
	if _, _, err := e.run(t, "example.test", CTDisabled); err != nil {
		t.Fatal(err)
	}
	if e.web.ctQuery != "" {
		t.Error("CT queried although disabled")
	}
}

// One NXDOMAIN may be a glitch: the final target is asked twice.
func TestSubdomainTakeoverServfailIsNotAFinding(t *testing.T) {
	e := newTakeoverEnv(t)
	e.web.ct = []string{"app.example.test"}
	e.dns.configure(func(f *fakeDNS) {
		f.add("app.example.test. 300 IN CNAME acme.azurewebsites.net.")
		f.servfail["acme.azurewebsites.net.|A"] = true
	})
	fs, _, err := e.run(t, "example.test", "")
	if err != nil || len(fs) != 0 {
		t.Fatalf("got %v %v", findingSummary(fs), err)
	}
}

// The check's cost stays bounded whatever CT returns.
func TestSubdomainTakeoverCostIsBounded(t *testing.T) {
	e := newTakeoverEnv(t)
	e.dns.configure(func(f *fakeDNS) {
		for i := 0; i < 300; i++ {
			n := fmt.Sprintf("n%03d.example.test", i)
			e.web.ct = append(e.web.ct, n)
			f.add(n+". 300 IN CNAME a"+n+".", "a"+n+". 300 IN CNAME b"+n+".", "b"+n+". 300 IN A 192.0.2.1")
		}
	})
	_, client, err := e.run(t, "example.test", "")
	if err != nil {
		t.Fatal(err)
	}
	if used := client.RequestsUsed(); used > takeoverMaxOps {
		t.Errorf("used %d requests, cap %d", used, takeoverMaxOps)
	}
}

func TestSubdomainTakeoverSkipsIPTargets(t *testing.T) {
	client := probe.New(probe.Options{})
	defer client.Close()
	tg, _ := NewTarget("http://192.0.2.1", client)
	fs, err := SubdomainTakeover{}.Run(context.Background(), tg)
	if err != nil || len(fs) != 0 || client.RequestsUsed() != 0 {
		t.Errorf("IP target: %v %v %d", fs, err, client.RequestsUsed())
	}
}

func TestParseCTNamesToleratesTruncation(t *testing.T) {
	body := []byte(`[{"common_name":"a.example.test","name_value":"a.example.test\n*.b.example.test\nexample.org"},{"common_name":"c.exa`)
	got := parseCTNames(body, "example.test")
	if !got["a.example.test"] || !got["b.example.test"] || got["example.org"] || len(got) != 2 {
		t.Errorf("got %v", got)
	}
	if len(parseCTNames([]byte(`<html>busy</html>`), "example.test")) != 0 {
		t.Error("non-JSON body yielded names")
	}
}

func TestInScope(t *testing.T) {
	for in, want := range map[string]string{
		"A.Example.Test.":      "a.example.test",
		"*.x.example.test":     "x.example.test",
		"example.test":         "example.test",
		"badexample.test":      "",
		"example.test.evil.io": "",
		"a b.example.test":     "",
		"user@example.test":    "",
	} {
		got, ok := inScope(in, "example.test")
		if (want == "") == ok || got != want {
			t.Errorf("inScope(%q) = %q %v", in, got, ok)
		}
	}
}

func TestTakeoverProvidersLoad(t *testing.T) {
	if len(takeoverProviders) < 10 {
		t.Fatalf("only %d providers", len(takeoverProviders))
	}
	// "Edge case" / "Not vulnerable" providers must never be on the list.
	for _, name := range []string{"github.io", "herokuapp.com", "herokudns.com", "netlify.app", "myshopify.com", "fastly.net", "cloudfront.net", "wixdns.net", "webflow.io"} {
		if p := providerFor([]string{"acme." + name}); p != nil {
			t.Errorf("%s matched provider %s", name, p.Name)
		}
	}
	for target, want := range map[string]string{
		"x.s3.amazonaws.com":                   "AWS S3",
		"x.s3.eu-central-1.amazonaws.com":      "AWS S3",
		"x.s3-website-us-east-1.amazonaws.com": "AWS S3",
		"x.s3-website.eu-west-2.amazonaws.com": "AWS S3",
		"x.azurewebsites.net":                  "Microsoft Azure",
		"x.eu-west-1.elasticbeanstalk.com":     "AWS Elastic Beanstalk",
		"x.bitbucket.io":                       "Bitbucket",
		"ec2-1-2-3-4.compute.amazonaws.com":    "",
		"s3.amazonaws.com.evil.test":           "",
		"evilbitbucket.io":                     "",
	} {
		p := providerFor([]string{target})
		got := ""
		if p != nil {
			got = p.Name
		}
		if got != want {
			t.Errorf("%s: got %q want %q", target, got, want)
		}
	}
	for _, bad := range []string{
		"version: 1\nproviders: [{name: X, kind: http, cnames: [x.test], fingerprints: [\"Not Found\"]}]",
		"version: 1\nproviders: [{name: X, kind: http, cnames: [x.test]}]",
		"version: 1\nproviders: [{name: X, kind: magic, cnames: [x.test]}]",
		"version: 1\nproviders: [{name: X, kind: nxdomain, cnames: [nodot]}]",
		"version: 2\nproviders: [{name: X, kind: nxdomain, cnames: [x.test]}]",
	} {
		if _, err := loadTakeoverProviders([]byte(bad)); err == nil {
			t.Errorf("accepted: %s", bad)
		}
	}
	wp := providerFor([]string{"acme.wordpress.com"})
	if _, ok := wp.fingerprint([]byte("<h1>Do you want to register acme.wordpress.com?</h1>")); !ok {
		t.Error("WordPress regex fingerprint did not match")
	}
}
