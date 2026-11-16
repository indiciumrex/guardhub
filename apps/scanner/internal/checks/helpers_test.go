package checks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
)

// spaShell is what a single-page app returns for EVERY path (soft 404).
const spaShell = `<!doctype html><html><head><title>Acme</title></head><body><div id="root"></div><script src="/app.js"></script></body></html>`

// site serves routes; unknown paths get a real 404, or a 200 SPA shell
// when soft404 is true.
func site(t *testing.T, soft404 bool, routes map[string]http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(siteHandler(soft404, routes))
	t.Cleanup(srv.Close)
	return srv
}

func siteHandler(soft404 bool, routes map[string]http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, ok := routes[r.URL.Path]; ok {
			h(w, r)
			return
		}
		if soft404 {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(spaShell))
			return
		}
		http.NotFound(w, r)
	})
}

// newCatchAll serves the same HTML body with 200 for every path.
func newCatchAll(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(html(body))
	t.Cleanup(srv.Close)
	return srv.URL
}

func text(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(body))
	}
}

func html(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(body))
	}
}

func testClient() *probe.Client {
	return probe.New(probe.Options{
		AllowPrivateHosts:  []string{"127.0.0.1"},
		HostRPS:            1000,
		HostBurst:          100,
		BackoffBase:        time.Millisecond,
		Timeout:            3 * time.Second,
		InsecureSkipVerify: true,
	})
}

func targetFor(t *testing.T, rawURL string) Target {
	t.Helper()
	tg, err := NewTarget(rawURL, testClient())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tg.Probe.Close)
	return tg
}

func run(t *testing.T, c Check, srvURL string) []evidence.Finding {
	t.Helper()
	fs, err := c.Run(context.Background(), targetFor(t, srvURL))
	if err != nil {
		t.Fatalf("%s: unexpected error: %v", c.ID(), err)
	}
	validateFindings(t, fs)
	return fs
}

func keysOf(fs []evidence.Finding) []string {
	var ks []string
	for _, f := range fs {
		ks = append(ks, f.FindingKey)
	}
	sort.Strings(ks)
	return ks
}

func requireKeys(t *testing.T, fs []evidence.Finding, want ...string) {
	t.Helper()
	sort.Strings(want)
	got := keysOf(fs)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("finding keys = %v, want %v\nfindings: %+v", got, want, fs)
	}
}

func findKey(t *testing.T, fs []evidence.Finding, key string) evidence.Finding {
	t.Helper()
	for _, f := range fs {
		if f.FindingKey == key {
			return f
		}
	}
	t.Fatalf("no %s finding in %+v", key, fs)
	return evidence.Finding{}
}

type catalog struct {
	Checks []struct {
		ID          string `json:"id"`
		FindingKeys []struct {
			Key      string   `json:"key"`
			Severity string   `json:"severity"`
			Params   []string `json:"params"`
		} `json:"finding_keys"`
	} `json:"checks"`
}

func loadCatalog(t *testing.T) map[string]map[string][]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "packages", "shared", "check-ids.json"))
	if err != nil {
		t.Fatalf("read check-ids.json: %v", err)
	}
	var c catalog
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string][]string{}
	for _, ch := range c.Checks {
		out[ch.ID] = map[string][]string{}
		for _, fk := range ch.FindingKeys {
			out[ch.ID][fk.Key] = fk.Params
			if string(evidence.FindingKeys[ch.ID][fk.Key]) != fk.Severity {
				t.Fatalf("generated contract out of date for %s.%s", ch.ID, fk.Key)
			}
		}
	}
	return out
}

var hex64 = regexp.MustCompile(`^[a-f0-9]{64}$`)

// validateFindings enforces the RawFinding contract: declared key, default
// severity, exactly the declared params, schema limits, fingerprint.
func validateFindings(t *testing.T, fs []evidence.Finding) {
	t.Helper()
	cat := loadCatalog(t)
	seen := map[string]bool{}
	for _, f := range fs {
		params, ok := cat[f.CheckID][f.FindingKey]
		if !ok {
			t.Fatalf("undeclared finding %s.%s", f.CheckID, f.FindingKey)
		}
		if f.Severity != evidence.FindingKeys[f.CheckID][f.FindingKey] {
			t.Fatalf("%s: wrong severity %s", f.FindingKey, f.Severity)
		}
		if len(f.Params) != len(params) {
			t.Fatalf("%s: params %v, declared %v", f.FindingKey, f.Params, params)
		}
		for _, p := range params {
			v, ok := f.Params[p]
			if !ok || v == "" || len(v) > evidence.MaxParamLen {
				t.Fatalf("%s: param %q missing/invalid in %v", f.FindingKey, p, f.Params)
			}
		}
		if len(f.Evidence.RedactedPayload) > evidence.MaxPayloadLen || f.Evidence.Location == "" || f.Evidence.RedactedPayload == "" {
			t.Fatalf("%s: bad evidence %+v", f.FindingKey, f.Evidence)
		}
		if !hex64.MatchString(f.Fingerprint) || f.Fingerprint != evidence.Fingerprint(f.CheckID, f.FindingKey, f.Evidence.Location) {
			t.Fatalf("%s: bad fingerprint", f.FindingKey)
		}
		if seen[f.Fingerprint] {
			t.Fatalf("duplicate fingerprint for %s at %s", f.FindingKey, f.Evidence.Location)
		}
		seen[f.Fingerprint] = true
		// Must serialise exactly to the schema's field names.
		if _, err := json.Marshal(f); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRegistryMatchesCatalog(t *testing.T) {
	cat := loadCatalog(t)
	r := Default()
	if len(r.IDs()) != len(cat) {
		t.Fatalf("registry has %v, catalog has %d checks", r.IDs(), len(cat))
	}
	for id := range cat {
		c, ok := r.Get(id)
		if !ok || c.ID() != id {
			t.Fatalf("check %s not registered", id)
		}
	}
	if _, ok := r.Get("nope"); ok {
		t.Fatal("unknown id must not resolve")
	}
}

func TestParseOrigin(t *testing.T) {
	good := map[string]string{
		"https://Example.com":      "https://example.com",
		"http://example.com:8080/": "http://example.com:8080",
	}
	for in, want := range good {
		u, err := ParseOrigin(in)
		if err != nil || u.String() != want {
			t.Errorf("ParseOrigin(%q) = %v, %v", in, u, err)
		}
	}
	for _, bad := range []string{"ftp://x.test", "https://x.test/path", "https://u:p@x.test", "https://x.test/?q=1", "example.com", ""} {
		if _, err := ParseOrigin(bad); err == nil {
			t.Errorf("ParseOrigin(%q) should fail", bad)
		}
	}
}

// Checks must be deterministic: same site, same findings (order included).
func TestChecksAreDeterministic(t *testing.T) {
	srv := site(t, true, map[string]http.HandlerFunc{
		"/.env":          text("A_KEY=abcdefghijklmnop\nB=2\n"),
		"/server-status": html("<title>Apache Status</title><h1>Apache Server Status for x</h1>"),
		"/":              html("<title>x</title>"),
	})
	for _, c := range []Check{ExposedEnv{}, OpenAdmin{}, InfoLeak{}, SecurityHeaders{}, DefaultCreds{}} {
		a := run(t, c, srv.URL)
		b := run(t, c, srv.URL)
		ja, _ := json.Marshal(a)
		jb, _ := json.Marshal(b)
		if string(ja) != string(jb) {
			t.Fatalf("%s not deterministic:\n%s\n%s", c.ID(), ja, jb)
		}
	}
}
