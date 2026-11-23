package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hksolutions/guardhub/apps/scanner/internal/active/oobserver"
)

func TestCollaboratorRoundTrip(t *testing.T) {
	collab := httptest.NewServer(oobserver.New(100))
	defer collab.Close()
	c := HTTPCollaborator{Base: collab.URL, HTTP: collab.Client()}
	tok, other := NewToken(), NewToken()
	if len(tok) != 32 || tok == other {
		t.Fatalf("tokens %q %q", tok, other)
	}
	ctx := context.Background()
	if seen, err := c.Seen(ctx, tok); err != nil || seen {
		t.Fatalf("seen before any hit: %v %v", seen, err)
	}
	// a vulnerable "target" fetches whatever URL it is given
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u := r.URL.Query().Get("url"); u != "" {
			if resp, err := http.Get(u); err == nil { //nolint:noctx // the test's deliberately vulnerable target
				_ = resp.Body.Close()
			}
		}
	}))
	defer target.Close()
	cl, log := newTestClient(t, target, &StaticKill{}, Limits{})
	p, _ := PayloadByID("ssrf.oob.http")
	if _, err := cl.Send(ctx, OOBProbe("active_ssrf", mustURL(t, target.URL+"/fetch"), "url", p, c.URL(tok))); err != nil {
		t.Fatal(err)
	}
	seen, err := WaitSeen(ctx, c, tok, 2*time.Second, 50*time.Millisecond)
	if err != nil || !seen {
		t.Fatalf("hit not seen: %v %v", seen, err)
	}
	if seen, _ := c.Seen(ctx, other); seen {
		t.Fatal("another token reported as seen")
	}
	e := log.Entries()[0]
	if e.PayloadID != "ssrf.oob.http" || e.PayloadHash == "" {
		t.Fatalf("log %+v", e)
	}
}
