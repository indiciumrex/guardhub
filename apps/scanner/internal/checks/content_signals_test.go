package checks

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func tlsPage(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewTLSServer(siteHandler(false, map[string]http.HandlerFunc{"/": html(body)}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestContentSignalsMixedAndSRI(t *testing.T) {
	u := tlsPage(t, `<!doctype html><html><head>
<script src="http://cdn.example.test/app.js"></script>
<link rel="preload stylesheet" href="http://cdn.example.test/site.css">
<script src="https://cdn.example.test/lib.js"></script>
<script src="https://cdn.example.test/ok.js" integrity="sha384-abc" crossorigin="anonymous"></script>
</head><body>
<img src="http://img.example.test/logo.png">
<video controls><source src="http://media.example.test/a.mp4"></video>
<iframe src="http://widgets.example.test/w"></iframe>
</body></html>`)
	fs := run(t, ContentSignals{}, u)
	requireKeys(t, fs, "mixed_content_active", "mixed_content_passive", "sri_missing")
	if p := findKey(t, fs, "mixed_content_active").Params; p["count"] != "3" || p["example"] != "http://cdn.example.test/app.js" {
		t.Fatalf("active params %v", p)
	}
	if p := findKey(t, fs, "mixed_content_passive").Params; p["count"] != "2" {
		t.Fatalf("passive params %v", p)
	}
	if p := findKey(t, fs, "sri_missing").Params; p["count"] != "1" || p["example"] != "https://cdn.example.test/lib.js" {
		t.Fatalf("sri params %v", p)
	}
}

func TestContentSignalsNegatives(t *testing.T) {
	u := tlsPage(t, `<!doctype html><html><head>
<!-- <script src="http://cdn.example.test/old.js"></script> -->
<noscript><img src="http://img.example.test/pixel.gif"></noscript>
<template><script src="http://cdn.example.test/tpl.js"></script></template>
<script src="/static/app.js"></script>
<script src="//`+"127.0.0.1"+`/same.js"></script>
<script src="http://localhost:8080/dev.js"></script>
<link rel="alternate" href="http://example.test/feed.xml">
<script>var u = "<script src='http://cdn.example.test/x.js'>";</script>
</head><body>
<a href="http://example.test/">a link is not a resource</a>
<picture><source srcset="http://img.example.test/a.webp"><img src="/a.png"></picture>
</body></html>`)
	requireKeys(t, run(t, ContentSignals{}, u))
}

func TestContentSignalsPlainHTTPPage(t *testing.T) {
	// an http:// page has no mixed content; a same-site https script needs no SRI
	srv := site(t, false, map[string]http.HandlerFunc{"/": html(`<!doctype html><script src="http://cdn.example.test/app.js"></script><img src="http://x.example.test/a.png">`)})
	requireKeys(t, run(t, ContentSignals{}, srv.URL))
}

func TestContentSignalsBaseHref(t *testing.T) {
	u := tlsPage(t, `<!doctype html><html><head><base href="http://assets.example.test/"><script src="app.js"></script></head></html>`)
	fs := run(t, ContentSignals{}, u)
	requireKeys(t, fs, "mixed_content_active")
	if p := findKey(t, fs, "mixed_content_active").Params; p["example"] != "http://assets.example.test/app.js" {
		t.Fatalf("base href not applied: %v", p)
	}
}

func TestCrossSite(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"www.example.com", "cdn.example.com", false},
		{"example.com", "example.com", false},
		{"shop.example.co.uk", "cdn.example.co.uk", false},
		{"a.github.io", "b.github.io", true}, // public suffix: different sites
		{"example.com", "cdnjs.cloudflare.com", true},
		{"10.0.0.1", "10.0.0.2", true},
	} {
		if got := crossSite(c.a, c.b); got != c.want {
			t.Errorf("crossSite(%s, %s) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
