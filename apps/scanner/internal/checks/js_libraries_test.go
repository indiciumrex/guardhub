package checks

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func jsOSV(t *testing.T) JSLibraries {
	t.Helper()
	return JSLibraries{OSV: fakeOSV(t,
		map[string][]string{
			"npm|jquery|1.12.4":    {"GHSA-gxr4-xjj5-5px2", "GHSA-rmxg-73gg-4p98"},
			"npm|bootstrap|3.3.7":  {"GHSA-9v3m-8fp8-mj99"},
			"npm|jquery-ui|1.12.1": {"GHSA-h6gj-6jjq-h8g9"},
			"npm|angular|1.5.8":    {"GHSA-withdrawn-0001"},
		},
		map[string]map[string]any{
			"GHSA-gxr4-xjj5-5px2": osvRecord("GHSA-gxr4-xjj5-5px2", "npm", "jquery", "MODERATE", "3.5.0", "CVE-2020-11022"),
			"GHSA-rmxg-73gg-4p98": osvRecord("GHSA-rmxg-73gg-4p98", "npm", "jquery", "MODERATE", "3.0.0", "CVE-2015-9251"),
			"GHSA-9v3m-8fp8-mj99": osvRecord("GHSA-9v3m-8fp8-mj99", "npm", "bootstrap", "MODERATE", "3.4.0", "CVE-2018-14041"),
			"GHSA-h6gj-6jjq-h8g9": osvRecord("GHSA-h6gj-6jjq-h8g9", "npm", "jquery-ui", "MODERATE", "1.13.0", "CVE-2021-41184"),
			"GHSA-withdrawn-0001": func() map[string]any {
				r := osvRecord("GHSA-withdrawn-0001", "npm", "angular", "HIGH", "1.6.0")
				r["withdrawn"] = "2024-01-01T00:00:00Z"
				return r
			}(),
		})}
}

func js(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(body))
	}
}

func TestJSLibrariesBannerAndCDN(t *testing.T) {
	srv := site(t, false, map[string]http.HandlerFunc{
		"/": html(`<!doctype html><title>Shop</title>
<script src="/static/jquery.min.js"></script>
<script src="/static/bootstrap.js"></script>
<script src="/static/jquery-again.js"></script>
<script src="https://code.jquery.com/ui/1.12.1/jquery-ui.min.js"></script>
<script src="https://cdn.example.test/jquery-1.8.3.min.js"></script>`),
		"/static/jquery.min.js":   js("/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */\n!function(a,b){}"),
		"/static/bootstrap.js":    js("/*!\n * Bootstrap v3.3.7 (http://getbootstrap.com)\n * Copyright 2011-2016 Twitter, Inc.\n */\n"),
		"/static/jquery-again.js": js("/*!\n * jQuery JavaScript Library v1.12.4\n */"),
	})
	fs := run(t, jsOSV(t), srv.URL)
	requireKeys(t, fs, "vulnerable_js_library", "vulnerable_js_library", "vulnerable_js_library")
	got := map[string]map[string]string{}
	for _, f := range fs {
		got[f.Params["library"]] = f.Params
	}
	if p := got["jquery"]; p["version"] != "1.12.4" || p["fixed_version"] != "3.5.0" || !strings.Contains(p["advisories"], "CVE-2020-11022") || !strings.HasSuffix(p["script"], "/static/jquery.min.js") {
		t.Fatalf("jquery params %v", p)
	}
	if p := got["bootstrap"]; p["version"] != "3.3.7" || p["fixed_version"] != "3.4.0" {
		t.Fatalf("bootstrap params %v", p)
	}
	if p := got["jquery-ui"]; p["version"] != "1.12.1" || p["script"] != "https://code.jquery.com/ui/1.12.1/jquery-ui.min.js" {
		t.Fatalf("jquery-ui params %v", p)
	}
}

func TestJSLibrariesNegatives(t *testing.T) {
	srv := site(t, false, map[string]http.HandlerFunc{
		"/": html(`<!doctype html><title>Shop</title>
<script src="/static/jquery-1.8.3.min.js"></script>
<script src="/static/app.js"></script>
<script src="/static/angular.js"></script>
<script src="/static/lodash.min.js"></script>
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/jquery@3/dist/jquery.min.js"></script>`),
		// the name says 1.8.3, the banner says 3.7.1: the banner wins, and 3.7.1 has no advisory
		"/static/jquery-1.8.3.min.js": js("/*! jQuery v3.7.1 | (c) OpenJS Foundation and other contributors | jquery.org/license */"),
		// a mention in application code is not a banner
		"/static/app.js": js("// requires jQuery v1.12.4 or later\nconsole.log('jQuery v1.12.4')"),
		// every advisory withdrawn
		"/static/angular.js": js("/**\n * @license AngularJS v1.5.8\n * (c) 2010-2016 Google, Inc. http://angularjs.org\n */"),
		// lodash credits Underscore.js in its banner: never read as underscore
		"/static/lodash.min.js": js("/** @license Lodash lodash.com/license | Underscore.js 1.8.3 underscorejs.org/LICENSE */"),
	})
	requireKeys(t, run(t, jsOSV(t), srv.URL))
}

func TestJSLibrariesNoLibraryNoOSV(t *testing.T) {
	srv := site(t, false, map[string]http.HandlerFunc{"/": html(`<!doctype html><title>Plain</title><script src="/app.js"></script>`), "/app.js": js("1")})
	requireKeys(t, run(t, JSLibraries{}, srv.URL)) // no OSV client needed when nothing was found
}

func TestJSLibrariesFromCDN(t *testing.T) {
	cases := map[string][2]string{
		"https://code.jquery.com/jquery-1.12.4.min.js":                                       {"jquery", "1.12.4"},
		"https://code.jquery.com/jquery-3.4.1.slim.min.js":                                   {"jquery", "3.4.1"},
		"https://code.jquery.com/jquery-migrate-1.4.1.min.js":                                {"jquery-migrate", "1.4.1"},
		"https://code.jquery.com/ui/1.12.1/jquery-ui.js":                                     {"jquery-ui", "1.12.1"},
		"https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/js/bootstrap.min.js": {"bootstrap", "3.3.7"},
		"https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.18.1/moment.min.js":              {"moment", "2.18.1"},
		"https://ajax.googleapis.com/ajax/libs/angularjs/1.5.8/angular.min.js":               {"angular", "1.5.8"},
		"https://cdn.jsdelivr.net/npm/handlebars@4.0.11/dist/handlebars.min.js":              {"handlebars", "4.0.11"},
		"https://unpkg.com/vue@2.5.16/dist/vue.min.js":                                       {"vue", "2.5.16"},
		"https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/js/bootstrap.min.js":             {"bootstrap", "4.1.3"},
	}
	for raw, want := range cases {
		u, _ := url.Parse(raw)
		lib, ver, ok := fromCDN(u)
		if !ok || lib != want[0] || ver != want[1] {
			t.Errorf("%s: got %s %s %v, want %v", raw, lib, ver, ok, want)
		}
	}
	for _, raw := range []string{
		"https://cdn.jsdelivr.net/npm/jquery@3/dist/jquery.min.js", // a range, not a version
		"https://cdn.jsdelivr.net/gh/jquery/jquery@3.4.1/dist/jquery.min.js",
		"https://code.jquery.com/jquery-latest.min.js",
		"https://cdn.example.test/jquery-1.8.3.min.js", // not a known CDN
		"https://cdnjs.cloudflare.com/ajax/libs/unknown-lib/1.0.0/x.js",
	} {
		u, _ := url.Parse(raw)
		if lib, ver, ok := fromCDN(u); ok {
			t.Errorf("%s: read as %s %s", raw, lib, ver)
		}
	}
}
