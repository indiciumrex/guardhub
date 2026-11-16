package checks

import (
	"net/http"
	"testing"
)

func notFoundWith(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(body))
	}
}

func TestInfoLeakHeaders(t *testing.T) {
	srv := site(t, false, map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
			w.Header().Set("X-Powered-By", "PHP/7.4.3")
			w.Header().Set("X-AspNet-Version", "4.0.30319")
		},
	})
	fs := run(t, InfoLeak{}, srv.URL)
	requireKeys(t, fs, "server_version_disclosed", "framework_version_disclosed", "framework_version_disclosed")
	if f := findKey(t, fs, "server_version_disclosed"); f.Params["header"] != "Server" || f.Params["value"] != "Apache/2.4.41 (Ubuntu)" {
		t.Fatalf("params %v", f.Params)
	}
}

func TestInfoLeakHeadersWithoutVersions(t *testing.T) {
	srv := site(t, false, map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Server", "cloudflare")
			w.Header().Set("X-Powered-By", "Next.js")
		},
	})
	requireKeys(t, run(t, InfoLeak{}, srv.URL))
}

func TestInfoLeakStackTraces(t *testing.T) {
	cases := map[string]string{
		"python": "<pre>Traceback (most recent call last):\n  File \"/app/main.py\", line 10, in handler\nKeyError: 'x'</pre>",
		"java":   "java.lang.NullPointerException\n\tat com.acme.web.Controller.handle(Controller.java:42)\n\tat org.springframework.web.servlet.FrameworkServlet.service(FrameworkServlet.java:897)",
		"php":    "<br />\n<b>Fatal error</b>:  Uncaught Error: Call to undefined function foo() in /var/www/html/index.php:12\nStack trace:\n#0 {main}\n  thrown in <b>/var/www/html/index.php</b> on line <b>12</b><br />",
		"dotnet": "<title>Runtime Error</title><h1>Server Error in '/' Application.</h1>",
		"node":   "Error: boom\n    at Object.<anonymous> (/srv/app/server.js:10:15)\n    at Module._compile (node:internal/modules/cjs/loader:1105:14)",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			srv := site(t, false, map[string]http.HandlerFunc{baselinePath: notFoundWith(body)})
			fs := run(t, InfoLeak{}, srv.URL)
			requireKeys(t, fs, "stack_trace_exposed")
			if fs[0].Params["path"] != baselinePath {
				t.Fatalf("params %v", fs[0].Params)
			}
		})
	}
}

func TestInfoLeakDebugMode(t *testing.T) {
	cases := map[string]string{
		"Django":        `<title>Page not found at /x</title><p>Using the URLconf defined in <code>acme.urls</code></p><p>You're seeing this error because you have <code>DEBUG = True</code> in your Django settings file.</p>`,
		"Laravel":       `<html><head><title>Laravel</title><script>window.ignite = {};</script></head><body>Ignition</body></html>`,
		"Ruby on Rails": `<h1>Routing Error</h1><p>No route matches [GET] "/x"</p><p>Rails.root: /app</p>`,
	}
	for fw, body := range cases {
		t.Run(fw, func(t *testing.T) {
			srv := site(t, false, map[string]http.HandlerFunc{baselinePath: notFoundWith(body)})
			fs := run(t, InfoLeak{}, srv.URL)
			requireKeys(t, fs, "debug_mode_enabled")
			if fs[0].Params["framework"] != fw {
				t.Fatalf("framework %v", fs[0].Params)
			}
		})
	}
}

func TestInfoLeakDirectoryListing(t *testing.T) {
	srv := site(t, false, map[string]http.HandlerFunc{
		"/uploads/": html(`<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1><a href="a.pdf">a.pdf</a></body></html>`),
		"/images/":  html(`<html><head><title>Index of /images</title></head></html>`),
	})
	fs := run(t, InfoLeak{}, srv.URL)
	requireKeys(t, fs, "directory_listing_enabled")
	if fs[0].Params["path"] != "/uploads/" {
		t.Fatalf("params %v", fs[0].Params)
	}
}

func TestInfoLeakNegative(t *testing.T) {
	// Clean site with real 404s and a soft-404 SPA.
	requireKeys(t, run(t, InfoLeak{}, site(t, false, map[string]http.HandlerFunc{"/": html("<title>Home</title>")}).URL))
	requireKeys(t, run(t, InfoLeak{}, site(t, true, nil).URL))

	// Text that mentions the signatures in prose is not a trace.
	srv := site(t, false, map[string]http.HandlerFunc{
		"/":          html(`<title>Blog</title><p>How to read a Python traceback and what "Index of" pages are.</p>`),
		baselinePath: notFoundWith(`<title>404</title><p>We use Django and Laravel.</p>`),
	})
	requireKeys(t, run(t, InfoLeak{}, srv.URL))
}
