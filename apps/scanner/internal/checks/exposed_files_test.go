package checks

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"testing"
)

func bin(ct string, body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", ct)
		_, _ = w.Write(body)
	}
}

const mysqlDump = "-- MySQL dump 10.13\n--\nCREATE TABLE `users` (\n  `id` int NOT NULL\n);\nINSERT INTO `users` VALUES (1),(2);\n"

func gz(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return b.Bytes()
}

func TestExposedFilesPositives(t *testing.T) {
	srv := site(t, false, map[string]http.HandlerFunc{
		"/":                  html(`<!doctype html><title>Shop</title><script src="/app.js"></script><script src="https://cdn.example/x.js"></script>`),
		"/app.js":            text("console.log(1)\n//# sourceMappingURL=app.js.map\n"),
		"/app.js.map":        bin("application/json", []byte(`{"version":3,"sources":["src/app.ts"],"sourcesContent":["export const a = 1"],"mappings":"AAAA"}`)),
		"/backup.sql":        text(mysqlDump),
		"/db.sql.gz":         bin("application/gzip", gz("-- PostgreSQL database dump\nCREATE TABLE public.orders (id int);\nCOPY public.orders (id) FROM stdin;\n1\n\\.\n")),
		"/wp-config.php.bak": bin("application/octet-stream", []byte("<?php\ndefine( 'DB_NAME', 'wp' );\ndefine( 'DB_PASSWORD', 'hunter2' );\n")),
		"/backup.tar.gz":     bin("application/gzip", gz("not really a tar")),
		"/.DS_Store":         bin("application/octet-stream", append([]byte("\x00\x00\x00\x01Bud1"), make([]byte, 64)...)),
	})
	fs := run(t, ExposedFiles{}, srv.URL)
	requireKeys(t, fs, "database_dump_exposed", "database_dump_exposed", "source_backup_exposed", "archive_backup_exposed", "ds_store_exposed", "source_map_exposed")
	for _, f := range fs {
		if bytes.Contains([]byte(f.Evidence.RedactedPayload), []byte("hunter2")) {
			t.Fatalf("a value leaked into the evidence: %s", f.Evidence.RedactedPayload)
		}
	}
	if p := findKey(t, fs, "source_map_exposed").Params; p["path"] != "/app.js.map" || p["source_count"] != "1" {
		t.Fatalf("source map params %v", p)
	}
}

func TestExposedFilesNegatives(t *testing.T) {
	srv := site(t, false, map[string]http.HandlerFunc{
		"/":              html(`<!doctype html><title>Shop</title><script src="/app.js"></script>`),
		"/app.js":        text("console.log(1)\n//# sourceMappingURL=app.js.map\n"),
		"/app.js.map":    bin("application/json", []byte(`{"version":3,"sources":["src/app.ts"],"mappings":"AAAA"}`)), // names only
		"/dump.sql":      text("-- MySQL dump 10.13\nCREATE TABLE `users` (`id` int);\n"),                             // schema only
		"/index.php.bak": html("<!doctype html><html><body>Rendered page</body></html>"),                              // executed, not source
		"/backup.zip":    html("<!doctype html><p>Download our brochure</p>"),                                         // not an archive
		"/.DS_Store":     text("nothing here"),
	})
	requireKeys(t, run(t, ExposedFiles{}, srv.URL))
}

func TestExposedFilesSoftNotFound(t *testing.T) {
	// a catch-all answering every path with the same body: nothing may be reported
	srv := site(t, true, map[string]http.HandlerFunc{})
	requireKeys(t, run(t, ExposedFiles{}, srv.URL))
}

func TestExposedFilesDefaultPage(t *testing.T) {
	srv := site(t, false, map[string]http.HandlerFunc{
		"/": html("<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n</head><body><h1>Welcome to nginx!</h1></body></html>"),
	})
	fs := run(t, ExposedFiles{}, srv.URL)
	requireKeys(t, fs, "default_page_exposed")
	if s := findKey(t, fs, "default_page_exposed").Params["server"]; s != "nginx" {
		t.Fatalf("server %q", s)
	}
}

func TestExposedFilesCrossOriginMapIgnored(t *testing.T) {
	srv := site(t, false, map[string]http.HandlerFunc{
		"/":       html(`<!doctype html><title>x</title><script src="/a.js"></script>`),
		"/a.js":   text("x()\n//# sourceMappingURL=https://cdn.example/a.js.map\n"),
		"/a.js.m": text(""),
	})
	requireKeys(t, run(t, ExposedFiles{}, srv.URL))
}
