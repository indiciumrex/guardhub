package checks

// exposed_files (ADR-0007): forgotten files a web server hands to anyone,
// beyond exposed_env's secret files. A fixed list of well-known paths (no
// brute force, no wordlists), every hit confirmed by the file's CONTENT, never
// by the status code, and never equal to the site's answer for a path that
// does not exist (soft-404 baseline).
//
//   - database_dump_exposed: an SQL dump WITH DATA rows (INSERT INTO / COPY
//     ... FROM stdin), plain or gzip-compressed. Schema-only dumps are not
//     reported.
//   - source_backup_exposed: an editor/backup copy of PHP source (.bak, ~,
//     .save, .old) served as source: it starts with "<?php".
//   - archive_backup_exposed: a site archive (zip or gzip/tar.gz magic bytes)
//     at a backup path.
//   - ds_store_exposed: a macOS .DS_Store file (lists the folder's files).
//   - source_map_exposed: a same-origin JavaScript source map (from the home
//     page's first scripts) that embeds the original source (sourcesContent).
//   - default_page_exposed: the home page is a web server's stock welcome page.
//
// Bodies are read up to the probe's cap (256 KiB); evidence never contains
// file contents beyond names (tables, defined constants, source file names).

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
)

// ExposedFiles implements the exposed_files check.
type ExposedFiles struct{}

// ID implements Check.
func (ExposedFiles) ID() string { return evidence.CheckExposedFiles }

var (
	dumpPaths    = []string{"/backup.sql", "/dump.sql", "/db.sql", "/database.sql", "/backup.sql.gz", "/db.sql.gz"}
	sourceBackup = []string{"/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.save", "/wp-config.php.old", "/config.php.bak", "/index.php.bak", "/index.php~"}
	archivePaths = []string{"/backup.zip", "/backup.tar.gz", "/site.zip", "/www.zip"}

	dumpHeaderRe  = regexp.MustCompile(`(?im)^-- (?:MySQL|MariaDB) dump|^-- PostgreSQL database dump|^\s*CREATE TABLE\b`)
	dumpDataRe    = regexp.MustCompile(`(?im)^\s*INSERT INTO\b|^\s*COPY\s+\S+.*\bFROM stdin;`)
	createTableRe = regexp.MustCompile(`(?im)^\s*CREATE TABLE\s+(?:IF NOT EXISTS\s+)?[` + "`" + `"]?([A-Za-z0-9_.]+)`)
	insertLineRe  = regexp.MustCompile(`(?im)^\s*INSERT INTO\b`)
	phpDefineRe   = regexp.MustCompile(`define\(\s*['"]([A-Z0-9_]+)['"]`)
	scriptSrcRe   = regexp.MustCompile(`(?is)<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']`)
	sourceMapRe   = regexp.MustCompile(`(?m)^[ \t]*//[#@] sourceMappingURL=([^\s'"]+)\s*$`)
	dsStoreMagic  = []byte("\x00\x00\x00\x01Bud1")

	// defaultPages: stock welcome pages of web servers (exact markers of the
	// pages the packages install).
	defaultPages = []struct{ server, marker string }{
		{"nginx", "<title>Welcome to nginx!</title>"},
		{"Apache (Ubuntu)", "<title>Apache2 Ubuntu Default Page: It works</title>"},
		{"Apache (Debian)", "<title>Apache2 Debian Default Page: It works</title>"},
		{"Apache", "<html><body><h1>It works!</h1></body></html>"},
		{"Apache (RHEL/CentOS/Fedora)", "<title>Test Page for the Apache HTTP Server"},
		{"Apache (RHEL/CentOS/Fedora)", "<title>HTTP Server Test Page powered by"},
		{"IIS", "<title>IIS Windows Server</title>"},
		{"Caddy", "<title>Caddy works!</title>"},
	}
)

const maxScripts = 3

// Run implements Check.
func (c ExposedFiles) Run(ctx context.Context, t Target) ([]evidence.Finding, error) {
	f := newFetcher(t)
	base, err := f.baseline(ctx)
	if err != nil {
		return nil, err
	}
	var out []evidence.Finding
	add := func(key string, params map[string]string, path, payload string) {
		out = append(out, evidence.New(c.ID(), key, params, evidence.KindHttpResponse, t.URL(path), payload))
	}
	hit := func(resp *probe.Response) bool {
		return resp != nil && resp.StatusCode == 200 && len(resp.Body) > 0 && !resp.RedirectRefused && !sameAsBaseline(resp, base)
	}

	for _, p := range dumpPaths {
		resp, err := f.get(ctx, p)
		if err != nil {
			return out, err
		}
		if !hit(resp) {
			continue
		}
		if payload, ok := sqlDump(resp.Body, strings.HasSuffix(p, ".gz")); ok {
			add("database_dump_exposed", map[string]string{"path": p}, p, payload)
		}
	}
	for _, p := range sourceBackup {
		resp, err := f.get(ctx, p)
		if err != nil {
			return out, err
		}
		if hit(resp) && isPHPSource(resp.Body) {
			add("source_backup_exposed", map[string]string{"path": p}, p, phpPayload(p, resp))
		}
	}
	for _, p := range archivePaths {
		resp, err := f.get(ctx, p)
		if err != nil {
			return out, err
		}
		if !hit(resp) {
			continue
		}
		if kind := archiveKind(resp.Body); kind != "" {
			add("archive_backup_exposed", map[string]string{"path": p}, p,
				fmt.Sprintf("GET %s -> HTTP 200, %s, first bytes are the %s signature (%s)", p, sizeText(resp), kind, resp.Header.Get("Content-Type")))
		}
	}
	if resp, err := f.get(ctx, "/.DS_Store"); err != nil {
		return out, err
	} else if hit(resp) && bytes.HasPrefix(resp.Body, dsStoreMagic) {
		add("ds_store_exposed", map[string]string{"path": "/.DS_Store"}, "/.DS_Store",
			"GET /.DS_Store -> HTTP 200, "+sizeText(resp)+", starts with the .DS_Store signature (\\x00\\x00\\x00\\x01Bud1)")
	}

	root, err := f.get(ctx, "/")
	if err != nil {
		return out, err
	}
	if root != nil && root.StatusCode == 200 && !root.RedirectRefused {
		for _, d := range defaultPages {
			if bytes.Contains(root.Body, []byte(d.marker)) {
				add("default_page_exposed", map[string]string{"server": d.server}, "/",
					fmt.Sprintf("GET / -> HTTP 200, title %q\nThe page is %s's stock welcome page.", pageTitle(root.Body), d.server))
				break
			}
		}
		found, err := c.sourceMaps(ctx, f, root, base)
		if err != nil {
			return out, err
		}
		out = append(out, found...)
	}
	return out, f.done()
}

// sqlDump confirms an SQL dump with data rows and describes it without data.
func sqlDump(body []byte, gz bool) (string, bool) {
	text := body
	how := "plain text"
	if gz {
		if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
			return "", false
		}
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return "", false
		}
		text, _ = io.ReadAll(io.LimitReader(zr, 256<<10)) // a truncated download is fine
		how = "gzip-compressed"
	}
	if !dumpHeaderRe.Match(text) || !dumpDataRe.Match(text) {
		return "", false
	}
	var tables []string
	for _, m := range createTableRe.FindAllSubmatch(text, 20) {
		tables = append(tables, string(m[1]))
	}
	return fmt.Sprintf("SQL dump (%s) with data rows: %d INSERT statements in the first %d KiB read; tables: %s\n(No row data is stored as evidence.)",
		how, len(insertLineRe.FindAll(text, -1)), len(text)>>10, evidence.Truncate(strings.Join(tables, ", "), 300)), true
}

// isPHPSource: the body is PHP source code, not the output of running it.
func isPHPSource(body []byte) bool {
	b := bytes.TrimLeft(bytes.TrimPrefix(body, []byte("\xef\xbb\xbf")), " \t\r\n")
	return bytes.HasPrefix(b, []byte("<?php"))
}

func phpPayload(p string, resp *probe.Response) string {
	var names []string
	for _, m := range phpDefineRe.FindAllSubmatch(resp.Body, 30) {
		names = append(names, string(m[1]))
	}
	defs := "none"
	if len(names) > 0 {
		defs = strings.Join(names, ", ")
	}
	return fmt.Sprintf("GET %s -> HTTP 200, %s, %d lines of PHP source starting with <?php\nConstants defined (names only, values never stored): %s",
		p, sizeText(resp), bytes.Count(resp.Body, []byte("\n"))+1, evidence.Truncate(defs, 400))
}

func archiveKind(body []byte) string {
	switch {
	case bytes.HasPrefix(body, []byte("PK\x03\x04")):
		return "ZIP"
	case len(body) > 2 && body[0] == 0x1f && body[1] == 0x8b:
		return "gzip"
	}
	return ""
}

func sizeText(resp *probe.Response) string {
	if n := resp.Header.Get("Content-Length"); n != "" {
		return n + " bytes"
	}
	s := strconv.Itoa(len(resp.Body)) + " bytes"
	if resp.Truncated {
		s += "+ (read capped)"
	}
	return s
}

// sourceMaps follows the home page's first same-origin scripts to their source
// maps and reports maps that embed the original source.
func (c ExposedFiles) sourceMaps(ctx context.Context, f *fetcher, root, base *probe.Response) ([]evidence.Finding, error) {
	var out []evidence.Finding
	seen := 0
	for _, m := range scriptSrcRe.FindAllSubmatch(root.Body, -1) {
		if seen == maxScripts {
			break
		}
		js, ok := sameOrigin(root.URL, string(m[1]))
		if !ok {
			continue
		}
		seen++
		resp, err := f.getURL(ctx, js.String())
		if err != nil {
			return out, err
		}
		if resp == nil || resp.StatusCode != 200 || sameAsBaseline(resp, base) {
			continue
		}
		ref := resp.Header.Get("SourceMap")
		if ref == "" {
			ref = resp.Header.Get("X-SourceMap")
		}
		if ref == "" {
			tail := resp.Body
			if len(tail) > 4096 {
				tail = tail[len(tail)-4096:]
			}
			if mm := sourceMapRe.FindAllSubmatch(tail, -1); len(mm) > 0 {
				ref = string(mm[len(mm)-1][1])
			}
		}
		if ref == "" || strings.HasPrefix(ref, "data:") {
			continue
		}
		mapURL, ok := sameOrigin(js, ref)
		if !ok {
			continue
		}
		mresp, err := f.getURL(ctx, mapURL.String())
		if err != nil {
			return out, err
		}
		if mresp == nil || mresp.StatusCode != 200 || sameAsBaseline(mresp, base) {
			continue
		}
		var sm struct {
			Version        int       `json:"version"`
			Sources        []string  `json:"sources"`
			SourcesContent []*string `json:"sourcesContent"`
		}
		if json.Unmarshal(mresp.Body, &sm) != nil || sm.Version != 3 || len(sm.Sources) == 0 {
			continue
		}
		embedded := 0
		for _, s := range sm.SourcesContent {
			if s != nil && strings.TrimSpace(*s) != "" {
				embedded++
			}
		}
		if embedded == 0 {
			continue
		}
		out = append(out, evidence.New(c.ID(), "source_map_exposed",
			map[string]string{"path": evidence.Truncate(mapURL.Path, 200), "source_count": strconv.Itoa(embedded)},
			evidence.KindHttpResponse, mapURL.String(),
			fmt.Sprintf("Script %s points to %s (HTTP 200), a version 3 source map embedding the original source of %d file(s): %s",
				js.Path, mapURL.Path, embedded, evidence.Truncate(strings.Join(sm.Sources, ", "), 300))))
	}
	return out, nil
}

// sameOrigin resolves ref against base and keeps it only on the same origin.
func sameOrigin(base *url.URL, ref string) (*url.URL, bool) {
	u, err := base.Parse(strings.TrimSpace(ref))
	if err != nil || u.Scheme != base.Scheme || !strings.EqualFold(u.Host, base.Host) {
		return nil, false
	}
	u.Fragment = ""
	return u, true
}
