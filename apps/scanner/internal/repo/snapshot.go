// Package repo reads a connected GitHub repository into memory (ADR-0006):
// one tarball of the default branch, streamed entry by entry, bounded by
// size caps, never written to disk. Repo checks (dependency_vulns,
// repo_secrets) work on the resulting Snapshot; when the scan ends the
// snapshot is garbage and only findings leave the scanner.
package repo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

// Limits bound what a snapshot keeps in memory.
type Limits struct {
	Stream    int64 // compressed bytes read from the tarball stream
	File      int64 // largest ordinary text file kept
	Lockfile  int64 // largest dependency lockfile kept
	Total     int64 // all kept file bytes together
	MaxFiles  int   // number of kept files
	BinarySig int   // bytes inspected for a NUL to tell binary files
}

// DefaultLimits are the production caps (ADR-0006 §6).
func DefaultLimits() Limits {
	return Limits{
		Stream:    128 << 20,
		File:      1 << 20,
		Lockfile:  16 << 20,
		Total:     48 << 20,
		MaxFiles:  50000,
		BinarySig: 8000,
	}
}

// File is one kept text file. Path is relative to the repository root,
// slash-separated and clean.
type File struct {
	Path string
	Data []byte
}

// Snapshot is the in-memory view of one commit of one repository.
type Snapshot struct {
	Repo   string // owner/name
	Commit string // full commit sha the tarball was taken at
	Files  []File // sorted by Path
	// Truncated means a stream/total/file-count cap was hit: checks still
	// run on what was read, and report the scan as incomplete.
	Truncated bool
	// SkippedLarge counts single files over their size cap (not a
	// truncation: generated or data files, documented as a limit).
	SkippedLarge int
}

// ErrTooLarge marks an incomplete snapshot; checks return it (wrapped)
// together with their findings so the scan shows the check as incomplete.
var ErrTooLarge = errors.New("repository exceeds the snapshot caps")

// ErrBadArchive means the tarball stream could not be read at all.
var ErrBadArchive = errors.New("unreadable repository archive")

// vendoredDirs are skipped wherever they appear: third-party code that is
// not the repository's own (its lockfiles are what describe it).
var vendoredDirs = map[string]bool{
	".git": true, "node_modules": true, "bower_components": true, "jspm_packages": true,
	"vendor": true, "third_party": true, "third-party": true,
	".venv": true, "venv": true, "site-packages": true, "__pycache__": true,
	".tox": true, ".nox": true, ".mypy_cache": true, ".pytest_cache": true, ".ruff_cache": true,
	".next": true, ".nuxt": true, ".yarn": true, ".pnpm-store": true, ".terraform": true,
}

// IsLockfile reports whether p names a dependency lockfile the dependency
// check reads (it gets the larger size cap).
func IsLockfile(p string) bool {
	base := path.Base(p)
	switch base {
	case "package-lock.json", "npm-shrinkwrap.json", "uv.lock", "poetry.lock", "Pipfile.lock":
		return true
	}
	return IsRequirementsFile(p)
}

// IsRequirementsFile reports pip requirement files: requirements*.txt, or
// any *.txt inside a directory named "requirements".
func IsRequirementsFile(p string) bool {
	base := strings.ToLower(path.Base(p))
	if !strings.HasSuffix(base, ".txt") {
		return false
	}
	if strings.HasPrefix(base, "requirements") {
		return true
	}
	dir := strings.ToLower(path.Base(path.Dir(p)))
	return dir == "requirements"
}

// countingReader stops the stream at a byte cap.
type countingReader struct {
	r    io.Reader
	n    int64
	max  int64
	over bool
}

var errStreamCap = errors.New("stream cap reached")

func (c *countingReader) Read(p []byte) (int, error) {
	if c.n >= c.max {
		c.over = true
		return 0, errStreamCap
	}
	if rem := c.max - c.n; int64(len(p)) > rem {
		p = p[:rem]
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// ReadTarball builds a snapshot from a GitHub tarball stream (gzip'd tar
// whose entries sit under one top-level "<owner>-<repo>-<sha>/" directory).
// Only regular files are kept: symlinks, devices and directories are
// skipped, and no path can escape the root.
func ReadTarball(r io.Reader, lim Limits) (*Snapshot, error) {
	cr := &countingReader{r: r, max: lim.Stream}
	gz, err := gzip.NewReader(cr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadArchive, err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	snap := &Snapshot{}
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if cr.over {
				snap.Truncated = true
				break
			}
			if len(snap.Files) == 0 && snap.SkippedLarge == 0 {
				return nil, fmt.Errorf("%w: %w", ErrBadArchive, err)
			}
			// A stream that broke mid-way: keep what was read, say so.
			snap.Truncated = true
			break
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		rel, ok := relPath(hdr.Name)
		if !ok || skipPath(rel) {
			continue
		}
		limit := lim.File
		if IsLockfile(rel) {
			limit = lim.Lockfile
		}
		if hdr.Size > limit {
			snap.SkippedLarge++
			continue
		}
		if len(snap.Files) >= lim.MaxFiles || total+hdr.Size > lim.Total {
			snap.Truncated = true
			break
		}
		data, err := io.ReadAll(io.LimitReader(tr, limit+1))
		if err != nil {
			snap.Truncated = true
			break
		}
		if int64(len(data)) > limit {
			snap.SkippedLarge++
			continue
		}
		if isBinary(data, lim.BinarySig) {
			continue
		}
		total += int64(len(data))
		snap.Files = append(snap.Files, File{Path: rel, Data: data})
	}
	sort.Slice(snap.Files, func(i, j int) bool { return snap.Files[i].Path < snap.Files[j].Path })
	return snap, nil
}

// relPath strips the archive's top-level directory and cleans the rest.
// It refuses absolute paths and anything that climbs out of the root.
func relPath(name string) (string, bool) {
	name = strings.TrimPrefix(name, "./")
	i := strings.IndexByte(name, '/')
	if i < 0 {
		return "", false // the top-level directory itself, or a stray root file
	}
	rest := name[i+1:]
	if rest == "" || strings.HasPrefix(rest, "/") || strings.Contains(rest, "\\") {
		return "", false
	}
	clean := path.Clean(rest)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}
	return clean, true
}

func skipPath(rel string) bool {
	for _, part := range strings.Split(path.Dir(rel), "/") {
		if vendoredDirs[part] {
			return true
		}
	}
	return false
}

func isBinary(data []byte, sig int) bool {
	if len(data) > sig {
		data = data[:sig]
	}
	return bytes.IndexByte(data, 0) >= 0
}

// File returns the file at p, if kept.
func (s *Snapshot) File(p string) (File, bool) {
	i := sort.Search(len(s.Files), func(i int) bool { return s.Files[i].Path >= p })
	if i < len(s.Files) && s.Files[i].Path == p {
		return s.Files[i], true
	}
	return File{}, false
}
