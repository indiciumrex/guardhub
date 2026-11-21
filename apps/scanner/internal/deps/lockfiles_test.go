package deps

import (
	"fmt"
	"testing"

	"github.com/hksolutions/guardhub/apps/scanner/internal/repo"
)

func snapshotOf(files map[string]string) *repo.Snapshot {
	s := &repo.Snapshot{Repo: "o/r", Commit: "c"}
	for p, d := range files {
		s.Files = append(s.Files, repo.File{Path: p, Data: []byte(d)})
	}
	return s
}

func pkgSet(pkgs []Package) map[string]bool {
	out := map[string]bool{}
	for _, p := range pkgs {
		out[fmt.Sprintf("%s|%s|%s@%s|dev=%v", p.Manifest, p.Ecosystem, p.Name, p.Version, p.Dev)] = true
	}
	return out
}

func expectPkgs(t *testing.T, got []Package, want ...string) {
	t.Helper()
	g := pkgSet(got)
	if len(g) != len(want) {
		t.Errorf("got %d packages %v, want %d %v", len(g), g, len(want), want)
	}
	for _, w := range want {
		if !g[w] {
			t.Errorf("missing %s in %v", w, g)
		}
	}
}

func TestPackageLockV3(t *testing.T) {
	lock := `{"name":"app","lockfileVersion":3,"packages":{
	  "": {"name":"app","version":"1.0.0"},
	  "node_modules/lodash": {"version":"4.17.15"},
	  "node_modules/mocha": {"version":"8.0.0","dev":true},
	  "node_modules/a/node_modules/@scope/b": {"version":"2.0.0-beta.1"},
	  "node_modules/aliased": {"name":"real-pkg","version":"1.2.3"},
	  "node_modules/gitdep": {"version":"git+ssh://git@github.com/x/y.git#abc"},
	  "node_modules/ws-link": {"resolved":"packages/ws","link":true},
	  "packages/ws": {"name":"ws","version":"0.0.1"},
	  "node_modules/lodash-dup": {"version":"4.17.15"}
	}}`
	pkgs, errs := FromSnapshot(snapshotOf(map[string]string{"web/package-lock.json": lock}))
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	expectPkgs(t, pkgs,
		"web/package-lock.json|npm|lodash@4.17.15|dev=false",
		"web/package-lock.json|npm|mocha@8.0.0|dev=true",
		"web/package-lock.json|npm|@scope/b@2.0.0-beta.1|dev=false",
		"web/package-lock.json|npm|real-pkg@1.2.3|dev=false",
		"web/package-lock.json|npm|lodash-dup@4.17.15|dev=false",
	)
}

func TestPackageLockV1(t *testing.T) {
	lock := `{"lockfileVersion":1,"dependencies":{
	  "minimist":{"version":"1.2.5"},
	  "jest":{"version":"26.0.0","dev":true,"dependencies":{"minimist":{"version":"1.2.0","dev":true}}},
	  "local":{"version":"file:../local"}
	}}`
	pkgs, _ := FromSnapshot(snapshotOf(map[string]string{"package-lock.json": lock}))
	expectPkgs(t, pkgs,
		"package-lock.json|npm|minimist@1.2.5|dev=false",
		"package-lock.json|npm|jest@26.0.0|dev=true",
		"package-lock.json|npm|minimist@1.2.0|dev=true",
	)
}

func TestPackageLockRuntimeWinsOverDev(t *testing.T) {
	lock := `{"lockfileVersion":1,"dependencies":{
	  "a":{"version":"1.0.0","dev":true,"dependencies":{"x":{"version":"1.0.0","dev":true}}},
	  "x":{"version":"1.0.0"}
	}}`
	pkgs, _ := FromSnapshot(snapshotOf(map[string]string{"package-lock.json": lock}))
	expectPkgs(t, pkgs, "package-lock.json|npm|a@1.0.0|dev=true", "package-lock.json|npm|x@1.0.0|dev=false")
}

func TestRequirements(t *testing.T) {
	req := "# app\nDjango==3.2.0\nrequests[security] == 2.19.0 ; python_version >= \"3\"\nPyYAML===5.3\n" +
		"flask>=1.0\n-r base.txt\n-e git+https://x/y.git#egg=y\nurllib3==1.24.1 --hash=sha256:abc\n" +
		"https://example.com/pkg.whl\nzope.interface==5.0  # pinned\n"
	pkgs, _ := FromSnapshot(snapshotOf(map[string]string{
		"requirements.txt":          req,
		"requirements-dev.txt":      "pytest==6.0.0\n",
		"requirements/test.txt":     "coverage==5.0\n",
		"requirements/prod.txt":     "gunicorn==19.0.0\n",
		"docs/requirements.md":      "Django==1.0\n", // not a requirements file
		"tools/requirements_ci.txt": "tox==3.0.0\n",
	}))
	expectPkgs(t, pkgs,
		"requirements.txt|PyPI|django@3.2.0|dev=false",
		"requirements.txt|PyPI|requests@2.19.0|dev=false",
		"requirements.txt|PyPI|pyyaml@5.3|dev=false",
		"requirements.txt|PyPI|urllib3@1.24.1|dev=false",
		"requirements.txt|PyPI|zope-interface@5.0|dev=false",
		"requirements-dev.txt|PyPI|pytest@6.0.0|dev=true",
		"requirements/test.txt|PyPI|coverage@5.0|dev=true",
		"requirements/prod.txt|PyPI|gunicorn@19.0.0|dev=false",
		"tools/requirements_ci.txt|PyPI|tox@3.0.0|dev=true",
	)
}

func TestPipfileLock(t *testing.T) {
	lock := `{"_meta":{},"default":{"django":{"version":"==2.2.0"},"localpkg":{"path":"."}},"develop":{"pytest":{"version":"==5.0.0"}}}`
	pkgs, errs := FromSnapshot(snapshotOf(map[string]string{"Pipfile.lock": lock}))
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	expectPkgs(t, pkgs, "Pipfile.lock|PyPI|django@2.2.0|dev=false", "Pipfile.lock|PyPI|pytest@5.0.0|dev=true")
}

func TestPoetryLock(t *testing.T) {
	lock := `
[[package]]
name = "Jinja2"
version = "2.10"
category = "main"

[[package]]
name = "pytest"
version = "5.0.0"
category = "dev"

[[package]]
name = "mylib"
version = "0.1.0"
[package.source]
type = "git"
url = "https://x/y.git"

[[package]]
name = "urllib3"
version = "1.25.0"
[package.source]
type = "legacy"
url = "https://mirror.example/simple"
`
	pkgs, errs := FromSnapshot(snapshotOf(map[string]string{"poetry.lock": lock}))
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	expectPkgs(t, pkgs, "poetry.lock|PyPI|jinja2@2.10|dev=false", "poetry.lock|PyPI|pytest@5.0.0|dev=true",
		"poetry.lock|PyPI|urllib3@1.25.0|dev=false")
}

func TestUVLockReachability(t *testing.T) {
	lock := `
version = 1

[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "fastapi" }]
[package.optional-dependencies]
s3 = [{ name = "boto3" }]
[package.dev-dependencies]
dev = [{ name = "pytest" }, { name = "starlette" }]

[[package]]
name = "fastapi"
version = "0.100.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "starlette" }]

[[package]]
name = "starlette"
version = "0.27.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "boto3"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "7.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "py" }]

[[package]]
name = "py"
version = "1.10.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "gitpkg"
version = "1.0.0"
source = { git = "https://x/y.git" }
`
	pkgs, errs := FromSnapshot(snapshotOf(map[string]string{"apps/api/uv.lock": lock}))
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	expectPkgs(t, pkgs,
		"apps/api/uv.lock|PyPI|fastapi@0.100.0|dev=false",
		"apps/api/uv.lock|PyPI|starlette@0.27.0|dev=false", // runtime via fastapi, although also a dev dep
		"apps/api/uv.lock|PyPI|boto3@1.0.0|dev=false",      // optional extra: counted as runtime
		"apps/api/uv.lock|PyPI|pytest@7.0.0|dev=true",
		"apps/api/uv.lock|PyPI|py@1.10.0|dev=true",
	)
}

func TestUVLockWithoutRootIsRuntime(t *testing.T) {
	lock := "version = 1\n[[package]]\nname = \"x\"\nversion = \"1.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n"
	pkgs, _ := FromSnapshot(snapshotOf(map[string]string{"uv.lock": lock}))
	expectPkgs(t, pkgs, "uv.lock|PyPI|x@1.0|dev=false")
}

func TestUnparsableLockfileIsReported(t *testing.T) {
	pkgs, errs := FromSnapshot(snapshotOf(map[string]string{
		"a/package-lock.json": "{not json",
		"b/package-lock.json": `{"lockfileVersion":3,"packages":{"node_modules/x":{"version":"1.0.0"}}}`,
	}))
	if len(errs) != 1 || errs[0].Manifest != "a/package-lock.json" {
		t.Fatalf("errs = %v", errs)
	}
	expectPkgs(t, pkgs, "b/package-lock.json|npm|x@1.0.0|dev=false")
}

func TestNoLockfileNoGuess(t *testing.T) {
	pkgs, errs := FromSnapshot(snapshotOf(map[string]string{
		"package.json":   `{"dependencies":{"lodash":"^4.17.0"}}`,
		"pyproject.toml": "[project]\ndependencies=[\"django>=3\"]\n",
		"setup.py":       "install_requires=['flask==0.12']",
	}))
	if len(pkgs) != 0 || len(errs) != 0 {
		t.Fatalf("ranges must never be guessed: %v %v", pkgs, errs)
	}
}
