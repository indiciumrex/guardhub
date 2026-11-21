package checks

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/labfixture"
	"github.com/hksolutions/guardhub/apps/scanner/internal/repo"
)

// Every realistic value below is generated at test time (labfixture): no
// credential-shaped string is committed, so our own secret scan stays clean.
func sec(kind, seed string) string { return labfixture.MustSecret(kind, seed) }

func secretFindings(t *testing.T, files map[string]string) map[string]evidence.Finding {
	t.Helper()
	snap := &repo.Snapshot{Repo: "acme/api", Commit: "fedcba9876543210fedcba9876543210fedcba98"}
	for p, d := range files {
		snap.Files = append(snap.Files, repo.File{Path: p, Data: []byte(d)})
	}
	fs, err := RepoSecrets{}.RunRepo(context.Background(), snap)
	if err != nil {
		t.Fatal(err)
	}
	validateFindings(t, fs)
	out := map[string]evidence.Finding{}
	for _, f := range fs {
		out[strings.TrimPrefix(f.Evidence.Location, "https://github.com/acme/api/blob/HEAD/")] = f
	}
	return out
}

func TestRepoSecretsFindsProviderSecrets(t *testing.T) {
	aws := sec("aws_secret_access_key", "t1")
	pat := sec("github_pat", "t2")
	live := sec("stripe_live_secret", "t3")
	testKey := sec("stripe_test_secret", "t4")
	pem := sec("private_key", "t5")
	hook := sec("slack_webhook", "t6")
	dbpw := sec("password", "t7")
	generic := sec("generic", "t8")
	openai := sec("openai_key", "t9")
	files := map[string]string{
		"config/aws.py":        "AWS_ACCESS_KEY_ID = 'AKIA" + labfixture.Chars("k", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16) + "'\nAWS_SECRET_ACCESS_KEY = '" + aws + "'\n",
		"scripts/deploy.sh":    "#!/bin/sh\nexport GH_TOKEN=" + pat + "\ncurl -H \"Authorization: token $GH_TOKEN\" ...\n",
		"src/billing.js":       "const stripe = require('stripe')('" + live + "');\nconst t = '" + testKey + "';\n",
		"deploy/id_rsa":        pem + "\n",
		"src/notify.ts":        "const url = \"" + hook + "\";\n",
		"settings.py":          "DATABASES = {'default': dj_database_url.parse('postgres://app:" + dbpw + "@db.acme-prod.io:5432/app')}\n",
		"src/config.ts":        "export const config = {\n  apiSecret: \"" + generic + "\",\n};\n",
		"service-account.json": "{\"type\": \"service_account\", \"private_key\": \"" + strings.ReplaceAll(pem, "\n", `\n`) + "\"}\n",
		"ai/client.py":         "client = OpenAI(api_key=\"" + openai + "\")\n",
	}
	got := secretFindings(t, files)
	want := map[string]string{
		"config/aws.py#aws_secret_access_key": "hardcoded_secret",
		"scripts/deploy.sh#github_pat":        "hardcoded_secret",
		"src/billing.js#stripe_live_secret":   "hardcoded_secret",
		"src/billing.js#stripe_test_secret":   "test_mode_secret",
		"deploy/id_rsa#private_key":           "hardcoded_secret",
		"src/notify.ts#slack_webhook":         "hardcoded_secret",
		"settings.py#database_url":            "hardcoded_secret",
		"src/config.ts#generic":               "generic_secret",
		"service-account.json#private_key":    "hardcoded_secret",
		"ai/client.py#openai_key":             "hardcoded_secret",
	}
	for loc, key := range want {
		f, ok := got[loc]
		if !ok {
			t.Errorf("missing %s (%s)", loc, key)
			continue
		}
		if f.FindingKey != key {
			t.Errorf("%s: key %s, want %s", loc, f.FindingKey, key)
		}
	}
	for loc := range got {
		if _, ok := want[loc]; !ok {
			t.Errorf("unexpected finding %s", loc)
		}
	}
	// Evidence: last 4 characters only; the value and the line never appear.
	f := got["src/billing.js#stripe_live_secret"]
	if !strings.Contains(f.Evidence.RedactedPayload, "****"+live[len(live)-4:]) || strings.Contains(f.Evidence.RedactedPayload, live[:12]) {
		t.Errorf("payload not masked: %q", f.Evidence.RedactedPayload)
	}
	if f.Params["file"] != "src/billing.js" || f.Params["line"] != "1" || f.Params["secret_type"] != "Stripe live secret key" {
		t.Errorf("params %v", f.Params)
	}
	if got["src/config.ts#generic"].Params["variable"] != "apiSecret" || got["src/config.ts#generic"].Params["line"] != "2" {
		t.Errorf("generic params %v", got["src/config.ts#generic"].Params)
	}
	for _, fnd := range got {
		for _, v := range []string{aws, pat, live, testKey, hook, dbpw, generic, openai} {
			if strings.Contains(fnd.Evidence.RedactedPayload, v) || strings.Contains(fnd.Evidence.Location, v) {
				t.Fatalf("raw secret leaked into %s", fnd.Evidence.Location)
			}
			for _, p := range fnd.Params {
				if strings.Contains(p, v) {
					t.Fatalf("raw secret leaked into params of %s", fnd.Evidence.Location)
				}
			}
		}
	}
}

func TestRepoSecretsIgnoresFakesAndPlaceholders(t *testing.T) {
	real := sec("github_pat", "trap1")
	files := map[string]string{
		// AWS's documented example pair, placeholders and template variables.
		"README.md": "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n" +
			"STRIPE_KEY=sk_live_your_key_here_xxxxxxxxxxxxxxxx\nGITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
		".env.example":        "STRIPE_SECRET=" + sec("stripe_live_secret", "trap2") + "\n",
		"config.sample.json":  "{\"token\": \"" + real + "\"}\n",
		"tests/fixtures/x.py": "TOKEN = '" + real + "'\n",
		"src/__tests__/a.ts":  "const k = '" + sec("stripe_live_secret", "trap3") + "';\n",
		"api/handler_test.go": "const tok = \"" + real + "\"\n",
		"e2e/login.spec.ts":   "await page.fill('#pw', '" + sec("generic", "trap4") + "');\n",
		"docker-compose.yml":  "DATABASE_URL: postgres://postgres:" + sec("password", "trap5") + "@db:5432/app\nREDIS: redis://:pw@localhost:6379\n",
		"settings/local.py":   "DB = 'mysql://root:" + sec("password", "trap6") + "@127.0.0.1/app'\nX = 'postgres://u:" + sec("password", "trap7") + "@db.example.com/x'\n",
		"src/env.ts":          "export const password = process.env.DB_PASSWORD;\nconst apiKey = `${API_KEY}`;\nconst secret = \"changeme-changeme-123\";\n",
		"src/ids.ts":          "const client_id = \"" + sec("generic", "trap8") + "\";\nconst publicKey = \"" + sec("generic", "trap9") + "\";\nconst passwordHash = \"" + sec("generic", "trap10") + "\";\n",
		"src/words.py":        "PASSWORD_RESET_URL = 'https://acme.io/reset/password'\nsecret_message = 'this-is-not-a-secret-at-all'\n",
		"package-lock.json":   "{\"integrity\": \"sha512-" + sec("generic", "trap11") + "\", \"api_key\": \"" + sec("generic", "trap12") + "\"}\n",
		"web/dist/app.min.js": "var t=\"" + real + "\";",
		"src/seq.py":          "API_KEY = 'abcdefghijklmnop1234567890'\nAUTH_TOKEN = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n",
	}
	if got := secretFindings(t, files); len(got) != 0 {
		for loc, f := range got {
			t.Errorf("false positive %s (%s): %s", loc, f.FindingKey, f.Evidence.RedactedPayload)
		}
	}
}

func TestRepoSecretsCountsPerFileAndRule(t *testing.T) {
	a, b := sec("github_pat", "c1"), sec("github_pat", "c2")
	got := secretFindings(t, map[string]string{"ci/tokens.txt": a + "\n" + a + "\n\n" + b + "\n"})
	f, ok := got["ci/tokens.txt#github_pat"]
	if !ok || len(got) != 1 || f.Params["count"] != "2" || f.Params["line"] != "1" ||
		!strings.Contains(f.Evidence.RedactedPayload, "and 1 more in this file") {
		t.Fatalf("got %+v", got)
	}
}

func TestRepoSecretsTruncatedSnapshot(t *testing.T) {
	snap := &repo.Snapshot{Repo: "a/b", Truncated: true,
		Files: []repo.File{{Path: "x.sh", Data: []byte("T=" + sec("npm_token", "tr") + "\n")}}}
	fs, err := RepoSecrets{}.RunRepo(context.Background(), snap)
	if len(fs) != 1 || !errors.Is(err, repo.ErrTooLarge) {
		t.Fatalf("partial results + ErrTooLarge expected: %v %v", fs, err)
	}
}

func TestLabFixtureKindsAllMatchARule(t *testing.T) {
	// Every generator the lab can plant must be found by repo_secrets in a
	// plain source file, so lab ground truth never depends on a broken fixture.
	for _, kind := range labfixture.Kinds() {
		v := sec(kind, "kinds")
		var line string
		switch kind {
		case "password":
			line = "DSN = 'postgres://svc:" + v + "@db.acme-prod.io/app'"
		case "generic":
			line = "client_secret = '" + v + "'"
		case "aws_secret_access_key":
			line = "aws_secret_access_key = " + v
		default:
			line = "X = '" + v + "'"
		}
		got := secretFindings(t, map[string]string{"src/f.py": line + "\n"})
		if len(got) != 1 {
			t.Errorf("%s: %d findings for %q", kind, len(got), line[:min(len(line), 40)])
		}
	}
}
