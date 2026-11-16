package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"
)

func TestFingerprint(t *testing.T) {
	sum := sha256.Sum256([]byte("exposed_env|env_file_exposed|https://a.test/.env"))
	want := hex.EncodeToString(sum[:])
	if got := Fingerprint("exposed_env", "env_file_exposed", "https://a.test/.env"); got != want {
		t.Fatalf("got %s want %s", got, want)
	}
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(want) {
		t.Fatal("fingerprint must be 64 lowercase hex chars")
	}
}

func TestNewUsesCatalogSeverityAndLimits(t *testing.T) {
	f := New(CheckExposedEnv, "env_file_exposed", map[string]string{"path": "/.env", "secret_count": "3"},
		KindHttpResponse, "https://a.test/.env", strings.Repeat("x", 5000))
	if f.Severity != SeverityCritical {
		t.Fatalf("severity %s", f.Severity)
	}
	if len(f.Evidence.RedactedPayload) > MaxPayloadLen {
		t.Fatalf("payload not truncated: %d", len(f.Evidence.RedactedPayload))
	}
	if f.Fingerprint != Fingerprint(CheckExposedEnv, "env_file_exposed", "https://a.test/.env") {
		t.Fatal("fingerprint mismatch")
	}
}

func TestNewPanicsOnUnknownKey(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	New(CheckExposedEnv, "not_a_key", nil, KindHttpResponse, "x", "")
}

func TestTruncateKeepsUTF8(t *testing.T) {
	s := strings.Repeat("ğ", 100) // 2 bytes each
	got := Truncate(s, 51)
	if len(got) > 51 || !strings.HasSuffix(got, "…") {
		t.Fatalf("bad truncation: %q (%d)", got, len(got))
	}
	if !utf8Valid(got) {
		t.Fatal("invalid utf8")
	}
	if Truncate("short", 10) != "short" {
		t.Fatal("short strings must be unchanged")
	}
}

func utf8Valid(s string) bool { return strings.ToValidUTF8(s, "?") == s }

func TestMaskSecret(t *testing.T) {
	cases := map[string]string{
		"supersecretabcd":    "****abcd",
		`"quoted-value1234"`: "****1234",
		"short":              "****",
		"":                   "",
	}
	for in, want := range cases {
		if got := MaskSecret(in); got != want {
			t.Errorf("MaskSecret(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMaskLinesNeverLeaksSecrets(t *testing.T) {
	secrets := []string{"p4ssw0rd-very-secret-abcd", "sk_live_51HxYzVeryLongStripeKey9xyz", "AKIAIOSFODNN7EXAMPLE"}
	text := "# comment\nDB_PASSWORD=" + secrets[0] + "\nexport STRIPE_KEY=\"" + secrets[1] + "\"\n" +
		"aws_access_key_id = " + secrets[2] + "\nA=1\nB=2\nC=3\nD=4\n"
	got := MaskLines(text, 5)
	for _, s := range secrets {
		if strings.Contains(got, s) {
			t.Fatalf("raw secret %q leaked in %q", s, got)
		}
	}
	if !strings.Contains(got, "DB_PASSWORD=****abcd") {
		t.Fatalf("expected masked line, got %q", got)
	}
	if !strings.Contains(got, "more lines") {
		t.Fatalf("expected truncation marker, got %q", got)
	}
	if n := strings.Count(got, "\n"); n != 5 { // 5 lines + marker
		t.Fatalf("expected 6 lines, got %d: %q", n+1, got)
	}
}

func TestMaskURLCredentials(t *testing.T) {
	got := MaskURLCredentials("url = https://deploy:ghp_secrettoken123@github.com/acme/app.git")
	if strings.Contains(got, "ghp_secrettoken123") || !strings.Contains(got, "https://****@github.com") {
		t.Fatalf("got %q", got)
	}
}
