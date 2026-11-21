package deps

import "testing"

func TestSemverOrdering(t *testing.T) {
	// Each version sorts strictly before the next (SemVer 2.0 §11 example plus extras).
	ordered := []string{
		"0.9.9", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
		"1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.2.0", "1.10.0", "4.17.20", "4.17.21",
	}
	for i := 0; i+1 < len(ordered); i++ {
		c, ok := Compare(EcosystemNPM, ordered[i], ordered[i+1])
		if !ok || c != -1 {
			t.Errorf("%s < %s: got %d, ok=%v", ordered[i], ordered[i+1], c, ok)
		}
		c, _ = Compare(EcosystemNPM, ordered[i+1], ordered[i])
		if c != 1 {
			t.Errorf("%s > %s: got %d", ordered[i+1], ordered[i], c)
		}
	}
	if c, ok := Compare(EcosystemNPM, "1.0.0+build.1", "1.0.0"); !ok || c != 0 {
		t.Errorf("build metadata must not affect precedence: %d %v", c, ok)
	}
	for _, bad := range []string{"1.0", "latest", "^1.2.3", "1.2.3.4", "01.2.3", ""} {
		if _, ok := Compare(EcosystemNPM, bad, "1.0.0"); ok {
			t.Errorf("%q must not parse as semver", bad)
		}
	}
}

func TestPEP440Ordering(t *testing.T) {
	// From PEP 440's ordering rules / packaging's test suite.
	ordered := []string{
		"1.0.dev0", "1.0a1.dev0", "1.0a1", "1.0a2", "1.0b1", "1.0rc1", "1.0", "1.0.post1.dev0", "1.0.post1",
		"1.0.1", "1.1.dev1", "1.1", "2.0", "2.0.1", "1!0.1",
	}
	for i := 0; i+1 < len(ordered); i++ {
		c, ok := Compare(EcosystemPyPI, ordered[i], ordered[i+1])
		if !ok || c != -1 {
			t.Errorf("%s < %s: got %d, ok=%v", ordered[i], ordered[i+1], c, ok)
		}
	}
	equal := [][2]string{{"1.0", "1.0.0"}, {"1.0", "1.0.0.0"}, {"1.0a1", "1.0.alpha.1"}, {"1.0rc1", "1.0c1"},
		{"1.0.post1", "1.0-1"}, {"1.0.post1", "1.0.rev1"}, {"2.0", "v2.0"}, {"1.0+local.7", "1.0"}}
	for _, p := range equal {
		if c, ok := Compare(EcosystemPyPI, p[0], p[1]); !ok || c != 0 {
			t.Errorf("%s == %s: got %d, ok=%v", p[0], p[1], c, ok)
		}
	}
	for _, bad := range []string{"", "latest", "1.0-beta-x", ">=1.0", "1..0"} {
		if _, ok := Compare(EcosystemPyPI, bad, "1.0"); ok {
			t.Errorf("%q must not parse as PEP 440", bad)
		}
	}
	if _, ok := Compare("Go", "1.0.0", "1.0.0"); ok {
		t.Error("unknown ecosystems are not comparable")
	}
}

func TestCVSS3BaseScore(t *testing.T) {
	// Scores from the FIRST CVSS v3.1 calculator.
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": 5.5,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
		"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H": 9.9,
		"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.6,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
	}
	for v, want := range cases {
		got, ok := CVSS3BaseScore(v)
		if !ok || got != want {
			t.Errorf("%s: got %.1f ok=%v, want %.1f", v, got, ok, want)
		}
	}
	for _, bad := range []string{"", "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", "CVSS:3.1/AV:N", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"} {
		if _, ok := CVSS3BaseScore(bad); ok {
			t.Errorf("%q must not score", bad)
		}
	}
	if RatingFromScore(9.8) != RatingCritical || RatingFromScore(7.0) != RatingHigh || RatingFromScore(6.9) != RatingModerate ||
		RatingFromScore(0.1) != RatingLow || RatingFromScore(0) != RatingUnrated {
		t.Error("rating bands")
	}
}
