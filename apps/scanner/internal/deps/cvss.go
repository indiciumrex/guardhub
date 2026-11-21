package deps

// CVSS v3.0/v3.1 base score from a vector string, for advisories that carry
// a vector but no GitHub Advisory rating (ADR-0006 §8). The formula is the
// FIRST specification's (v3.1 §7.1 and Appendix A Roundup).

import (
	"math"
	"strings"
)

// CVSS3BaseScore returns the base score of a "CVSS:3.x/AV:..." vector, or
// ok=false when the vector is not a complete v3 base vector.
func CVSS3BaseScore(vector string) (float64, bool) {
	parts := strings.Split(strings.TrimSpace(vector), "/")
	if len(parts) < 9 || (parts[0] != "CVSS:3.0" && parts[0] != "CVSS:3.1") {
		return 0, false
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			return 0, false
		}
		m[k] = v
	}
	weights := map[string]map[string]float64{
		"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
		"AC": {"L": 0.77, "H": 0.44},
		"UI": {"N": 0.85, "R": 0.62},
		"C":  {"H": 0.56, "L": 0.22, "N": 0},
		"I":  {"H": 0.56, "L": 0.22, "N": 0},
		"A":  {"H": 0.56, "L": 0.22, "N": 0},
	}
	val := map[string]float64{}
	for k, w := range weights {
		x, ok := w[m[k]]
		if !ok {
			return 0, false
		}
		val[k] = x
	}
	changed := false
	switch m["S"] {
	case "U":
	case "C":
		changed = true
	default:
		return 0, false
	}
	var pr float64
	switch m["PR"] {
	case "N":
		pr = 0.85
	case "L":
		pr = 0.62
		if changed {
			pr = 0.68
		}
	case "H":
		pr = 0.27
		if changed {
			pr = 0.5
		}
	default:
		return 0, false
	}
	iss := 1 - (1-val["C"])*(1-val["I"])*(1-val["A"])
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	exploitability := 8.22 * val["AV"] * val["AC"] * pr * val["UI"]
	if impact <= 0 {
		return 0, true
	}
	if changed {
		return roundUp(math.Min(1.08*(impact+exploitability), 10)), true
	}
	return roundUp(math.Min(impact+exploitability, 10)), true
}

// roundUp is CVSS v3.1's Roundup: the smallest one-decimal number >= x,
// computed on integers to avoid floating-point artefacts.
func roundUp(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return float64(i/10000+1) / 10
}

// RatingFromScore maps a CVSS base score to the qualitative rating.
func RatingFromScore(score float64) Rating {
	switch {
	case score >= 9.0:
		return RatingCritical
	case score >= 7.0:
		return RatingHigh
	case score >= 4.0:
		return RatingModerate
	case score > 0:
		return RatingLow
	}
	return RatingUnrated
}
