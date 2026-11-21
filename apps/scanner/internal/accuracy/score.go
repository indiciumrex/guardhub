package accuracy

import (
	"sort"

	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
)

// Gate: a check may be switched on (admin "enabled") only when its scorecard
// meets ALL of these. Precision first: a false alarm costs the user's trust.
const (
	MinPrecision = 0.95 // TP / (TP + FP)
	MinRecall    = 0.80 // TP / (TP + FN)
	MinPositives = 3    // ground-truth findings it was measured on (TP + FN)
	MinCleanRuns = 1    // targets where it must find nothing, and found nothing it shouldn't
)

// TargetRun is what the lab runner observed on one target.
type TargetRun struct {
	Target   string             `json:"target"`
	Origin   string             `json:"origin"`
	Findings []evidence.Finding `json:"findings"`
	// Failed maps a check id to its error code when the check did not finish.
	Failed map[string]string `json:"failed,omitempty"`
	// Error is set when the target could not be scanned at all (preflight).
	Error string `json:"error,omitempty"`
	// Requests: probe requests used per check (and "preflight") on this target.
	Requests map[string]int `json:"requests,omitempty"`
}

// Case is one scored item, kept so the scorecard can explain itself.
type Case struct {
	Target   string `json:"target"`
	Key      string `json:"key"`
	Location string `json:"location,omitempty"`
	Outside  bool   `json:"outside,omitempty"`
	Why      string `json:"why,omitempty"`
}

// KeyScore counts one finding key.
type KeyScore struct {
	TP int `json:"tp"`
	FP int `json:"fp"`
	FN int `json:"fn"`
}

// CheckScore is the scorecard of one check.
type CheckScore struct {
	CheckID   string `json:"check_id"`
	Targets   int    `json:"targets"`    // targets it was scored on
	CleanRuns int    `json:"clean_runs"` // scored targets with no expected finding
	TP        int    `json:"tp"`
	FP        int    `json:"fp"`
	FN        int    `json:"fn"`         // misses within the declared scope
	FNOutside int    `json:"fn_outside"` // misses of real issues beyond it
	Tolerated int    `json:"tolerated"`
	Errors    int    `json:"errors"` // runs where the check failed
	// MaxRequests: the most probe requests the check used on any lab target
	// (do-no-harm is measured too; the per-scan budget must cover the sum).
	MaxRequests int                 `json:"max_requests"`
	Precision   *float64            `json:"precision"`
	Recall      *float64            `json:"recall"`     // TP / (TP + FN): the gate
	RecallAll   *float64            `json:"recall_all"` // TP / (TP + FN + FN outside)
	MeetsGate   bool                `json:"meets_gate"`
	GateNotes   []string            `json:"gate_notes,omitempty"`
	ByKey       map[string]KeyScore `json:"by_key"`
	TruePos     []Case              `json:"true_positives"`
	FalsePos    []Case              `json:"false_positives"`
	FalseNeg    []Case              `json:"false_negatives"`
}

// Score compares runs with manifests and returns one scorecard per check id
// that is scored on at least one target, sorted by check id.
func Score(manifests []Manifest, runs []TargetRun) []CheckScore {
	byTarget := map[string]TargetRun{}
	for _, r := range runs {
		byTarget[r.Target] = r
	}
	scores := map[string]*CheckScore{}
	get := func(id string) *CheckScore {
		s, ok := scores[id]
		if !ok {
			s = &CheckScore{CheckID: id, ByKey: map[string]KeyScore{}}
			scores[id] = s
		}
		return s
	}
	bump := func(s *CheckScore, key string, f func(*KeyScore)) {
		k := s.ByKey[key]
		f(&k)
		s.ByKey[key] = k
	}

	for _, m := range manifests {
		run, ran := byTarget[m.Target]
		for _, id := range m.Checks {
			s := get(id)
			s.Targets++
			if n := run.Requests[id]; n > s.MaxRequests {
				s.MaxRequests = n
			}
			var expected []Expectation
			for _, e := range m.Expect {
				if e.Check == id {
					expected = append(expected, e)
				}
			}
			if len(expected) == 0 {
				s.CleanRuns++
			}
			_, failed := run.Failed[id]
			if !ran || run.Error != "" || failed {
				// Not measured on this target: every expected finding is missed.
				s.Errors++
				for _, e := range expected {
					s.miss(m.Target, e, "check did not run: ")
				}
				if len(expected) == 0 {
					s.CleanRuns-- // a clean run only counts when the check actually ran
				}
				continue
			}
			var found []evidence.Finding
			for _, f := range run.Findings {
				if f.CheckID == id {
					found = append(found, f)
				}
			}
			used := make([]bool, len(found))
			for _, e := range expected {
				hit := -1
				for i, f := range found {
					if !used[i] && e.matches(f) {
						hit = i
						break
					}
				}
				if hit >= 0 {
					used[hit] = true
					s.TP++
					bump(s, e.Key, func(k *KeyScore) { k.TP++ })
					s.TruePos = append(s.TruePos, Case{Target: m.Target, Key: e.Key, Location: found[hit].Evidence.Location, Why: e.Why})
				} else {
					s.miss(m.Target, e, "")
				}
			}
			for i, f := range found {
				if used[i] {
					continue
				}
				if tolerated(m.Tolerate, f) {
					s.Tolerated++
					continue
				}
				s.FP++
				bump(s, f.FindingKey, func(k *KeyScore) { k.FP++ })
				s.FalsePos = append(s.FalsePos, Case{Target: m.Target, Key: f.FindingKey, Location: f.Evidence.Location})
			}
		}
	}

	out := make([]CheckScore, 0, len(scores))
	for _, s := range scores {
		s.finish()
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CheckID < out[j].CheckID })
	return out
}

// miss records an expected finding that was not reported.
func (s *CheckScore) miss(target string, e Expectation, prefix string) {
	if e.Outside {
		s.FNOutside++
	} else {
		s.FN++
	}
	k := s.ByKey[e.Key]
	k.FN++
	s.ByKey[e.Key] = k
	s.FalseNeg = append(s.FalseNeg, Case{Target: target, Key: e.Key, Location: e.Location, Outside: e.Outside, Why: prefix + e.Why})
}

func tolerated(list []Expectation, f evidence.Finding) bool {
	for _, e := range list {
		if e.matches(f) {
			return true
		}
	}
	return false
}

func ratio(a, b int) *float64 {
	if b == 0 {
		return nil
	}
	v := float64(a) / float64(b)
	return &v
}

func (s *CheckScore) finish() {
	s.Precision = ratio(s.TP, s.TP+s.FP)
	s.Recall = ratio(s.TP, s.TP+s.FN)
	s.RecallAll = ratio(s.TP, s.TP+s.FN+s.FNOutside)
	for _, list := range [][]Case{s.TruePos, s.FalsePos, s.FalseNeg} {
		sortCases(list)
	}
	var notes []string
	if s.Errors > 0 {
		notes = append(notes, "the check failed on some lab targets")
	}
	if s.TP+s.FN < MinPositives {
		notes = append(notes, "too few ground-truth findings to measure")
	}
	if s.CleanRuns < MinCleanRuns {
		notes = append(notes, "no clean target to measure false positives on")
	}
	if s.Precision == nil || *s.Precision < MinPrecision {
		notes = append(notes, "precision below the gate")
	}
	if s.Recall == nil || *s.Recall < MinRecall {
		notes = append(notes, "recall below the gate")
	}
	s.GateNotes = notes
	s.MeetsGate = len(notes) == 0
}

func sortCases(cs []Case) {
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].Target != cs[j].Target {
			return cs[i].Target < cs[j].Target
		}
		if cs[i].Key != cs[j].Key {
			return cs[i].Key < cs[j].Key
		}
		return cs[i].Location < cs[j].Location
	})
}
