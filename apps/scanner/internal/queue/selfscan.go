package queue

// Self-scan (dogfooding, GUARDHUB_STANDARDS §2.5, §9.1): run every registered
// check once against our own origin without Redis, for the pre-release gate in
// ops/scripts/self_scan.py. The permission-first rule still applies: ownership
// is proven with the same verifier as customer targets before any check runs,
// and the same hardened probe clients (budget, rate limit, IP guard) are used.

import (
	"context"
	"errors"
	"strings"

	"github.com/hksolutions/guardhub/apps/scanner/internal/checks"
	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
)

// ErrNotVerified means the ownership proof was not found, so nothing was scanned.
var ErrNotVerified = errors.New("ownership not verified")

// SelfScanReport is the JSON printed by `scanner selfscan`.
type SelfScanReport struct {
	Target       string             `json:"target"`
	VerifiedBy   string             `json:"verified_by"`
	Findings     []evidence.Finding `json:"findings"`
	CheckResults []CheckResult      `json:"check_results"`
}

// SelfScan verifies ownership of origin with token, then runs all checks in
// registry order. It returns ErrNotVerified (wrapping the reason) when the
// proof is missing.
func (s *Service) SelfScan(ctx context.Context, origin, token string) (SelfScanReport, error) {
	u, err := checks.ParseOrigin(origin)
	if err != nil {
		return SelfScanReport{}, err
	}
	canonical := u.Scheme + "://" + u.Host

	vctx, cancel := context.WithTimeout(ctx, s.VerifyDeadline)
	vclient := s.NewVerifyProbe()
	out := verifyOwnership(vctx, vclient, canonical, strings.ToLower(u.Hostname()), token)
	vclient.Close()
	cancel()
	if out.method == "" {
		return SelfScanReport{}, errors.Join(ErrNotVerified, errors.New(out.errMsg))
	}

	client := s.NewScanProbe()
	defer client.Close()
	target, err := checks.NewTarget(canonical, client)
	if err != nil {
		return SelfScanReport{}, err
	}
	report := SelfScanReport{Target: canonical, VerifiedBy: out.method, Findings: []evidence.Finding{}}
	for _, id := range s.Registry.IDs() {
		found, res := s.selfScanCheck(ctx, id, target)
		report.Findings = append(report.Findings, found...)
		report.CheckResults = append(report.CheckResults, res)
	}
	return report, nil
}

// selfScanCheck runs one check; a panic is contained and reported as failed.
func (s *Service) selfScanCheck(ctx context.Context, id string, target checks.Target) (found []evidence.Finding, res CheckResult) {
	res = CheckResult{CheckID: id, Status: "done"}
	defer func() {
		if r := recover(); r != nil {
			s.log().Error("check panicked during self-scan", "check_id", id, "panic", r)
			code := ErrCodeInternal
			found, res = nil, CheckResult{CheckID: id, Status: "failed", Error: &code}
		}
	}()
	check, ok := s.Registry.Get(id)
	if !ok {
		code := ErrCodeUnknownCheck
		return nil, CheckResult{CheckID: id, Status: "failed", Error: &code}
	}
	found, err := check.Run(ctx, target)
	if err != nil {
		code := classifyCheckError(ctx, err)
		return nil, CheckResult{CheckID: id, Status: "failed", Error: &code}
	}
	return found, res
}
