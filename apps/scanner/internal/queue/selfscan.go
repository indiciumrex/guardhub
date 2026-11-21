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
	report := SelfScanReport{Target: canonical, VerifiedBy: out.method}
	report.Findings, report.CheckResults = s.RunChecks(ctx, target, s.Registry.IDs())
	return report, nil
}

// LabDomain is the only domain the validation lab may scan. ".test" is
// reserved (RFC 2606) and never resolves on the public internet, so a lab run
// cannot reach a real site even if a manifest is wrong.
const LabDomain = ".lab.test"

// ErrNotALabTarget: ScanOrigin refuses anything outside LabDomain.
var ErrNotALabTarget = errors.New("lab scans are limited to *" + LabDomain + " hosts on the private-host allowlist")

// ScanLabOrigin runs every registered check against a LAB origin the way a
// production scan does (same probe client and budget, same preflight), without
// Redis. It needs no ownership proof because it can only reach lab containers:
// the host must be under LabDomain AND on the SCANNER_ALLOW_PRIVATE_HOSTS
// allowlist (allowed is that list). Used by `scanner lab` only (§9.2).
func (s *Service) ScanLabOrigin(ctx context.Context, origin string, allowed []string) ([]evidence.Finding, []CheckResult, map[string]int, error) {
	u, err := checks.ParseOrigin(origin)
	if err != nil {
		return nil, nil, nil, err
	}
	host := strings.ToLower(u.Hostname())
	onList := false
	for _, h := range allowed {
		onList = onList || strings.EqualFold(strings.TrimSpace(h), host)
	}
	if !strings.HasSuffix(host, LabDomain) || !onList {
		return nil, nil, nil, ErrNotALabTarget
	}
	client := s.NewScanProbe()
	defer client.Close()
	target, err := checks.NewTarget(origin, client)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := preflight(ctx, target); err != nil {
		return nil, nil, nil, err
	}
	// Request cost per check (the lab reports it: do-no-harm is measured too).
	// Checks run one after another here, so the counter delta is per check.
	cost := map[string]int{"preflight": client.RequestsUsed()}
	findings := []evidence.Finding{}
	results := make([]CheckResult, 0)
	for _, id := range s.Registry.IDs() {
		before := client.RequestsUsed()
		found, res := s.isolatedCheck(ctx, id, target)
		cost[id] = client.RequestsUsed() - before
		findings = append(findings, found...)
		results = append(results, res)
	}
	return findings, results, cost, nil
}

// RunChecks runs the given checks one after another against target, outside
// the Redis job flow (self-scan, validation lab). Each check is isolated: a
// failure or panic is reported in its CheckResult and the others still run.
func (s *Service) RunChecks(ctx context.Context, target checks.Target, ids []string) ([]evidence.Finding, []CheckResult) {
	findings := []evidence.Finding{}
	results := make([]CheckResult, 0, len(ids))
	for _, id := range ids {
		found, res := s.isolatedCheck(ctx, id, target)
		findings = append(findings, found...)
		results = append(results, res)
	}
	return findings, results
}

// isolatedCheck runs one check; a panic is contained and reported as failed.
func (s *Service) isolatedCheck(ctx context.Context, id string, target checks.Target) (found []evidence.Finding, res CheckResult) {
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
