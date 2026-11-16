package queue

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/hksolutions/guardhub/apps/scanner/internal/checks"
	"github.com/hksolutions/guardhub/apps/scanner/internal/evidence"
	"github.com/hksolutions/guardhub/apps/scanner/internal/probe"
)

type fakeResolver struct{ txt map[string][]string }

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if r, ok := f.txt[name]; ok {
		return r, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// panicCheck uses a real catalog id (registry requires it) and panics.
type panicCheck struct{}

func (panicCheck) ID() string { return evidence.CheckInfoLeak }
func (panicCheck) Run(context.Context, checks.Target) ([]evidence.Finding, error) {
	panic("boom")
}

type env struct {
	mr  *miniredis.Miniredis
	rdb *redis.Client
	svc *Service
}

func newEnv(t *testing.T, allow []string, resolver probe.Resolver) *env {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	opts := probe.Options{
		AllowPrivateHosts:  allow,
		HostRPS:            1000,
		HostBurst:          100,
		BackoffBase:        time.Millisecond,
		Timeout:            2 * time.Second,
		InsecureSkipVerify: true,
		Resolver:           resolver,
	}
	svc := &Service{
		RDB:              rdb,
		Consumer:         "test-consumer",
		Registry:         checks.NewRegistry(checks.ExposedEnv{}, checks.SecurityHeaders{}, panicCheck{}),
		NewScanProbe:     func() *probe.Client { return probe.New(opts) },
		NewVerifyProbe:   func() *probe.Client { v := opts; v.InsecureSkipVerify = false; return probe.New(v) },
		Workers:          2,
		CheckConcurrency: 2,
		VerifyDeadline:   5 * time.Second,
		ShutdownTimeout:  5 * time.Second,
		Block:            50 * time.Millisecond,
		Logger:           slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Now:              func() time.Time { return time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC) },
	}
	if err := svc.EnsureGroup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := svc.EnsureGroup(context.Background()); err != nil { // BUSYGROUP is ignored
		t.Fatal(err)
	}
	return &env{mr: mr, rdb: rdb, svc: svc}
}

func (e *env) enqueue(t *testing.T, payload any) string {
	t.Helper()
	var s string
	switch p := payload.(type) {
	case string:
		s = p
	default:
		b, _ := json.Marshal(p)
		s = string(b)
	}
	id, err := e.rdb.XAdd(context.Background(), &redis.XAddArgs{Stream: StreamJobs, Values: map[string]any{PayloadField: s}}).Result()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// processOne reads one message through the consumer and handles it.
func (e *env) processOne(t *testing.T) {
	t.Helper()
	e.svc.lastClaim = e.svc.now() // skip reclaim pass
	msg, claimed, err := e.svc.next(context.Background())
	if err != nil || msg == nil {
		t.Fatalf("no message: %v", err)
	}
	e.svc.HandleMessage(context.Background(), *msg, claimed)
}

func (e *env) events(t *testing.T) []map[string]any {
	t.Helper()
	msgs, err := e.rdb.XRange(context.Background(), StreamEvents, "-", "+").Result()
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, m := range msgs {
		var ev map[string]any
		if err := json.Unmarshal([]byte(m.Values[PayloadField].(string)), &ev); err != nil {
			t.Fatal(err)
		}
		out = append(out, ev)
	}
	return out
}

func (e *env) pendingCount(t *testing.T) int64 {
	t.Helper()
	p, err := e.rdb.XPending(context.Background(), StreamJobs, GroupScanners).Result()
	if err != nil {
		t.Fatal(err)
	}
	return p.Count
}

func scanJob(target string, checkIDs ...string) map[string]any {
	return map[string]any{"v": 1, "kind": "scan", "job_id": "job-1", "scan_id": "scan-1", "target": target,
		"checks": checkIDs, "deadline_seconds": 60}
}

func TestScanJobEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			_, _ = w.Write([]byte("DB_PASSWORD=very-secret-password-wxyz\nAPI_KEY=abcdefghijklmnop\n"))
			return
		}
		if r.URL.Path == "/" {
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	e := newEnv(t, []string{"127.0.0.1"}, nil)
	e.enqueue(t, scanJob(srv.URL, "exposed_env", "security_headers", "info_leak", "bogus_check"))
	e.processOne(t)

	evs := e.events(t)
	if len(evs) != 2 || evs[0]["type"] != EventScanStarted || evs[1]["type"] != EventScanCompleted {
		t.Fatalf("events: %v", evs)
	}
	if evs[0]["scan_id"] != "scan-1" || evs[0]["at"] != "2026-11-16T10:00:00Z" || evs[0]["v"] != float64(1) {
		t.Fatalf("started event: %v", evs[0])
	}
	completed := evs[1]
	findings := completed["findings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("findings: %v", findings)
	}
	f := findings[0].(map[string]any)
	if f["check_id"] != "exposed_env" || f["finding_key"] != "env_file_exposed" || f["severity"] != "critical" {
		t.Fatalf("finding: %v", f)
	}
	raw, _ := json.Marshal(completed)
	if strings.Contains(string(raw), "very-secret-password-wxyz") || strings.Contains(string(raw), "abcdefghijklmnop") {
		t.Fatal("raw secret in event")
	}

	results := completed["check_results"].([]any)
	want := []struct {
		id, status string
		err        any
	}{
		{"exposed_env", "done", nil},
		{"security_headers", "done", nil},
		{"info_leak", "failed", "internal"},
		{"bogus_check", "failed", "unknown_check"},
	}
	if len(results) != len(want) {
		t.Fatalf("check_results: %v", results)
	}
	for i, w := range want {
		r := results[i].(map[string]any)
		if r["check_id"] != w.id || r["status"] != w.status || r["error"] != w.err {
			t.Errorf("result %d = %v, want %+v", i, r, w)
		}
		if _, ok := r["error"]; !ok {
			t.Errorf("error key must be present (null) in %v", r)
		}
	}

	key := "gh:scan:scan-1:progress"
	for id, st := range map[string]string{"exposed_env": "done", "security_headers": "done", "info_leak": "failed", "bogus_check": "failed"} {
		if got := e.mr.HGet(key, id); got != st {
			t.Errorf("progress %s = %q, want %q", id, got, st)
		}
	}
	if ttl := e.mr.TTL(key); ttl <= 0 || ttl > 24*time.Hour {
		t.Fatalf("progress ttl %v", ttl)
	}
	if e.pendingCount(t) != 0 {
		t.Fatal("job must be acked after publishing")
	}
}

func TestScanJobBlockedTarget(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	e := newEnv(t, nil, nil) // no allowlist: 127.0.0.1 is private
	e.enqueue(t, scanJob(srv.URL, "exposed_env"))
	e.processOne(t)
	evs := e.events(t)
	if len(evs) != 2 || evs[1]["type"] != EventScanFailed || evs[1]["error"] != ErrCodeTargetBlocked {
		t.Fatalf("events: %v", evs)
	}
	if hits.Load() != 0 {
		t.Fatal("blocked target was contacted")
	}
	if e.mr.HGet("gh:scan:scan-1:progress", "exposed_env") != "failed" {
		t.Fatal("progress should be failed")
	}
	if e.pendingCount(t) != 0 {
		t.Fatal("must be acked")
	}
}

func TestScanJobUnreachableTarget(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	_ = l.Close()
	e := newEnv(t, []string{"127.0.0.1"}, nil)
	e.enqueue(t, scanJob("http://"+addr, "exposed_env"))
	e.processOne(t)
	evs := e.events(t)
	if len(evs) != 2 || evs[1]["type"] != EventScanFailed || evs[1]["error"] != ErrCodeTargetUnreachable {
		t.Fatalf("events: %v", evs)
	}
}

func TestScanDeadlineEnforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			return
		}
		select { // every other path hangs
		case <-time.After(5 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	e := newEnv(t, []string{"127.0.0.1"}, nil)
	job := scanJob(srv.URL, "exposed_env")
	job["deadline_seconds"] = 1
	e.enqueue(t, job)
	start := time.Now()
	e.processOne(t)
	if el := time.Since(start); el > 4*time.Second {
		t.Fatalf("deadline not enforced: %v", el)
	}
	evs := e.events(t)
	res := evs[len(evs)-1]["check_results"].([]any)[0].(map[string]any)
	if evs[len(evs)-1]["type"] != EventScanCompleted || res["status"] != "failed" || res["error"] != ErrCodeTimeout {
		t.Fatalf("events: %v", evs)
	}
}

func TestMalformedJobsAreAckedWithoutLooping(t *testing.T) {
	e := newEnv(t, nil, nil)
	e.enqueue(t, "this is not json")
	e.processOne(t)
	if len(e.events(t)) != 0 || e.pendingCount(t) != 0 {
		t.Fatal("garbage must be acked silently")
	}

	// A message without a payload field at all.
	if err := e.rdb.XAdd(context.Background(), &redis.XAddArgs{Stream: StreamJobs, Values: map[string]any{"x": "y"}}).Err(); err != nil {
		t.Fatal(err)
	}
	e.processOne(t)
	if e.pendingCount(t) != 0 {
		t.Fatal("must be acked")
	}

	// Malformed scan with a usable scan_id: the API is told.
	e.enqueue(t, `{"v":1,"kind":"scan","job_id":"j","scan_id":"s9","target":"https://x.test/path"}`)
	e.processOne(t)
	evs := e.events(t)
	if len(evs) != 1 || evs[0]["type"] != EventScanFailed || evs[0]["scan_id"] != "s9" || evs[0]["error"] != ErrCodeInternal {
		t.Fatalf("events: %v", evs)
	}

	// Malformed verify with a usable reply key: verified=false reply.
	e.enqueue(t, `{"v":1,"kind":"verify","job_id":"j2","target":"not-an-origin","token":"tok","reply_key":"gh:verify-reply:j2"}`)
	e.processOne(t)
	reply := popReply(t, e, "gh:verify-reply:j2")
	if reply.Verified || reply.Error == nil || *reply.Error != VerifyErrUnreachable {
		t.Fatalf("reply %+v", reply)
	}
	if e.pendingCount(t) != 0 {
		t.Fatal("must be acked")
	}
}

func popReply(t *testing.T, e *env, key string) VerifyReply {
	t.Helper()
	if ttl := e.mr.TTL(key); ttl <= 0 || ttl > VerifyReplyTTL {
		t.Fatalf("reply ttl %v", ttl)
	}
	s, err := e.rdb.RPop(context.Background(), key).Result()
	if err != nil {
		t.Fatalf("no reply on %s: %v", key, err)
	}
	var r VerifyReply
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	_ = json.Unmarshal([]byte(s), &generic)
	for _, k := range []string{"v", "job_id", "verified", "method", "error"} {
		if _, ok := generic[k]; !ok {
			t.Fatalf("reply missing %q: %s", k, s)
		}
	}
	return r
}

func verifyJob(target, token string) map[string]any {
	return map[string]any{"v": 1, "kind": "verify", "job_id": "vjob", "target": target, "token": token, "reply_key": "gh:verify-reply:vjob"}
}

func TestVerifyWellKnown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/guardhub-verify.txt" {
			_, _ = w.Write([]byte("# guardhub\nghv_token123\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	e := newEnv(t, []string{"127.0.0.1"}, nil)
	e.enqueue(t, verifyJob(srv.URL, "ghv_token123"))
	e.processOne(t)
	r := popReply(t, e, "gh:verify-reply:vjob")
	if !r.Verified || r.Method == nil || *r.Method != MethodWellKnown || r.Error != nil || r.JobID != "vjob" {
		t.Fatalf("reply %+v", r)
	}
	if e.pendingCount(t) != 0 {
		t.Fatal("must be acked")
	}
}

func TestVerifyMetaTag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte(`<html><head><meta content='ghv_meta' NAME="guardhub-verification" /></head></html>`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	e := newEnv(t, []string{"127.0.0.1"}, nil)
	e.enqueue(t, verifyJob(srv.URL, "ghv_meta"))
	e.processOne(t)
	if r := popReply(t, e, "gh:verify-reply:vjob"); !r.Verified || *r.Method != MethodMetaTag {
		t.Fatalf("reply %+v", r)
	}
}

func TestVerifyDNSTXT(t *testing.T) {
	// "verify.test" is allowlisted so CheckHost passes; HTTP fails (no such
	// host), and the fake resolver answers the TXT lookup.
	res := fakeResolver{txt: map[string][]string{"_guardhub.verify.test": {"v=spf1 -all", "guardhub-verify=ghv_dns"}}}
	e := newEnv(t, []string{"verify.test"}, res)
	e.enqueue(t, verifyJob("https://verify.test", "ghv_dns"))
	e.processOne(t)
	if r := popReply(t, e, "gh:verify-reply:vjob"); !r.Verified || *r.Method != MethodDNSTXT {
		t.Fatalf("reply %+v", r)
	}
}

func TestVerifyNotFoundBlockedUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte(`<meta name="guardhub-verification" content="someone-else">`))
			return
		}
		if r.URL.Path == "/.well-known/guardhub-verify.txt" {
			_, _ = w.Write([]byte("ghv_wrong"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	e := newEnv(t, []string{"127.0.0.1"}, fakeResolver{})
	e.enqueue(t, verifyJob(srv.URL, "ghv_right"))
	e.processOne(t)
	if r := popReply(t, e, "gh:verify-reply:vjob"); r.Verified || r.Method != nil || *r.Error != VerifyErrNotFound {
		t.Fatalf("reply %+v", r)
	}

	blocked := newEnv(t, nil, fakeResolver{})
	blocked.enqueue(t, verifyJob(srv.URL, "ghv_right"))
	blocked.processOne(t)
	if r := popReply(t, blocked, "gh:verify-reply:vjob"); r.Verified || *r.Error != VerifyErrBlocked {
		t.Fatalf("reply %+v", r)
	}

	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	_ = l.Close()
	down := newEnv(t, []string{"127.0.0.1"}, fakeResolver{})
	down.enqueue(t, verifyJob("http://"+addr, "ghv_right"))
	down.processOne(t)
	if r := popReply(t, down, "gh:verify-reply:vjob"); r.Verified || *r.Error != VerifyErrUnreachable {
		t.Fatalf("reply %+v", r)
	}
}

func TestVerifyMatchers(t *testing.T) {
	if !wellKnownMatches([]byte("  tok \n"), "tok") || wellKnownMatches([]byte("tokx"), "tok") || wellKnownMatches([]byte(""), "tok") {
		t.Fatal("wellKnownMatches")
	}
	if !metaTagMatches([]byte(`<meta name=guardhub-verification content=tok>`), "tok") {
		t.Fatal("unquoted meta")
	}
	if metaTagMatches([]byte(`<meta name="description" content="tok">`), "tok") {
		t.Fatal("wrong meta name must not match")
	}
	if !txtMatches([]string{"guardhub-verify=tok"}, "tok") || txtMatches([]string{"guardhub-verify=tok2"}, "tok") {
		t.Fatal("txtMatches")
	}
}

func TestReclaimStalePendingJob(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	e := newEnv(t, []string{"127.0.0.1"}, nil)
	e.enqueue(t, scanJob(srv.URL, "security_headers"))
	// A consumer that died after reading the job.
	if _, err := e.rdb.XReadGroup(context.Background(), &redis.XReadGroupArgs{Group: GroupScanners, Consumer: "dead", Streams: []string{StreamJobs, ">"}, Count: 1}).Result(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	e.svc.ClaimMinIdle = 10 * time.Millisecond
	msg, claimed, err := e.svc.next(context.Background())
	if err != nil || msg == nil || !claimed {
		t.Fatalf("expected reclaimed message: %v %v %v", msg, claimed, err)
	}
	e.svc.HandleMessage(context.Background(), *msg, claimed)
	if e.pendingCount(t) != 0 {
		t.Fatal("reclaimed job must be acked")
	}
	evs := e.events(t)
	if len(evs) != 2 || evs[1]["type"] != EventScanCompleted {
		t.Fatalf("events %v", evs)
	}
}

func TestPoisonMessageIsDropped(t *testing.T) {
	e := newEnv(t, nil, nil)
	e.enqueue(t, scanJob("https://example.com", "security_headers"))
	ctx := context.Background()
	if _, err := e.rdb.XReadGroup(ctx, &redis.XReadGroupArgs{Group: GroupScanners, Consumer: "c1", Streams: []string{StreamJobs, ">"}, Count: 1}).Result(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ { // each claim bumps the delivery counter
		time.Sleep(5 * time.Millisecond)
		if err := e.rdb.XAutoClaim(ctx, &redis.XAutoClaimArgs{Stream: StreamJobs, Group: GroupScanners, Consumer: "c2", MinIdle: time.Millisecond, Start: "0-0", Count: 1}).Err(); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(5 * time.Millisecond)
	e.svc.ClaimMinIdle = time.Millisecond
	e.svc.MaxDeliveries = 3
	msg, claimed, err := e.svc.next(ctx)
	if err != nil || msg == nil || !claimed {
		t.Fatalf("expected reclaimed message: %v", err)
	}
	e.svc.HandleMessage(ctx, *msg, claimed)
	evs := e.events(t)
	if len(evs) != 1 || evs[0]["type"] != EventScanFailed || evs[0]["error"] != ErrCodeInternal {
		t.Fatalf("poison job should fail without running: %v", evs)
	}
	if e.pendingCount(t) != 0 {
		t.Fatal("poison job must be acked")
	}
}

func TestRunLoopAndGracefulShutdown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	e := newEnv(t, []string{"127.0.0.1"}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.svc.Run(ctx) }()

	e.enqueue(t, scanJob(srv.URL, "security_headers"))
	deadline := time.Now().Add(5 * time.Second)
	for {
		evs := e.events(t)
		if len(evs) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("job not processed by Run: %v", evs)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after cancel")
	}
	if e.pendingCount(t) != 0 {
		t.Fatal("processed job must be acked")
	}
}
