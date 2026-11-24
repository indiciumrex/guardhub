package queue

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/hksolutions/guardhub/apps/scanner/internal/checks"
)

// An admin-cancelled scan is skipped: acked, nothing published, nothing sent.
func TestCancelledScanIsSkipped(t *testing.T) {
	svc, mr, rdb := newCancelTestService(t)
	if err := mr.Set(CancelPrefix+"0b9b3c8e-2a0f-4c1e-9d65-3c1f0e4e7a11", "1"); err != nil {
		t.Fatal(err)
	}
	payload := `{"v":1,"kind":"scan","job_id":"7c9e6679-7425-40de-944b-e07fc1f90ae7","scan_id":"0b9b3c8e-2a0f-4c1e-9d65-3c1f0e4e7a11","target":"https://example.com","checks":["tls_cert"]}`
	id, err := rdb.XAdd(context.Background(), &redis.XAddArgs{Stream: StreamJobs, Values: map[string]any{PayloadField: payload}}).Result()
	if err != nil {
		t.Fatal(err)
	}
	svc.HandleMessage(context.Background(), redis.XMessage{ID: id, Values: map[string]any{PayloadField: payload}}, false)
	if n, _ := rdb.XLen(context.Background(), StreamEvents).Result(); n != 0 {
		t.Fatalf("a cancelled scan published %d events", n)
	}
}

func TestPublishInfo(t *testing.T) {
	svc, mr, _ := newCancelTestService(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { svc.PublishInfo(ctx, Info{HostRPS: 2, ActiveEnabled: false}); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for !mr.Exists(InfoPrefix+"c1") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	v, err := mr.Get(InfoPrefix + "c1")
	if err != nil || !strings.Contains(v, `"host_rps":2`) || !strings.Contains(v, `"consumer":"c1"`) {
		t.Fatalf("info %q %v", v, err)
	}
	if ttl := mr.TTL(InfoPrefix + "c1"); ttl <= 0 || ttl > 3*InfoInterval {
		t.Fatalf("ttl %v", ttl)
	}
}

func newCancelTestService(t *testing.T) (*Service, *miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return &Service{RDB: rdb, Consumer: "c1", Registry: checks.Default()}, mr, rdb
}
