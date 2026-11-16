package progress

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestTracker(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()
	ctx := context.Background()
	tr := NewTracker(rdb)

	if err := tr.Init(ctx, "s1", []string{"exposed_env", "tls_cert"}); err != nil {
		t.Fatal(err)
	}
	key := "gh:scan:s1:progress"
	if Key("s1") != key {
		t.Fatal(Key("s1"))
	}
	got := mr.HGet(key, "exposed_env") + "," + mr.HGet(key, "tls_cert")
	if got != "queued,queued" {
		t.Fatalf("got %s", got)
	}
	if ttl := mr.TTL(key); ttl != 24*time.Hour {
		t.Fatalf("ttl %v", ttl)
	}
	if err := tr.Set(ctx, "s1", "tls_cert", Running); err != nil {
		t.Fatal(err)
	}
	if err := tr.Set(ctx, "s1", "exposed_env", Done); err != nil {
		t.Fatal(err)
	}
	if mr.HGet(key, "tls_cert") != "running" || mr.HGet(key, "exposed_env") != "done" {
		t.Fatal("status not updated")
	}
}
