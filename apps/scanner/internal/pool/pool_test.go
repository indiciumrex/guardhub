package pool

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// trackMax records the highest number of concurrently running tasks.
type trackMax struct{ cur, max atomic.Int32 }

func (t *trackMax) enter() {
	n := t.cur.Add(1)
	for {
		m := t.max.Load()
		if n <= m || t.max.CompareAndSwap(m, n) {
			return
		}
	}
}
func (t *trackMax) leave() { t.cur.Add(-1) }

func TestPoolBoundIsHonoured(t *testing.T) {
	p := New(3)
	var tr trackMax
	var done atomic.Int32
	for i := 0; i < 30; i++ {
		if err := p.Go(context.Background(), func() {
			tr.enter()
			time.Sleep(5 * time.Millisecond)
			tr.leave()
			done.Add(1)
		}); err != nil {
			t.Fatal(err)
		}
	}
	p.Wait()
	if done.Load() != 30 {
		t.Fatalf("ran %d tasks", done.Load())
	}
	if m := tr.max.Load(); m > 3 || m < 2 {
		t.Fatalf("max concurrency %d, want <= 3 (and actually parallel)", m)
	}
}

func TestForEachBound(t *testing.T) {
	var tr trackMax
	var seen [20]atomic.Bool
	ForEach(context.Background(), 4, 20, func(_ context.Context, i int) {
		tr.enter()
		time.Sleep(3 * time.Millisecond)
		seen[i].Store(true)
		tr.leave()
	})
	for i := range seen {
		if !seen[i].Load() {
			t.Fatalf("task %d did not run", i)
		}
	}
	if tr.max.Load() > 4 {
		t.Fatalf("max concurrency %d > 4", tr.max.Load())
	}
}

func TestGoRespectsContext(t *testing.T) {
	p := New(1)
	block := make(chan struct{})
	if err := p.Go(context.Background(), func() { <-block }); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	ran := false
	if err := p.Go(ctx, func() { ran = true }); err == nil {
		t.Fatal("expected context error while the pool is full")
	}
	close(block)
	p.Wait()
	if ran {
		t.Fatal("task must not run when no slot was obtained")
	}
}

func TestForEachStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var count atomic.Int32
	ForEach(ctx, 1, 100, func(_ context.Context, i int) {
		if count.Add(1) == 3 {
			cancel()
		}
	})
	if c := count.Load(); c > 4 {
		t.Fatalf("ran %d tasks after cancel", c)
	}
	if New(0).Size() != 1 {
		t.Fatal("size floor is 1")
	}
}
