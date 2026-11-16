// Package pool provides a bounded worker pool. Unbounded goroutines are
// forbidden in the scanner (GUARDHUB_STANDARDS §7.2): every concurrent task
// runs through a Pool whose size is configured and fixed.
package pool

import (
	"context"
	"sync"
)

// Pool runs at most Size tasks at the same time.
type Pool struct {
	sem chan struct{}
	wg  sync.WaitGroup
}

// New creates a pool with size slots (minimum 1).
func New(size int) *Pool {
	if size < 1 {
		size = 1
	}
	return &Pool{sem: make(chan struct{}, size)}
}

// Size returns the number of slots.
func (p *Pool) Size() int { return cap(p.sem) }

// Acquire blocks until a slot is free or ctx is done.
func (p *Pool) Acquire(ctx context.Context) error {
	select {
	case p.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release frees a slot taken with Acquire.
func (p *Pool) Release() { <-p.sem }

// Go waits for a free slot (or ctx), then runs fn in a goroutine that holds
// the slot until fn returns. It returns ctx.Err() if no slot was obtained,
// in which case fn does not run.
func (p *Pool) Go(ctx context.Context, fn func()) error {
	if err := p.Acquire(ctx); err != nil {
		return err
	}
	p.GoAcquired(fn)
	return nil
}

// GoAcquired runs fn in a goroutine using a slot that the caller already
// obtained with Acquire; the slot is released when fn returns.
func (p *Pool) GoAcquired(fn func()) {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer p.Release()
		fn()
	}()
}

// Wait blocks until every task started with Go/GoAcquired has finished.
func (p *Pool) Wait() { p.wg.Wait() }

// ForEach calls fn(ctx, i) for i in [0, n) with at most limit calls running
// concurrently, and returns when all started calls are done. When ctx is
// cancelled, calls not yet started are skipped (fn is not called for them).
func ForEach(ctx context.Context, limit, n int, fn func(ctx context.Context, i int)) {
	p := New(limit)
	for i := 0; i < n; i++ {
		if err := p.Go(ctx, func() { fn(ctx, i) }); err != nil {
			break
		}
	}
	p.Wait()
}
