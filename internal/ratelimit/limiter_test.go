package ratelimit_test

import (
	"context"
	"testing"
	"time"

	"ipcheck/internal/ratelimit"
)

func TestTickerRateLimiter_Wait(t *testing.T) {
	interval := 100 * time.Millisecond
	limiter := ratelimit.NewTickerRateLimiter(interval)
	defer limiter.Stop()

	// Test initial wait (should wait for the interval)
	start1 := time.Now()
	ctx1, cancel1 := context.WithTimeout(context.Background(), interval+50*time.Millisecond) // Allow some buffer
	defer cancel1()
	if err := limiter.Wait(ctx1); err != nil {
		t.Fatalf("First wait failed unexpectedly: %v", err)
	}
	elapsed1 := time.Since(start1)
	if elapsed1 < interval-(10*time.Millisecond) || elapsed1 > interval+(50*time.Millisecond) { // Allow slight variance
		t.Errorf("First Wait did not respect the interval. Expected around %v, got %v", interval, elapsed1)
	}

	// Test if it waits for the interval
	start := time.Now()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*interval)
	defer cancel2()
	if err := limiter.Wait(ctx2); err != nil {
		t.Fatalf("Second wait failed unexpectedly: %v", err)
	}
	elapsed := time.Since(start)

	// Allow a small margin for scheduler delays
	if elapsed < interval-(10*time.Millisecond) {
		t.Errorf("Wait did not respect the interval. Expected at least %v, got %v", interval, elapsed)
	}

	// Test context cancellation during wait
	cancelCtx, cancelCancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(interval / 2) // Cancel halfway through the expected wait
		cancelCancel()
	}()

	err := limiter.Wait(cancelCtx)
	if err == nil {
		t.Fatal("Expected Wait to return an error due to context cancellation, but it didn't")
	}
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled error, got %v", err)
	}
}
