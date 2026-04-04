package ratelimit

import (
	"context"
	"time"
)

// RateLimiter defines the interface for a rate limiting mechanism.
type RateLimiter interface {
	Wait(ctx context.Context) error
	Stop()
}

// TickerRateLimiter implements RateLimiter using time.Ticker.
type TickerRateLimiter struct {
	ticker *time.Ticker
}

// NewTickerRateLimiter creates a new TickerRateLimiter with the given interval.
func NewTickerRateLimiter(interval time.Duration) *TickerRateLimiter {
	return &TickerRateLimiter{
		ticker: time.NewTicker(interval),
	}
}

// Wait waits for the next tick of the rate limiter.
// It returns an error if the context is cancelled during the wait.
func (t *TickerRateLimiter) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.ticker.C:
		return nil
	}
}

// Stop stops the underlying ticker.
func (t *TickerRateLimiter) Stop() {
	t.ticker.Stop()
}
