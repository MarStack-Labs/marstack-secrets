package ratelimit

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrRate    = errors.New("ratelimit: rate must be greater than zero")
	ErrBurst   = errors.New("ratelimit: burst must be at least one")
	ErrMaxKeys = errors.New("ratelimit: the key limit must be at least one")
)

const DefaultMaxKeys = 8192

type Options struct {
	PerMinute float64
	Burst     int
	MaxKeys   int
	Now       func() time.Time
}

type bucket struct {
	tokens float64
	seen   time.Time
}

type Limiter struct {
	perSecond float64
	burst     float64
	maxKeys   int
	idle      time.Duration
	now       func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

func New(opts Options) (*Limiter, error) {
	switch {
	case opts.PerMinute <= 0:
		return nil, ErrRate
	case opts.Burst < 1:
		return nil, ErrBurst
	case opts.MaxKeys < 0:
		return nil, ErrMaxKeys
	}

	limiter := &Limiter{
		perSecond: opts.PerMinute / 60,
		burst:     float64(opts.Burst),
		maxKeys:   opts.MaxKeys,
		now:       opts.Now,
		buckets:   make(map[string]*bucket),
	}
	if limiter.maxKeys == 0 {
		limiter.maxKeys = DefaultMaxKeys
	}
	if limiter.now == nil {
		limiter.now = time.Now
	}
	limiter.idle = time.Duration(limiter.burst/limiter.perSecond) * time.Second
	return limiter, nil
}

func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()

	current, known := l.buckets[key]
	if !known {
		l.makeRoom(now)
		current = &bucket{tokens: l.burst, seen: now}
		l.buckets[key] = current
	}

	elapsed := now.Sub(current.seen).Seconds()
	if elapsed > 0 {
		current.tokens = min(l.burst, current.tokens+elapsed*l.perSecond)
		current.seen = now
	}

	if current.tokens < 1 {
		return false
	}
	current.tokens--
	return true
}

func (l *Limiter) Tracked() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

func (l *Limiter) makeRoom(now time.Time) {
	if len(l.buckets) < l.maxKeys {
		return
	}

	for key, candidate := range l.buckets {
		if now.Sub(candidate.seen) >= l.idle {
			delete(l.buckets, key)
		}
	}

	for key := range l.buckets {
		if len(l.buckets) < l.maxKeys {
			break
		}
		delete(l.buckets, key)
	}
}
