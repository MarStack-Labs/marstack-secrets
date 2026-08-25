package ratelimit

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	at time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *clock) advance(by time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(by)
}

func newTestLimiter(t *testing.T, opts Options) (*Limiter, *clock) {
	t.Helper()
	tick := &clock{at: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)}
	opts.Now = tick.now

	limiter, err := New(opts)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	return limiter, tick
}

func TestTheBurstIsSpentThenRefused(t *testing.T) {
	limiter, _ := newTestLimiter(t, Options{PerMinute: 60, Burst: 3})

	for attempt := 1; attempt <= 3; attempt++ {
		if !limiter.Allow("a") {
			t.Fatalf("attempt %d was refused inside the burst", attempt)
		}
	}
	if limiter.Allow("a") {
		t.Fatal("the fourth attempt was allowed past the burst")
	}
}

func TestTokensComeBackWithTime(t *testing.T) {
	limiter, tick := newTestLimiter(t, Options{PerMinute: 60, Burst: 2})

	limiter.Allow("a")
	limiter.Allow("a")
	if limiter.Allow("a") {
		t.Fatal("the burst was not exhausted")
	}

	tick.advance(time.Second)
	if !limiter.Allow("a") {
		t.Fatal("a second should have restored one token at sixty per minute")
	}
	if limiter.Allow("a") {
		t.Fatal("more than one token came back")
	}

	tick.advance(time.Hour)
	for attempt := 1; attempt <= 2; attempt++ {
		if !limiter.Allow("a") {
			t.Fatalf("attempt %d was refused after a long idle period", attempt)
		}
	}
	if limiter.Allow("a") {
		t.Fatal("the bucket refilled past its burst")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	limiter, _ := newTestLimiter(t, Options{PerMinute: 60, Burst: 1})

	if !limiter.Allow("a") || !limiter.Allow("b") {
		t.Fatal("two different keys should each get their own burst")
	}
	if limiter.Allow("a") || limiter.Allow("b") {
		t.Fatal("a key was allowed past its burst")
	}
}

func TestTheKeyTableIsBounded(t *testing.T) {
	limiter, _ := newTestLimiter(t, Options{PerMinute: 60, Burst: 1, MaxKeys: 16})

	for attempt := range 1000 {
		limiter.Allow(fmt.Sprintf("attacker-%d", attempt))
	}

	if tracked := limiter.Tracked(); tracked > 16 {
		t.Fatalf("the limiter is tracking %d keys, want at most 16", tracked)
	}
}

func TestIdleKeysAreSweptBeforeAnythingElse(t *testing.T) {
	limiter, tick := newTestLimiter(t, Options{PerMinute: 60, Burst: 2, MaxKeys: 4})

	for _, key := range []string{"a", "b", "c", "d"} {
		limiter.Allow(key)
	}
	if tracked := limiter.Tracked(); tracked != 4 {
		t.Fatalf("Tracked() = %d, want 4", tracked)
	}

	tick.advance(time.Hour)
	limiter.Allow("fresh")

	if tracked := limiter.Tracked(); tracked != 1 {
		t.Fatalf("Tracked() = %d, want only the fresh key to remain", tracked)
	}
}

func TestAnEvictedKeyIsNotPunished(t *testing.T) {
	limiter, _ := newTestLimiter(t, Options{PerMinute: 60, Burst: 1, MaxKeys: 2})

	limiter.Allow("victim")
	if limiter.Allow("victim") {
		t.Fatal("the victim still had tokens")
	}

	for attempt := range 100 {
		limiter.Allow(fmt.Sprintf("filler-%d", attempt))
	}

	if !limiter.Allow("victim") {
		t.Error("an evicted key should start again rather than stay refused")
	}
}

func TestAllowIsSafeUnderConcurrentUse(t *testing.T) {
	limiter, _ := newTestLimiter(t, Options{PerMinute: 6000, Burst: 500})

	var group sync.WaitGroup
	allowed := make(chan bool, 1000)

	for worker := range 10 {
		group.Add(1)
		go func() {
			defer group.Done()
			for attempt := range 100 {
				allowed <- limiter.Allow(fmt.Sprintf("shared-%d", (worker+attempt)%3))
			}
		}()
	}
	group.Wait()
	close(allowed)

	var granted int
	for outcome := range allowed {
		if outcome {
			granted++
		}
	}
	if granted == 0 {
		t.Fatal("nothing was allowed")
	}
	if granted > 1500 {
		t.Fatalf("%d requests were allowed, well past three buckets of 500", granted)
	}
}

func TestNewValidatesItsOptions(t *testing.T) {
	cases := map[string]struct {
		opts Options
		want error
	}{
		"zero rate":     {opts: Options{PerMinute: 0, Burst: 1}, want: ErrRate},
		"negative rate": {opts: Options{PerMinute: -1, Burst: 1}, want: ErrRate},
		"zero burst":    {opts: Options{PerMinute: 60, Burst: 0}, want: ErrBurst},
		"negative keys": {opts: Options{PerMinute: 60, Burst: 1, MaxKeys: -1}, want: ErrMaxKeys},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(tc.opts); !errors.Is(err, tc.want) {
				t.Fatalf("New = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestASlowRateStillWorks(t *testing.T) {
	limiter, tick := newTestLimiter(t, Options{PerMinute: 6, Burst: 1})

	if !limiter.Allow("a") {
		t.Fatal("the first attempt was refused")
	}
	tick.advance(9 * time.Second)
	if limiter.Allow("a") {
		t.Fatal("nine seconds is not enough at six per minute")
	}
	tick.advance(2 * time.Second)
	if !limiter.Allow("a") {
		t.Fatal("eleven seconds should be enough at six per minute")
	}
}
