package ovpn

import (
	"context"
	"runtime"
	"testing"
	"time"
)

// TestSupervisorStopsOnCtxCancel shows SIGTERM (ctx cancel) stops the
// supervisor within the WaitDelay budget and leaks no goroutine.
func TestSupervisorStopsOnCtxCancel(t *testing.T) {
	// No config on a temp tree: SuperviseOpenVPN returns false, so this
	// test exercises the supervise loop directly with a fake conf.
	before := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		supervise(ctx, "")
		close(done)
	}()
	// Give the loop a chance to start
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
		// ok
	case <-time.After(11 * time.Second):
		t.Fatal("supervisor did not stop within 11s")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("goroutine leak: before=%d after=%d", before, runtime.NumGoroutine())
}
