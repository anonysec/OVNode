// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ratelimit

import (
	"fmt"
	"testing"
)

// Failed-auth keys come from unauthenticated callers. record must apply the
// same bucket cap as allow, or a distributed flood grows the map without
// bound for the whole window.
func TestRecordCapsBuckets(t *testing.T) {
	w := &window{max: failedMax, span: failedWindow, hits: map[string]timeEntry{}}
	for i := 0; i < maxBuckets+500; i++ {
		w.record(fmt.Sprintf("198.51.%d.%d", i/256, i%256))
	}
	if len(w.hits) > maxBuckets {
		t.Fatalf("buckets = %d, want at most %d", len(w.hits), maxBuckets)
	}
}
