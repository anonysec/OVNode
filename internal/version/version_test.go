// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package version

import (
	"regexp"
	"testing"
)

// The version is shown in the installer banner, the operator menu and the
// panel's node card. A malformed string there breaks all three at once, and
// nothing else in the tree would notice.
var versionPattern = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func TestVersionIsWellFormed(t *testing.T) {
	if !versionPattern.MatchString(Version) {
		t.Fatalf("Version = %q, want N.N.N", Version)
	}
}
