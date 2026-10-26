// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package version

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The version is shown in the installer banner, the operator menu, the
// panel's node card and the README badge. A missed bump is silent: nothing
// but this test notices, and the four spots drift apart over time.
//
// The set below is the whole set. It is enumerated rather than discovered, so
// a release that adds a new version spot still needs this list updated; the
// test just stops the existing ones drifting.
func TestVersionSpotsAgree(t *testing.T) {
	root := repoRoot(t)
	spots := []struct {
		file string
		re   *regexp.Regexp
	}{
		{"internal/version/version.go", regexp.MustCompile(`const Version = "([^"]+)"`)},
		{"install.sh", regexp.MustCompile(`(?m)^VERSION="([^"]+)"`)},
		{"ovnode.sh", regexp.MustCompile(`(?m)^VERSION="([^"]+)"`)},
		{"README.md", regexp.MustCompile(`badge/version-([0-9][^-]*)`)},
	}
	for _, spot := range spots {
		data, err := os.ReadFile(filepath.Join(root, spot.file))
		if err != nil {
			t.Errorf("%s: %v", spot.file, err)
			continue
		}
		m := spot.re.FindSubmatch(data)
		if m == nil {
			t.Errorf("%s: no version match for %s", spot.file, spot.re)
			continue
		}
		if got := string(m[1]); got != Version {
			t.Errorf("%s says %q, but the binary reports %q", spot.file, got, Version)
		}
	}
}

// repoRoot walks up from the package directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("go.mod not found above the package directory")
	return ""
}

// The tag a release is cut from must be the version the binary reports, or
// the installer fetches a tarball the agent does not match.
func TestVersionHasNoStrayWhitespace(t *testing.T) {
	if strings.TrimSpace(Version) != Version {
		t.Errorf("Version = %q, want no surrounding whitespace", Version)
	}
}
