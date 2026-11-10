package updater

import (
	"strings"
	"testing"
)

func TestValidVersionRegexp(t *testing.T) {
	for _, v := range []string{"1.2.3", "0.0.0", "10.20.30"} {
		if !ValidVersion(v) {
			t.Fatalf("ValidVersion(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"", "1.2", "v1.2.3", "1.2.3-rc1", "01.2", "1..3", "a.b.c"} {
		if ValidVersion(v) {
			t.Fatalf("ValidVersion(%q) = true, want false", v)
		}
	}
}

func TestValidVersionRejectsNonPlainSemver(t *testing.T) {
	if ValidVersion("1.2.3\n") {
		t.Fatal("trailing newline must be rejected")
	}
	if ValidVersion(" 1.2.3") {
		t.Fatal("leading space must be rejected")
	}
	if !ValidVersion(strings.TrimSpace("1.2.3")) {
		t.Fatal("trimmed plain semver must be accepted")
	}
}
