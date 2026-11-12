// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package assets

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmbeddedShellAssetsArePresent(t *testing.T) {
	for _, a := range Assets() {
		if len(a.Body) == 0 {
			t.Fatalf("%s is not embedded", a.Name)
		}
		if !strings.HasPrefix(string(a.Body), "#!") {
			t.Errorf("%s does not start with a shebang", a.Name)
		}
	}
}

// The shell files are the installer's only syntax gate: nothing compiles
// them, so a broken heredoc reaches a box instead of the test run.
func TestEmbeddedShellAssetsPassBashSyntax(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed")
	}
	dir := t.TempDir()
	for _, a := range Assets() {
		p := filepath.Join(dir, a.Name)
		if err := os.WriteFile(p, a.Body, 0o644); err != nil {
			t.Fatalf("write %s: %v", a.Name, err)
		}
		out, err := exec.Command(bash, "-n", p).CombinedOutput()
		if err != nil {
			t.Errorf("bash -n %s: %v\n%s", a.Name, err, out)
		}
	}
}

func TestWriteInstallsEveryAsset(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "app")
	written, err := Write(dir)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(written) != len(Assets()) {
		t.Fatalf("wrote %d files, want %d", len(written), len(Assets()))
	}
	for _, a := range Assets() {
		p := filepath.Join(dir, a.Name)
		info, err := os.Stat(p)
		if err != nil {
			t.Errorf("%s was not written: %v", a.Name, err)
			continue
		}
		if info.Mode().Perm() != a.Mode {
			t.Errorf("%s mode is %o, want %o", a.Name, info.Mode().Perm(), a.Mode)
		}
	}
}

// The CLI reads OpenVpnRoot/LogDir from .env at startup, so it must source
// lib.sh (where env_get lives) first. Calling env_get before the source fails
// silently — stderr is discarded — and the declared paths are ignored.
func TestOperatorSourcesLibBeforeReadingEnv(t *testing.T) {
	body := string(Operator)
	source := strings.Index(body, `. "$_libdir/$_lib"`)
	call := strings.Index(body, `env_get "`)
	if source < 0 || call < 0 {
		t.Fatalf("source=%d call=%d", source, call)
	}
	if call < source {
		line := strings.SplitN(body[call:], "\n", 2)[0]
		t.Fatalf("env_get is called before lib.sh is sourced: %s", line)
	}
}
