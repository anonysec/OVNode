// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestHookTargetsPointAtTheGoBinary covers the stale marker file: a tree
// that still says "python" must not send server.conf back to the deleted
// bash hooks.
func TestHookTargetsPointAtTheGoBinary(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", dir)
	targets := HookTargets()
	for _, directive := range []string{"client-connect", "client-disconnect"} {
		target := targets[directive]
		if !strings.HasSuffix(target, "ovnode hook "+directive[len("client-"):]) {
			t.Fatalf("%s points at %q, want the go binary", directive, target)
		}
		if strings.Contains(target, ".sh") {
			t.Fatalf("%s points at a deleted bash hook: %q", directive, target)
		}
	}
}

func TestFreshServerConfOnlyRealOptions(t *testing.T) {
	openvpn, err := exec.LookPath("openvpn")
	if err != nil {
		t.Skip("openvpn not installed")
	}
	dir := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", dir)
	os.MkdirAll(filepath.Join(dir, "server"), 0o755)
	os.MkdirAll(filepath.Join(dir, "ovnode"), 0o755)
	conf := FreshServerConf()
	out, _ := exec.Command(openvpn, "--help").Output()
	known := map[string]bool{}
	re := regexp.MustCompile(`(?m)^--([a-z0-9][a-z0-9-]*)`)
	for _, m := range re.FindAllStringSubmatch(string(out), -1) {
		known[m[1]] = true
	}
	for _, extra := range []string{"persist-key", "data-ciphers-fallback"} {
		known[extra] = true
	}
	for _, raw := range strings.Split(conf, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name := strings.Fields(line)[0]
		name = strings.TrimPrefix(name, "-")
		if !known[name] {
			t.Errorf("unknown directive: %s", name)
		}
	}
}

func TestIsOVNodeHook(t *testing.T) {
	if !IsOVNodeHook("/x/ovnode") {
		t.Fatal("ovnode should be hook")
	}
	if IsOVNodeHook("/x/admin.sh") {
		t.Fatal("admin hook should not be ours")
	}
}
func TestFreshServerConfHasCRLVerify(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", dir)
	os.MkdirAll(filepath.Join(dir, "server"), 0o755)
	os.MkdirAll(filepath.Join(dir, "ovnode"), 0o755)
	conf := FreshServerConf()
	if !strings.Contains(conf, "crl-verify") {
		t.Fatal("missing crl-verify")
	}
	if !strings.Contains(conf, "duplicate-cn") {
		t.Fatal("missing duplicate-cn")
	}
}
