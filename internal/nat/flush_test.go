// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package nat

import (
	"os/exec"
	"strings"
	"testing"
)

func TestFlushOwnRulesRemovesStaleMasquerade(t *testing.T) {
	old := execCmd
	defer func() { execCmd = old }()
	var deleted []string
	execCmd = func(name string, args ...string) *exec.Cmd {
		if len(args) >= 4 && args[0] == "-t" && args[1] == "nat" && args[2] == "-S" {
			return exec.Command("printf", "%s\n", "-A POSTROUTING -s 10.66.1.0/24 -o eth0 -m comment --comment ovnode-nat -j MASQUERADE")
		}
		if len(args) >= 4 && args[0] == "-t" && args[1] == "nat" && args[2] == "-D" {
			deleted = append(deleted, strings.Join(args, " "))
		}
		return exec.Command("true")
	}
	if err := flushOwnRules("POSTROUTING", "ovnode-nat"); err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 || !strings.Contains(deleted[0], "-D POSTROUTING") {
		t.Fatalf("stale masquerade rule was not deleted: %v", deleted)
	}
}
