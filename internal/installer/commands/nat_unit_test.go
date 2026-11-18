// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type noopRunner struct{}

func (noopRunner) Run(name string, args ...string) error              { return nil }
func (noopRunner) Output(name string, args ...string) ([]byte, error) { return nil, nil }

func TestWriteNatUnitCarriesInstanceIdentity(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SystemdDir", root)
	c := &Config{
		AppDir:     "/opt/testnode",
		Instance:   "testnode",
		NatService: "testnode-nat.service",
	}
	if err := c.writeNatUnit(noopRunner{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, c.NatService))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Environment=Instance=testnode", "Environment=AppDir=/opt/testnode"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("NAT unit missing %q", want)
		}
	}
}
