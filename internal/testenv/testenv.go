// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package testenv

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func Run(m *testing.M, source func() string) {
	base := ""
	for _, name := range []string{"TestREPAIR_JAIL", "TestRUNTIME_JAIL", "TestINSTALLED_ENV_JAIL", "TestNESTED_JAIL"} {
		if value := os.Getenv(name); value != "" {
			base = value
			break
		}
	}
	dir, err := os.MkdirTemp(base, "ovnode-test-env-")
	if os.IsPermission(err) && base == "" {
		dir, err = os.MkdirTemp("/tmp", "ovnode-test-env-")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	path := filepath.Join(dir, ".env")
	old, present := os.LookupEnv("AppDir")
	if err = os.WriteFile(path, nil, 0o600); err == nil {
		err = os.Setenv("AppDir", dir)
	}
	if err == nil && source() != path {
		err = fmt.Errorf("test configuration was initialized outside its owned fixture")
	}
	if present {
		os.Setenv("AppDir", old)
	} else {
		os.Unsetenv("AppDir")
	}
	if err != nil {
		os.RemoveAll(dir)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
