// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package store

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestPolicyMergeProcess(t *testing.T) {
	dir := os.Getenv("TestPOLICY_MERGE")
	if dir == "" {
		return
	}
	var err error
	if os.Getenv("TestPOLICY_FIELD") == "limit" {
		err = SetLimit(dir, "alice", 9)
	} else {
		err = SetDisabled(dir, "alice", true)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestPolicyMergeSerializesWriters(t *testing.T) {
	for _, processes := range []bool{false, true} {
		name := "goroutines"
		if processes {
			name = "processes"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			for range 8 {
				limit, disabled := 1, false
				if err := WriteUserState(dir, "alice", &limit, &disabled); err != nil {
					t.Fatal(err)
				}
				start := make(chan struct{})
				var wg sync.WaitGroup
				for _, field := range []string{"limit", "disabled"} {
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						if processes {
							cmd := exec.CommandContext(ctx, exe, "-test.run=^TestPolicyMergeProcess$")
							cmd.Env = append(os.Environ(), "TestPOLICY_MERGE="+dir, "TestPOLICY_FIELD="+field)
							if output, err := cmd.CombinedOutput(); err != nil {
								t.Errorf("policy writer: %v\n%s", err, output)
							}
						} else if field == "limit" {
							if err := SetLimit(dir, "alice", 9); err != nil {
								t.Error(err)
							}
						} else if err := SetDisabled(dir, "alice", true); err != nil {
							t.Error(err)
						}
					}()
				}
				close(start)
				wg.Wait()
				st, err := ReadUserState(dir, "alice")
				if err != nil || st.Limit != 9 || !st.Disabled {
					t.Fatalf("concurrent merge lost a field: %+v (%v)", st, err)
				}
			}
			info, err := os.Stat(filepath.Join(dir, "alice", ".state.lock"))
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("policy lock must remain private: %v (%v)", info, err)
			}
		})
	}
}
