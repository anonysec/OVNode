// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadUserStateRejectsCorruptPresentPolicy(t *testing.T) {
	for _, body := range []string{
		"broken policy\n", "limit=oops\ndisabled=oops\n", "limit=0\ndisabled=garbage\n",
		"", "limit=-1\n", "limit=999999999999999999999999\n",
		"limit=1\nlimit=0\n", "disabled=1\ndisabled=0\n", "unknown=1\n",
	} {
		t.Run(body, func(t *testing.T) {
			dir := t.TempDir()
			if err := CreateUser(dir, "alice"); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "alice", "state")
			if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
				t.Fatal(err)
			}
			if st, err := ReadUserState(dir, "alice"); err == nil {
				t.Errorf("corrupt policy returned an enabled/default state: %+v", st)
			}
			if err := SetLimit(dir, "alice", 2); err == nil {
				t.Error("policy merge overwrote corrupt state instead of returning the read error")
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != body {
				t.Errorf("failed policy merge changed existing data: %q (%v)", got, err)
			}
		})
	}
}
