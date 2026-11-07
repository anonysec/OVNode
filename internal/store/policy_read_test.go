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

func TestReadUserStateRejectsCorruptSplitLimit(t *testing.T) {
	for _, body := range []string{"", "oops", "2garbage", "-1\n", "1\nextra\n", "999999999999999999999999\n"} {
		t.Run(body, func(t *testing.T) {
			dir := t.TempDir()
			if err := CreateUser(dir, "alice"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "alice", "limit"), []byte(body), 0o640); err != nil {
				t.Fatal(err)
			}
			if st, err := ReadUserState(dir, "alice"); err == nil {
				t.Fatalf("corrupt split limit returned no error: %+v", st)
			}
		})
	}
}

func TestReadUserStateLegacyAndDefault(t *testing.T) {
	dir := t.TempDir()
	if err := CreateUser(dir, "alice"); err != nil {
		t.Fatal(err)
	}
	if st, err := ReadUserState(dir, "alice"); err != nil || st.LimitSet || st.Disabled {
		t.Fatalf("legitimate absent state: %+v (%v)", st, err)
	}
	if st, err := ReadUserState(dir, "absent"); err != nil || st.LimitSet || st.Disabled {
		t.Fatalf("legitimate absent user: %+v (%v)", st, err)
	}
	for _, body := range []string{"3", "3\n", "3\r\n", "0\n"} {
		if err := os.WriteFile(filepath.Join(dir, "alice", "limit"), []byte(body), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "alice", "disabled"), nil, 0o640); err != nil {
			t.Fatal(err)
		}
		st, err := ReadUserState(dir, "alice")
		if err != nil || !st.LimitSet || !st.Disabled || (body[0] == '0') != (st.Limit == 0) {
			t.Fatalf("valid split state %q: %+v (%v)", body, st, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "alice", "state"), []byte("disabled=0\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if st, err := ReadUserState(dir, "alice"); err != nil || st.Disabled || !st.LimitSet || st.Limit != 0 {
		t.Fatalf("merged disabled flag must override the legacy marker: %+v (%v)", st, err)
	}
}
