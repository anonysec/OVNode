// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package fsx

import (
	"os"
	"path/filepath"
)

// WriteFileAtomic writes data to path through a temporary file and a rename.
//
// The temporary name is not predictable: the tree is writable by the runtime
// user, so a guessable path is symlink bait. This is the single implementation;
// store, ovpn, pki and httpapi all use it.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		_ = os.Remove(tmp)
	}()
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// future upgrade: write a .bak copy of the previous file before rename
	if err := os.Chmod(tmp, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
