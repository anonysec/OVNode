// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"ovnode/internal/fsx"
	"ovnode/internal/pki"
	"ovnode/internal/store"
)

var errUserGenerationChanged = errors.New("user generation was deleted or replaced")

func withUserLifecycle(cn string, fn func() error) error {
	usersDir := pki.UsersDir()
	dir, err := store.UserDir(usersDir, cn)
	if err != nil {
		return err
	}
	path := dir
	generation, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		path = pki.IssuedCertPath(cn)
		generation, err = fsx.OpenFileNoFollow(path, os.O_RDONLY, 0)
	}
	var previous os.FileInfo
	if err == nil {
		defer generation.Close()
		previous, err = generation.Stat()
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	uid, gid := os.Geteuid(), os.Getegid()
	if uid == 0 {
		gid, err = fsx.RuntimeGroupID()
		if err != nil {
			return err
		}
	}
	if err := fsx.MkdirAllNoFollow(usersDir, 0o750); err != nil {
		return err
	}
	if err := fsx.SetPermissions(usersDir, 0o750|os.ModeSetgid, uid, gid); err != nil {
		return err
	}
	return store.Lock(filepath.Join(usersDir, ".lifecycle."+cn), 0o600, func() error {
		if previous != nil {
			current, err := os.Lstat(path)
			if os.IsNotExist(err) {
				return errUserGenerationChanged
			}
			if err != nil {
				return err
			}
			if !os.SameFile(previous, current) {
				return errUserGenerationChanged
			}
		}
		return fn()
	})
}
