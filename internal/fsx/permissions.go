// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package fsx

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const linuxOPath = 0x200000

func RuntimeUser() string {
	if value := Env("RUNTIME_USER", ""); value != "" {
		return value
	}
	return runtimeDirective("user", "nobody")
}

func RuntimeGroup() string {
	if value := Env("RUNTIME_GROUP", ""); value != "" {
		return value
	}
	return runtimeDirective("group", "nogroup")
}

func runtimeDirective(name, fallback string) string {
	f, err := OpenFileNoFollow(ServerConf(), os.O_RDONLY, 0)
	if err != nil {
		return fallback
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == name {
				return strings.Trim(fields[1], `"'`)
			}
		}
	}
	return fallback
}

func RuntimeGroupID() (int, error) {
	name := RuntimeGroup()
	if n, err := strconv.ParseUint(name, 10, 32); err == nil {
		return int(n), nil
	}
	group, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("runtime group %q: %w", name, err)
	}
	return strconv.Atoi(group.Gid)
}

func openDirectory(path string, create bool, perm os.FileMode) (*os.File, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Open("/", linuxOPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), "/")
	parts := strings.Split(strings.TrimPrefix(abs, "/"), "/")
	for index, part := range parts {
		if part == "" {
			continue
		}
		flags := linuxOPath | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
		fd, err := syscall.Openat(int(dir.Fd()), part, flags, 0)
		if os.IsNotExist(err) && create {
			mode := perm.Perm()
			if index < len(parts)-1 {
				mode = 0o755
			}
			var parent syscall.Stat_t
			err = syscall.Fstat(int(dir.Fd()), &parent)
			if err == nil && (parent.Uid != uint32(os.Geteuid()) || parent.Mode&0o022 != 0) {
				err = fmt.Errorf("cannot safely create a directory under a writable or unowned parent")
			}
			if err == nil {
				err = syscall.Mkdirat(int(dir.Fd()), part, uint32(mode))
			}
			if err == nil {
				fd, err = syscall.Openat(int(dir.Fd()), part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
				if err == nil {
					var created syscall.Stat_t
					err = syscall.Fstat(fd, &created)
					if err == nil && created.Uid != uint32(os.Geteuid()) {
						err = fmt.Errorf("new directory ownership changed during creation")
					}
					if err == nil {
						err = syscall.Fchmod(fd, uint32(mode))
					}
					if err != nil {
						syscall.Close(fd)
					}
				}
			} else if os.IsExist(err) {
				fd, err = syscall.Openat(int(dir.Fd()), part, flags, 0)
			}
		}
		dir.Close()
		if err != nil {
			return nil, &os.PathError{Op: "open directory", Path: path, Err: err}
		}
		dir = os.NewFile(uintptr(fd), path)
	}
	return dir, nil
}

func MkdirAllNoFollow(path string, perm os.FileMode) error {
	f, err := openDirectory(path, true, perm)
	if err != nil {
		return err
	}
	return f.Close()
}

func openPathNoFollow(path string, flags int, perm os.FileMode) (*os.File, error) {
	dir, err := openDirectory(filepath.Dir(path), false, 0)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	fd, err := syscall.Openat(int(dir.Fd()), filepath.Base(path), flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, uint32(perm.Perm()))
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

func OpenFileNoFollow(path string, flags int, perm os.FileMode) (*os.File, error) {
	f, err := openPathNoFollow(path, flags, perm)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		f.Close()
		if err == nil {
			err = fmt.Errorf("%s is not a single-link regular file", path)
		}
		return nil, err
	}
	return f, nil
}

func SetPermissions(path string, perm os.FileMode, uid, gid int) error {
	f, err := openPathNoFollow(path, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	stat := info.Sys().(*syscall.Stat_t)
	if info.Mode().IsRegular() && stat.Nlink == 0 {
		return &os.PathError{Op: "permissions", Path: path, Err: os.ErrNotExist}
	}
	if !info.IsDir() && (!info.Mode().IsRegular() || stat.Nlink != 1) {
		return fmt.Errorf("%s is not a directory or single-link regular file", path)
	}
	if (uid >= 0 && int(stat.Uid) != uid) || (gid >= 0 && int(stat.Gid) != gid) {
		currentMode := info.Mode() & (os.ModePerm | os.ModeSetgid | os.ModeSetuid | os.ModeSticky)
		if restricted := currentMode & perm; restricted != currentMode {
			if err := f.Chmod(restricted); err != nil {
				return err
			}
		}
		if err := f.Chown(uid, gid); err != nil {
			return err
		}
		info, err = f.Stat()
		if err != nil {
			return err
		}
	}
	if info.Mode()&(os.ModePerm|os.ModeSetgid|os.ModeSetuid|os.ModeSticky) != perm {
		return f.Chmod(perm)
	}
	return nil
}
