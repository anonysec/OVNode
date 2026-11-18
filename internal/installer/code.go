// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package installer

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// SnapshotCode archives the installed app tree so `ovnode rollback` can put
// the exact previous release back. The shell installer's snapshot_code uses
// the same name and layout: <label>-code-<base>-<stamp>.tar.gz with <base>/
// as the archive root.
func SnapshotCode(appDir, backupRoot, label string) (string, error) {
	base := filepath.Base(appDir)
	stamp := time.Now().Format("20060102-150405")
	final := filepath.Join(backupRoot, fmt.Sprintf("%s-code-%s-%s.tar.gz", label, base, stamp))
	if err := os.MkdirAll(backupRoot, 0o755); err != nil {
		return "", err
	}
	fd, err := os.CreateTemp(backupRoot, "."+label+"-code-*.part")
	if err != nil {
		return "", err
	}
	tmp := fd.Name()
	cleanup := func() { _ = fd.Close(); _ = os.Remove(tmp) }

	gw := gzip.NewWriter(fd)
	tw := tar.NewWriter(gw)
	walkErr := filepath.Walk(appDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(appDir, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(filepath.Join(base, rel))
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = name
		hdr.ModTime = time.Unix(0, 0)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		f, err := os.Open(path) // #nosec G304 -- path comes from the install tree walk
		if err != nil {
			return err
		}
		_, err = io.Copy(tw, f)
		closeErr := f.Close()
		if err != nil {
			return err
		}
		return closeErr
	})
	if walkErr == nil {
		walkErr = tw.Close()
	} else {
		_ = tw.Close()
	}
	if err := gw.Close(); err != nil && walkErr == nil {
		walkErr = err
	}
	if walkErr != nil {
		cleanup()
		return "", walkErr
	}
	if err := fd.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	pruneCodeSnapshots(backupRoot, label, 2)
	return final, nil
}

func pruneCodeSnapshots(backupRoot, label string, keep int) {
	matches, _ := filepath.Glob(filepath.Join(backupRoot, label+"-code-*.tar.gz"))
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))
	for i := keep; i < len(matches); i++ {
		_ = os.Remove(matches[i])
	}
}
