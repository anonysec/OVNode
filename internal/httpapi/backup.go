// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package httpapi

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"ovnode/internal/logging"
	"ovnode/internal/pki"
)

// backupRoots are the directories the node backs up: the OpenVPN PKI (the CA,
// the server certificate and key, the CRL) and the node's own state (user
// credentials, usage counters). A restore from this archive keeps every
// issued .ovpn valid, because the CA does not change.
//
// Resolved per call, not at init: the paths depend on the environment, which
// the test fixture sets after package init.
func backupRoots() []struct {
	name string
	path string
} {
	return []struct {
		name string
		path string
	}{
		{"pki", pki.PKIDir()},
		{"data", pki.OVNodeDir()},
	}
}

// handleBackup streams a gzipped tar of the node's PKI and state.
//
// The panel pulls this into its own backup set, so a rebuilt node can be
// restored without reissuing a single certificate. The body is raw, not the
// {success,msg,data} envelope: it is an archive.
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="ovnode-backup.tar.gz"`)
	w.WriteHeader(http.StatusOK)

	gz := gzip.NewWriter(w)
	defer func() { _ = gz.Close() }()
	tw := tar.NewWriter(gz)
	defer func() { _ = tw.Close() }()

	for _, root := range backupRoots() {
		if err := writeBackupTree(tw, root.name, root.path); err != nil {
			logging.Warn("backup archive failed for %s: %v", root.path, err)
			return
		}
	}
}

// writeBackupTree adds one directory tree to the archive under prefix.
func writeBackupTree(tw *tar.Writer, prefix, root string) error {
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		// A missing directory is not an error: a node without a state dir
		// still has a PKI worth backing up.
		return nil
	}
	return filepath.Walk(root, func(path string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		// A symlink could point outside the tree; it is skipped rather
		// than followed.
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if !fi.Mode().IsRegular() && !fi.IsDir() {
			return nil
		}
		header, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(filepath.Join(prefix, rel))
		if fi.IsDir() {
			header.Name += "/"
		}
		// The archive holds private keys: keep the restrictive mode.
		header.Mode = int64(fi.Mode().Perm())
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		_, err = io.Copy(tw, f)
		return err
	})
}
