// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package httpapi

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"ovnode/internal/logging"
	"ovnode/internal/pki"
)

// maxBackupArchive bounds the in-memory archive. A PKI plus user state is a
// few megabytes; 64 MiB is far above any healthy node and stops a runaway
// tree from exhausting the agent.
const maxBackupArchive = 64 << 20

var errBackupTooLarge = errors.New("backup archive exceeds the size limit")

// cappedBuffer fails once the archive passes the limit, so the writer chain
// stops before the agent allocates unbounded memory.
type cappedBuffer struct {
	bytes.Buffer
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.Len()+len(p) > c.max {
		return 0, errBackupTooLarge
	}
	return c.Buffer.Write(p)
}

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

// handleBackup returns a gzipped tar of the node's PKI and state.
//
// The panel pulls this into its own backup set, so a rebuilt node can be
// restored without reissuing a single certificate. The body is raw, not the
// {success,msg,data} envelope: it is an archive.
//
// The archive is built before any header is written. Streaming it directly
// made a failure indistinguishable from success: the client got HTTP 200 and
// a truncated tar. Now a failure is a real status code, and the body carries
// an exact Content-Length.
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	var buf cappedBuffer
	buf.max = maxBackupArchive
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	for _, root := range backupRoots() {
		if err := writeBackupTree(tw, root.name, root.path); err != nil {
			logging.Warn("backup archive failed for %s: %v", root.path, err)
			writeEnvelope(w, http.StatusInternalServerError, false, "backup archive failed", nil)
			return
		}
	}
	if err := tw.Close(); err != nil {
		logging.Warn("backup tar close: %v", err)
		writeEnvelope(w, http.StatusInternalServerError, false, "backup archive failed", nil)
		return
	}
	if err := gz.Close(); err != nil {
		logging.Warn("backup gzip close: %v", err)
		writeEnvelope(w, http.StatusInternalServerError, false, "backup archive failed", nil)
		return
	}

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="ovnode-backup.tar.gz"`)
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(buf.Bytes()); err != nil {
		logging.Warn("backup write: %v", err)
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
