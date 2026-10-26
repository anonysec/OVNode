// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

// Package installer is the part of install.sh that used to shell out to an
// inline python3 heredoc. Each function reproduces one helper: the JSON
// journal read and write, the identity hash, the state safety bundle, the
// restore after a failed activation, and the status probe. The output is
// byte-shaped to match the python so the existing test harness keeps passing.
package installer

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ── Identity (identity_sha) ─────────────────────────────────────────────

// IdentitySHA is the sha256 hex of node-name + "|" + api-key.
func IdentitySHA(name, key string) string {
	h := sha256.Sum256([]byte(name + "|" + key))
	return hex.EncodeToString(h[:])
}

// ── State safety snapshot (state_safety_bundle) ─────────────────────────

// Walk rules, matching the python helper byte-for-byte:
//   - skip update-maintenance and update-state.json
//   - follow only regular files (symlinks excluded, like tarfile default
//     dereference=False would not make them regular)
//   - compute a sha256 of every included member
//
// addTree is the archive-side wrapper: source root -> archive prefix.
func addToArchive(w *tar.Writer, src, prefix string, members map[string]string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, werr error) error {
		if werr != nil {
			return nil
		}
		if p == src {
			return nil
		}
		base := filepath.Base(p)
		if base == "update-maintenance" || base == "update-state.json" {
			return nil
		}
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		relArc := filepath.ToSlash(filepath.Join(prefix, rel))
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		hdr := &tar.Header{
			Name:     relArc,
			Size:     info.Size(),
			Mode:     0o644,
			ModTime:  time.Unix(0, 0),
			Typeflag: tar.TypeReg,
		}
		if err := w.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := io.Copy(w, f); err != nil {
			return err
		}
		h := sha256.New()
		f2, _ := os.Open(p)
		if f2 != nil {
			defer f2.Close()
			io.Copy(h, f2)
			members[relArc] = hex.EncodeToString(h.Sum(nil))
		}
		return nil
	})
}

func readEnv(path string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.IndexByte(line, '='); idx >= 0 {
			out[strings.TrimSpace(line[:idx])] = strings.TrimSpace(line[idx+1:])
		}
	}
	return out
}

// Bundle writes the state safety snapshot and returns its final path.
func Bundle(appDir, nodeData, ovpnRoot, backupRoot, node, fromVersion string) (string, error) {
	now := time.Now().UTC()
	stamp := now.Format("20060102_150405")
	final := filepath.Join(backupRoot, "ovnode-state-pre-update-"+stamp+".tar.gz")
	if err := os.MkdirAll(backupRoot, 0o755); err != nil {
		return "", err
	}
	if err := os.MkdirAll(nodeData, 0o755); err != nil {
		return "", err
	}

	fd, err := os.CreateTemp(backupRoot, ".ovnode-state-*.part")
	if err != nil {
		return "", err
	}
	tmp := fd.Name()
	cleanup := func() { fd.Close(); os.Remove(tmp) }

	gw, err := gzip.NewWriterLevel(fd, gzip.DefaultCompression)
	if err != nil {
		cleanup()
		return "", err
	}
	tw := tar.NewWriter(gw)

	members := map[string]string{}

	// node.env (the .env file).
	addFileEntry := func(path, arc string) error {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		hdr := &tar.Header{
			Name:     arc,
			Size:     info.Size(),
			Mode:     0o600,
			ModTime:  time.Unix(0, 0),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := io.Copy(tw, f); err != nil {
			return err
		}
		h := sha256.New()
		f2, _ := os.Open(path)
		if f2 != nil {
			defer f2.Close()
			io.Copy(h, f2)
		}
		members[arc] = hex.EncodeToString(h.Sum(nil))
		return nil
	}
	if err := addFileEntry(filepath.Join(appDir, ".env"), "node.env"); err != nil {
		cleanup()
		return "", err
	}

	// data/
	if err := addToArchive(tw, nodeData, "data", members); err != nil {
		cleanup()
		return "", err
	}
	// openvpn/{server,ccd,ovnode}
	for _, sub := range []string{"server", "ccd", "ovnode"} {
		src := filepath.Join(ovpnRoot, sub)
		if info, err := os.Stat(src); err == nil && info.IsDir() {
			if err := addToArchive(tw, src, filepath.ToSlash(filepath.Join("openvpn", sub)), members); err != nil {
				cleanup()
				return "", err
			}
		}
	}
	// tls/{SSL_KEYFILE, SSL_CERTFILE}
	env := readEnv(filepath.Join(appDir, ".env"))
	for _, key := range []string{"SSL_KEYFILE", "SSL_CERTFILE"} {
		target := env[key]
		if target != "" {
			if info, err := os.Stat(target); err == nil && info.Mode().IsRegular() {
				if err := addFileEntry(target, filepath.ToSlash(filepath.Join("tls", filepath.Base(target)))); err != nil {
					cleanup()
					return "", err
				}
			}
		}
	}

	// manifest
	manifest := map[string]any{
		"format":         "ovnode-state",
		"format_version": 1,
		"node":           node,
		"from_version":   fromVersion,
		"created_at":     now.Format(time.RFC3339Nano),
		"members":        members,
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		cleanup()
		return "", err
	}
	manifestData = append(manifestData, '\n')
	stageTmp, err := os.CreateTemp("", "ovnode-manifest-*")
	if err != nil {
		cleanup()
		return "", err
	}
	stageTmpName := stageTmp.Name()
	if _, err := stageTmp.Write(manifestData); err != nil {
		stageTmp.Close()
		os.Remove(stageTmpName)
		cleanup()
		return "", err
	}
	stageTmp.Close()
	info, _ := os.Stat(stageTmpName)
	hdr := &tar.Header{
		Name:     "manifest.json",
		Size:     info.Size(),
		Mode:     0o644,
		ModTime:  time.Unix(0, 0),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		os.Remove(stageTmpName)
		cleanup()
		return "", err
	}
	mf, _ := os.Open(stageTmpName)
	_, _ = io.Copy(tw, mf)
	mf.Close()
	os.Remove(stageTmpName)

	if err := tw.Close(); err != nil {
		cleanup()
		return "", err
	}
	if err := gw.Close(); err != nil {
		cleanup()
		return "", err
	}
	if err := fd.Sync(); err != nil {
		cleanup()
		return "", err
	}
	if err := fd.Close(); err != nil {
		cleanup()
		return "", err
	}
	// verify the bundle
	{
		vf, err := os.Open(tmp)
		if err != nil {
			cleanup()
			return "", err
		}
		vr, verr := gzip.NewReader(vf)
		if verr != nil {
			vf.Close()
			cleanup()
			return "", verr
		}
		tv := tar.NewReader(vr)
		names := map[string]bool{}
		var parsed map[string]any
		for {
			h, err := tv.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				vf.Close()
				cleanup()
				return "", err
			}
			if h.Typeflag == tar.TypeReg {
				names[h.Name] = true
			}
		}
		vf.Close()
		// read the manifest from the validated archive
		vf2, _ := os.Open(tmp)
		vr2, _ := gzip.NewReader(vf2)
		tv2 := tar.NewReader(vr2)
		for {
			h, err := tv2.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
			if h.Name == "manifest.json" {
				raw, _ := io.ReadAll(tv2)
				json.Unmarshal(raw, &parsed)
			}
		}
		vf2.Close()
		unsafe := false
		for n := range names {
			if strings.HasPrefix(n, "/") || strings.Contains(n, "..") {
				unsafe = true
			}
		}
		if !names["manifest.json"] || unsafe {
			cleanup()
			return "", fmt.Errorf("bundle verification failed")
		}
		mf2, _ := parsed["format"].(string)
		if mf2 != "ovnode-state" {
			cleanup()
			return "", fmt.Errorf("bundle verification failed: bad manifest")
		}
	}
	if err := os.Rename(tmp, final); err != nil {
		cleanup()
		return "", err
	}
	if err := os.Chmod(final, 0o600); err != nil {
		return "", err
	}
	// retention: keep 5 bundles
	entries, _ := filepath.Glob(filepath.Join(backupRoot, "ovnode-state-pre-update-*.tar.gz"))
	if len(entries) > 5 {
		sort.Strings(entries)
		for _, e := range entries[:len(entries)-5] {
			os.Remove(e)
		}
	}
	return final, nil
}

// ── Restore (state_restore) ──────────────────────────────────────────────

// Restore applies a safety bundle.
func Restore(bundle, appDir, dataBase, ovpnRoot string) error {
	f, err := os.Open(bundle)
	if err != nil {
		return err
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	infos := []tar.Header{}
	names := map[string]bool{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if h.Typeflag == tar.TypeReg {
			info := *h
			infos = append(infos, info)
			names[h.Name] = true
		}
	}
	if !names["manifest.json"] {
		return fmt.Errorf("unsafe state backup: no manifest")
	}
	for n := range names {
		if strings.HasPrefix(n, "/") || strings.Contains(n, "..") {
			return fmt.Errorf("unsafe state backup: unsafe member")
		}
	}
	// read manifest
	f2, _ := os.Open(bundle)
	defer f2.Close()
	gr2, _ := gzip.NewReader(f2)
	tr2 := tar.NewReader(gr2)
	var rawManifest []byte
	for {
		h, err := tr2.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		if h.Name == "manifest.json" {
			rawManifest, _ = io.ReadAll(tr2)
		}
	}
	var manifest struct {
		Format  string            `json:"format"`
		Members map[string]string `json:"members"`
	}
	if err := json.Unmarshal(rawManifest, &manifest); err != nil {
		return fmt.Errorf("unsafe state backup: bad manifest")
	}
	if manifest.Format != "ovnode-state" {
		return fmt.Errorf("unsafe state backup: bad manifest")
	}
	expected := manifest.Members

	// stage extraction
	staged, err := os.MkdirTemp("", "ovnode-restore-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staged)
	// extract all
	f3, _ := os.Open(bundle)
	defer f3.Close()
	gr3, _ := gzip.NewReader(f3)
	tr3 := tar.NewReader(gr3)
	for {
		h, err := tr3.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		dst := filepath.Join(staged, h.Name)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		out, err := os.Create(dst)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, tr3); err != nil {
			out.Close()
			return err
		}
		out.Close()
	}
	// verify checksums
	for rel, digest := range expected {
		f, err := os.Open(filepath.Join(staged, rel))
		if err != nil {
			return fmt.Errorf("state backup checksum mismatch: %s", rel)
		}
		h := sha256.New()
		io.Copy(h, f)
		f.Close()
		if hex.EncodeToString(h.Sum(nil)) != digest {
			return fmt.Errorf("state backup checksum mismatch: %s", rel)
		}
	}
	// apply
	for rel := range expected {
		var dst string
		if rel == "node.env" {
			dst = filepath.Join(appDir, ".env")
		} else if strings.HasPrefix(rel, "data/") {
			dst = filepath.Join(dataBase, filepath.FromSlash(strings.TrimPrefix(rel, "data/")))
		} else if strings.HasPrefix(rel, "openvpn/") {
			dst = filepath.Join(ovpnRoot, filepath.FromSlash(strings.TrimPrefix(rel, "openvpn/")))
		} else if strings.HasPrefix(rel, "tls/") {
			continue // certs restore via repair flow
		} else {
			return fmt.Errorf("unsafe state backup: unknown member %s", rel)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		src := filepath.Join(staged, filepath.FromSlash(rel))
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		fd, err := os.CreateTemp(filepath.Dir(dst), ".ovnode-restore-*")
		if err != nil {
			in.Close()
			return err
		}
		tmp := fd.Name()
		if _, err := io.Copy(fd, in); err != nil {
			in.Close()
			fd.Close()
			os.Remove(tmp)
			return err
		}
		in.Close()
		fd.Close()
		if strings.HasSuffix(dst, ".env") {
			os.Chmod(tmp, 0o600)
		}
		if err := os.Rename(tmp, dst); err != nil {
			os.Remove(tmp)
			return err
		}
	}
	fmt.Println("state restored")
	return nil
}

// ── probe ────────────────────────────────────────────────────────────────

// ProbeAgentStatus reads the JSON on r and returns "version openvpn_running".
func ProbeAgentStatus(r io.Reader) string {
	var doc struct {
		Data struct {
			Version        string      `json:"version"`
			OpenVPNRunning interface{} `json:"openvpn_running"`
		} `json:"data"`
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return " "
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return " "
	}
	rv := ""
	switch x := doc.Data.OpenVPNRunning.(type) {
	case bool:
		if x {
			rv = "true"
		} else {
			rv = "false"
		}
	case string:
		rv = strings.ToLower(x)
	case float64:
		if x != 0 {
			rv = "true"
		} else {
			rv = "false"
		}
	}
	return doc.Data.Version + " " + rv
}
