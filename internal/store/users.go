// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package store

import (
	"encoding/json"
	"os"
	"path/filepath"

	"ovnode/internal/fsx"
	"sort"
	"strings"
)

// SafeCN validates a CN before it becomes a path component.
func SafeCN(cn string) (string, error) {
	return fsx.SafeCN(cn)
}

// UserDir returns the user directory path (validates CN).
func UserDir(usersDir, cn string) (string, error) {
	safe, err := SafeCN(cn)
	if err != nil {
		return "", err
	}
	return filepath.Join(usersDir, safe), nil
}

// UserExists reports whether the user directory exists.
func UserExists(usersDir, cn string) bool {
	dir, err := UserDir(usersDir, cn)
	if err != nil {
		return false
	}
	info, err := os.Stat(dir)
	return err == nil && info.IsDir()
}

// ListUsers returns sorted user CNs.
func ListUsers(usersDir string) []string {
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if !fsx.StoreKeyRe.MatchString(e.Name()) {
			continue
		}
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

// CreateUser creates the user directory (idempotent).
func CreateUser(usersDir, cn string) error {
	dir, err := UserDir(usersDir, cn)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	os.Chmod(dir, 0o755)
	return nil
}

// DeleteUser removes the user folder.
// DeleteUser removes the user folder and the per-CN lock files.
//
// The usage lock is per-CN too and lives in the usage directory rather than
// beside the user. Left behind, it accumulates one file per deleted user,
// so the caller passes that directory in.
func DeleteUser(usersDir, sessionsDir, usageDir, cn string) {
	dir, err := UserDir(usersDir, cn)
	if err != nil {
		return
	}
	os.RemoveAll(dir)
	if sessionsDir != "" {
		os.Remove(filepath.Join(sessionsDir, ".lock."+cn))
	}
	if usageDir != "" {
		os.Remove(filepath.Join(usageDir, ".lock."+cn))
	}
}

// ReadName reads the panel username.
func ReadName(usersDir, cn string) string {
	dir, err := UserDir(usersDir, cn)
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(dir, "name"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// WriteName writes the panel username.
func WriteName(usersDir, cn, name string) error {
	dir, err := UserDir(usersDir, cn)
	if err != nil {
		return err
	}
	os.MkdirAll(dir, 0o755)
	return fsx.WriteFileAtomic(filepath.Join(dir, "name"), []byte(name+"\n"), 0o600)
}

// OVPNPath returns client.ovpn path.
func OVPNPath(usersDir, cn string) (string, error) {
	dir, err := UserDir(usersDir, cn)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "client.ovpn"), nil
}

// EnsureLayout creates the ovnode tree and runs legacy migration.
func EnsureLayout(openvpnRoot string) {
	ovnodeDir := filepath.Join(openvpnRoot, "ovnode")
	for _, d := range []string{
		filepath.Join(ovnodeDir, "users"),
		filepath.Join(ovnodeDir, "sessions"),
		filepath.Join(ovnodeDir, "usage"),
		filepath.Join(ovnodeDir, "scripts"),
		filepath.Join(ovnodeDir, "state"),
	} {
		os.MkdirAll(d, 0o755)
	}
	MigrateLegacy(openvpnRoot)
}

// FixRuntimePermissions fixes permissions for runtime user.
func FixRuntimePermissions(openvpnRoot string) {
	EnsureLayout(openvpnRoot)
}

// MigrateLegacy moves pre-store state into the ovnode tree (files moved, never copied).
func MigrateLegacy(openvpnRoot string) {
	ovnodeDir := filepath.Join(openvpnRoot, "ovnode")
	usersDir := filepath.Join(ovnodeDir, "users")
	sessionsDir := filepath.Join(ovnodeDir, "sessions")
	legacyClients := filepath.Join(openvpnRoot, "clients")
	legacyLimits := filepath.Join(openvpnRoot, "limits")
	legacyDisabled := filepath.Join(openvpnRoot, "disabled")
	legacyActive := filepath.Join(openvpnRoot, "ovnode-active")
	legacyScripts := filepath.Join(openvpnRoot, "scripts")

	// uid_map.json {uid: username} -> users/<uid>/name
	uidMap := filepath.Join(legacyClients, "uid_map.json")
	if info, err := os.Stat(uidMap); err == nil && !info.IsDir() {
		data, _ := os.ReadFile(uidMap)
		// parse minimal JSON manually: {"uid":"name",...}
		// use encoding/json
		var m map[string]string
		if jsonUnmarshal(data, &m) == nil {
			for uid, name := range m {
				if !fsx.StoreKeyRe.MatchString(uid) {
					continue
				}
				namePath := filepath.Join(usersDir, uid, "name")
				if _, err := os.Stat(namePath); err != nil {
					os.MkdirAll(filepath.Join(usersDir, uid), 0o755)
					os.WriteFile(namePath, []byte(name+"\n"), 0o600)
				}
			}
		}
		os.Remove(uidMap)
	}

	// move .ovpn files
	moveDir(legacyClients, usersDir, ".ovpn", func(cn, usersDir string) string {
		return filepath.Join(usersDir, cn, "client.ovpn")
	})
	// move limits
	moveDir(legacyLimits, usersDir, "", func(cn, usersDir string) string {
		return filepath.Join(usersDir, cn, "limit")
	})
	// move disabled
	moveDir(legacyDisabled, usersDir, "", func(cn, usersDir string) string {
		return filepath.Join(usersDir, cn, "disabled")
	})

	// session markers verbatim
	if info, err := os.Stat(legacyActive); err == nil && info.IsDir() {
		entries, _ := os.ReadDir(legacyActive)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			src := filepath.Join(legacyActive, e.Name())
			dst := filepath.Join(sessionsDir, e.Name())
			if _, err := os.Stat(dst); err != nil {
				os.Rename(src, dst)
			}
		}
		os.Remove(legacyActive)
	}

	// remove old hook copies
	for _, fname := range []string{"ovnode-client-connect.sh", "ovnode-client-disconnect.sh", "ovnode-mlogin.env"} {
		os.Remove(filepath.Join(legacyScripts, fname))
	}
	os.Remove(legacyScripts)
}

func moveFile(src, dst string) {
	if err := os.Rename(src, dst); err != nil {
		data, rerr := os.ReadFile(src)
		if rerr != nil {
			return
		}
		if werr := os.WriteFile(dst, data, 0o644); werr == nil {
			os.Remove(src)
		}
	}
}

func moveDir(srcDir, usersDir, suffix string, dstFor func(string, string) string) {
	info, err := os.Stat(srcDir)
	if err != nil || !info.IsDir() {
		return
	}
	entries, _ := os.ReadDir(srcDir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		cn := name
		if suffix != "" {
			if !strings.HasSuffix(name, suffix) {
				continue
			}
			cn = name[:len(name)-len(suffix)]
		}
		if !fsx.StoreKeyRe.MatchString(cn) {
			continue
		}
		src := filepath.Join(srcDir, name)
		fi, err := os.Stat(src)
		if err != nil || fi.IsDir() {
			continue
		}
		dst := dstFor(cn, usersDir)
		if _, err := os.Stat(dst); err != nil {
			moveFile(src, dst)
		} else {
			os.Remove(src)
		}
	}
	os.Remove(srcDir)
}

// jsonUnmarshal delegates to encoding/json.
func jsonUnmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
