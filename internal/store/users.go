// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package store

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

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
	if err := fsx.MkdirAllNoFollow(dir, 0o750); err != nil {
		return err
	}
	return fsx.SetPermissions(dir, 0o750|os.ModeSetgid, uid, gid)
}

// DeleteUser removes the user folder.
// DeleteUser removes the user folder and the per-CN lock files.
//
// The usage lock is per-CN too and lives in the usage directory rather than
// beside the user. Left behind, it accumulates one file per deleted user,
// so the caller passes that directory in.
func DeleteUser(usersDir, sessionsDir, usageDir, cn string) error {
	dir, err := UserDir(usersDir, cn)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if sessionsDir != "" {
		if err := os.Remove(filepath.Join(sessionsDir, ".lock."+cn)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if usageDir != "" {
		if err := os.Remove(filepath.Join(usageDir, ".lock."+cn)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	InvalidateNameCache()
	return nil
}

// ReadName reads the panel username.
func ReadName(usersDir, cn string) string {
	st, err := ReadUserState(usersDir, cn)
	if err != nil {
		return ""
	}
	if st.NameSet {
		return strings.TrimSpace(st.Name)
	}
	dir, err := UserDir(usersDir, cn)
	if err != nil {
		return ""
	}
	data, err := readPolicyFile(filepath.Join(dir, "name"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// WriteName writes the panel username.
func WriteName(usersDir, cn, name string) error {
	return WriteUserPolicy(usersDir, cn, &name, nil, nil)
}

func validateName(name string) error {
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("name contains control characters")
		}
	}
	return nil
}

// OVPNPath returns client.ovpn path.
func OVPNPath(usersDir, cn string) (string, error) {
	dir, err := UserDir(usersDir, cn)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "client.ovpn"), nil
}

// EnsureLayout creates the ovnode tree and runs legacy migration once at
// startup. Permission repair is separate: FixRuntimePermissions does not
// migrate, so a restart does not replay legacy moves.
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

// rule is one permission row. match returns the file mode, the owner gid,
// and whether the row applies; an empty match means the row does not apply.
type rule struct {
	path      string
	dir       os.FileMode
	file      os.FileMode
	gid       int
	recursive bool
	match     func(path string, info os.FileInfo) (os.FileMode, int, bool)
}

// permRules returns the repair table in walk order. The runtime gid is
// resolved by the caller.
func permRules(openvpnRoot string, gid int) []rule {
	legacy := filepath.Join(openvpnRoot, "ovnode")
	pkiDir := filepath.Join(openvpnRoot, "server", "pki")
	var rules []rule
	for _, dir := range []string{
		openvpnRoot, filepath.Join(openvpnRoot, "server"), pkiDir, filepath.Join(openvpnRoot, "ccd"), legacy, fsx.OVNodeDir(),
	} {
		rules = append(rules, rule{path: dir, dir: 0o750 | os.ModeSetgid, file: 0o750 | os.ModeSetgid, gid: gid})
	}
	for _, name := range []string{"users", "sessions", "usage", "scripts", "state"} {
		rules = append(rules, rule{path: filepath.Join(legacy, name), dir: 0o750 | os.ModeSetgid, file: 0o750 | os.ModeSetgid, gid: gid})
	}
	for _, name := range []string{"clients", "limits", "disabled", "ovnode-active", "scripts"} {
		source := filepath.Join(openvpnRoot, name)
		if _, err := os.Lstat(source); os.IsNotExist(err) {
			continue
		}
		n := name
		rules = append(rules, rule{
			path:      source,
			dir:       0o750 | os.ModeSetgid,
			file:      0o600,
			gid:       gid,
			recursive: true,
			match: func(path string, info fs.FileInfo) (os.FileMode, int, bool) {
				if info.IsDir() {
					return 0o750 | os.ModeSetgid, gid, true
				}
				switch n {
				case "limits", "disabled":
					return 0o640, gid, true
				case "clients":
					return 0o600, gid, true
				}
				if filepath.Ext(path) == ".ovpn" || filepath.Ext(path) == ".key" {
					return 0o600, gid, true
				}
				return 0, 0, false
			},
		})
	}
	rules = append(rules, rule{
		path:      filepath.Join(legacy, "users"),
		dir:       0o750 | os.ModeSetgid,
		file:      0o600,
		gid:       gid,
		recursive: true,
		match: func(path string, info fs.FileInfo) (os.FileMode, int, bool) {
			if info.IsDir() {
				return 0o750 | os.ModeSetgid, gid, true
			}
			switch info.Name() {
			case "state", "limit", "disabled", "name":
				return 0o640, gid, true
			case "cert.pem", "ca.pem":
				return 0o644, gid, true
			}
			return 0o600, gid, true
		},
	})
	ub := fsx.UsersDir()
	rules = append(rules, rule{
		path:      ub,
		dir:       0o750 | os.ModeSetgid,
		file:      0o600,
		gid:       gid,
		recursive: true,
		match: func(path string, info fs.FileInfo) (os.FileMode, int, bool) {
			if info.IsDir() {
				return 0o750 | os.ModeSetgid, gid, true
			}
			switch info.Name() {
			case "state", "limit", "disabled", "name":
				return 0o640, gid, true
			case "cert.pem", "ca.pem":
				return 0o644, gid, true
			}
			return 0o600, gid, true
		},
	})
	return rules
}

// applyRules walks the table. The .tmp- skip is once here, not per rule.
// PKI symlinks are refused. uid is always 0; gid comes from the row.
func applyRules(rules []rule) error {
	for _, r := range rules {
		if err := applyRule(r); err != nil {
			return err
		}
	}
	return nil
}

func applyRule(r rule) error {
	if err := repairRuntimeDir(r.path, r.dir, r.gid); err != nil {
		return err
	}
	if !r.recursive {
		return nil
	}
	return filepath.Walk(r.path, func(path string, info os.FileInfo, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if strings.HasPrefix(info.Name(), ".tmp-") {
			if info.Mode().IsRegular() {
				return nil
			}
		}
		if info.Mode()&os.ModeSymlink != 0 && strings.HasPrefix(info.Name(), ".tmp-") {
			return fmt.Errorf("unexpected runtime symlink %s", path)
		}
		perm := r.file
		gid := r.gid
		if r.match != nil {
			if p, g, ok := r.match(path, info); ok {
				perm, gid = p, g
			} else if !info.IsDir() && r.file == 0 {
				return nil
			}
		}
		if info.IsDir() {
			perm = r.dir
		}
		if err := setIfDiffers(path, perm, 0, gid); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	})
}

// setIfDiffers calls SetPermissions only when the mode or owner differs,
// so a no-op run on a healthy tree does no chmod/chown.
func setIfDiffers(path string, perm os.FileMode, uid, gid int) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if ok {
		cur := info.Mode() & (os.ModePerm | os.ModeSetgid | os.ModeSetuid | os.ModeSticky)
		if cur == perm && uid >= 0 && int(stat.Uid) == uid && gid >= 0 && int(stat.Gid) == gid {
			return nil
		}
		if uid < 0 && gid >= 0 {
			if cur == perm && int(stat.Gid) == gid {
				return nil
			}
		}
		if uid >= 0 && gid < 0 {
			if cur == perm && int(stat.Uid) == uid {
				return nil
			}
		}
	}
	return fsx.SetPermissions(path, perm, uid, gid)
}

func FixRuntimePermissions(openvpnRoot string) error {
	pkiDir := filepath.Join(openvpnRoot, "server", "pki")
	_, pkiErr := os.Lstat(pkiDir)
	_, confErr := os.Lstat(filepath.Join(openvpnRoot, "server", "server.conf"))
	if os.IsNotExist(pkiErr) && os.IsNotExist(confErr) {
		return nil
	}
	if pkiErr != nil && !os.IsNotExist(pkiErr) {
		return pkiErr
	}
	if confErr != nil && !os.IsNotExist(confErr) {
		return confErr
	}
	gid, err := fsx.RuntimeGroupID()
	if err != nil {
		return err
	}
	if err := applyRules(permRules(openvpnRoot, gid)); err != nil {
		return err
	}
	return fixRuntimeSpecial(openvpnRoot, pkiDir, gid)
}

// fixRuntimeSpecial covers the paths that are not part of the walker table:
// sessions/usage flat files, the log file and rotated logs, the PKI walk,
// and tls.key + mgmt password.
func fixRuntimeSpecial(openvpnRoot, pkiDir string, gid int) error {
	legacy := filepath.Join(openvpnRoot, "ovnode")
	_ = legacy
	for _, dir := range []string{fsx.SessionsDir(), fsx.UsageDir()} {
		if err := repairRuntimeDir(dir, 0o770|os.ModeSetgid, gid); err != nil {
			return err
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".tmp-") {
				if entry.Type().IsRegular() {
					continue
				}
				return fmt.Errorf("unexpected runtime symlink %s", filepath.Join(dir, entry.Name()))
			}
			if entry.IsDir() {
				return fmt.Errorf("unexpected runtime directory %s", filepath.Join(dir, entry.Name()))
			}
			path := filepath.Join(dir, entry.Name())
			if err := setIfDiffers(path, 0o660, 0, gid); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	if filepath.Clean(fsx.LogDir()) == "/var/log/"+fsx.InstanceName() {
		if err := repairRuntimeDir(fsx.LogDir(), 0o770|os.ModeSetgid, gid); err != nil {
			return err
		}
	}
	if err := fsx.MkdirAllNoFollow(filepath.Dir(fsx.LogFile()), 0o755); err != nil {
		return err
	}
	log, err := fsx.OpenFileNoFollow(fsx.LogFile(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o660)
	if err != nil {
		return err
	}
	if err := log.Close(); err != nil {
		return err
	}
	if err := setIfDiffers(fsx.LogFile(), 0o660, 0, gid); err != nil {
		return err
	}
	for i := 1; i <= 7; i++ {
		for _, suffix := range []string{"", ".gz"} {
			path := fmt.Sprintf("%s.%d%s", fsx.LogFile(), i, suffix)
			if err := setIfDiffers(path, 0o640, 0, gid); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	if err := fixPKIPerms(pkiDir, gid); err != nil {
		return err
	}
	for _, path := range []string{filepath.Join(openvpnRoot, "server", "tls.key"), fsx.MgmtPassFile()} {
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		perm, group := os.FileMode(0o600), 0
		if path == fsx.MgmtPassFile() {
			perm, group = 0o640, gid
		}
		if err := setIfDiffers(path, perm, 0, group); err != nil {
			return err
		}
	}
	return nil
}

func fixPKIPerms(pkiDir string, gid int) error {
	return filepath.Walk(pkiDir, func(path string, info os.FileInfo, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if strings.HasPrefix(info.Name(), ".tmp-") && info.Mode().IsRegular() {
			return nil
		}
		private := strings.Contains(path+"/", "/private/")
		perm, group := os.FileMode(0o644), gid
		if info.IsDir() {
			perm = 0o750 | os.ModeSetgid
			if private {
				perm = 0o700
			}
		} else if private || filepath.Ext(path) == ".key" {
			perm, group = 0o600, 0
		} else if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("unexpected PKI symlink %s", path)
		} else if info.Name() != "crl.pem" && info.Name() != "ca.crt" {
			return nil
		}
		if err := setIfDiffers(path, perm, 0, group); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	})
}

func repairRuntimeDir(path string, perm os.FileMode, gid int) error {
	if err := fsx.MkdirAllNoFollow(path, 0o750); err != nil {
		return err
	}
	return fsx.SetPermissions(path, perm, 0, gid)
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
		if json.Unmarshal(data, &m) == nil {
			for uid, name := range m {
				if !fsx.StoreKeyRe.MatchString(uid) {
					continue
				}
				namePath := filepath.Join(usersDir, uid, "name")
				if _, err := os.Stat(namePath); err != nil {
					os.MkdirAll(filepath.Join(usersDir, uid), 0o755)
					fsx.WriteFileAtomic(namePath, []byte(name+"\n"), 0o600)
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
		if werr := fsx.WriteFileAtomic(dst, data, 0o644); werr == nil {
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
