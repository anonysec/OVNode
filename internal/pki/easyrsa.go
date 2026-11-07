// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package pki

import (
	"context"
	"fmt"
	"os"

	"os/exec"
	"ovnode/internal/fsx"
	"path/filepath"
	"syscall"
	"time"
)

// DebugEnabled gates the easyrsa debug output.
var DebugEnabled bool

func RunEasyRSA(args ...string) bool {
	return RunEasyRSAChecked(args...) == nil
}

func RunEasyRSAChecked(args ...string) error {
	return runEasyRSAWithTimeout(120, "", args...)
}

// RunEasyRSAWithTimeout runs easyrsa with a timeout and optional pki dir.
func RunEasyRSAWithTimeout(timeout int, pkiDir string, args ...string) bool {
	return runEasyRSAWithTimeout(timeout, pkiDir, args...) == nil
}

func runEasyRSAWithTimeout(timeout int, pkiDir string, args ...string) error {
	if pkiDir == "" {
		pkiDir = PKIDir()
	}
	bin := filepath.Join(EasyRSADir(), "easyrsa")
	if _, err := os.Stat(bin); err != nil {
		return err
	}
	lockPath := filepath.Join(pkiDir, ".easyrsa.lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	cmdArgs := []string{"--pki-dir=" + pkiDir}
	cmdArgs = append(cmdArgs, args...)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, cmdArgs...)
	cmd.Dir = EasyRSADir()
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"EASYRSA_BATCH=1",
		"HOME=" + homeDir(),
	}
	if DebugEnabled || fsx.Env("DEBUG", "") != "" {
		fmt.Fprintf(os.Stderr, "DEBUG easyrsa: dir=%s args=%v\n", cmd.Dir, cmd.Args)
	}
	// ensure PATH default
	if os.Getenv("PATH") == "" {
		cmd.Env[0] = "PATH=/usr/sbin:/usr/bin:/sbin:/bin"
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("easyrsa %v: %w", args, ctx.Err())
		}
		return fmt.Errorf("easyrsa %v: %w", args, err)
	}
	return nil
}

func EnsureDirTree() error {
	if err := os.MkdirAll(PKIDir(), 0o755); err != nil {
		return err
	}
	subdirs := []string{
		"private",
		"issued",
		"reqs",
		"certs_by_serial",
		"index.txt.attrs",
		"inline/private",
		"revoked/certs_by_serial",
		"revoked/private",
		"revoked/reqs",
		"revoked/issued",
	}
	for _, sd := range subdirs {
		perm := os.FileMode(0o755)
		if sd == "private" || sd == "inline/private" || sd == "revoked/private" {
			perm = 0o700
		}
		if err := os.MkdirAll(filepath.Join(PKIDir(), sd), perm); err != nil {
			return err
		}
	}
	for _, fname := range []string{"index.txt", "index.txt.attr", "serial", "serial.old", "crlnumber", "crlnumber.old"} {
		path := filepath.Join(PKIDir(), fname)
		if info, err := os.Lstat(path); err == nil {
			if !info.Mode().IsRegular() {
				return fmt.Errorf("non-regular PKI file at %s", path)
			}
			continue
		} else if !os.IsNotExist(err) {
			return err
		}
		if fname == "index.txt" {
			if _, err := os.Lstat(CACert()); err == nil {
				return fmt.Errorf("certificate index is missing for an existing CA")
			} else if !os.IsNotExist(err) {
				return err
			}
		}
		f, err := fsx.OpenFileNoFollow(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		if fname == "serial" || fname == "crlnumber" {
			if _, err := f.WriteString("1000\n"); err != nil {
				f.Close()
				return err
			}
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	return nil
}

// EnsureSecretPerms repairs permissions on secret material.
func EnsureSecretPerms() {
	_ = fsx.SetPermissions(filepath.Join(PKIDir(), "private"), 0o700, -1, -1)
	_ = filepath.Walk(PKIDir(), func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if info.Name() == "ca.key" || filepath.Ext(path) == ".key" {
			_ = fsx.SetPermissions(path, 0o600, -1, -1)
		}
		if info.Name() == "tls.key" {
			_ = fsx.SetPermissions(path, 0o600, -1, -1)
		}
		return nil
	})
	_ = fsx.SetPermissions(TLSKey(), 0o600, -1, -1)
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return "/root"
}

// GenTLSKey generates OpenVPN tls-crypt key at /etc/openvpn/server/tls.key (idempotent).
func GenTLSKey() error {
	path := TLSKey()
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Size() == 0 {
			return fmt.Errorf("invalid TLS key at %s", path)
		}
		_, err := os.ReadFile(path)
		return err
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	cmd := exec.Command("openvpn", "--genkey", "secret", path)
	if err := cmd.Run(); err != nil {
		// Fallback for older openvpn versions with --secret flag
		cmd2 := exec.Command("openvpn", "--genkey", "--secret", path)
		if err2 := cmd2.Run(); err2 != nil {
			return err2
		}
	}
	return os.Chmod(path, 0o600)
}
