// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package pki

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// DebugEnabled gates the easyrsa debug output.
var DebugEnabled bool

func RunEasyRSA(args ...string) bool {
	return RunEasyRSAWithTimeout(120, "", args...)
}

// RunEasyRSAWithTimeout runs easyrsa with a timeout and optional pki dir.
func RunEasyRSAWithTimeout(timeout int, pkiDir string, args ...string) bool {
	if pkiDir == "" {
		pkiDir = PKIDir()
	}
	bin := filepath.Join(EasyRSADir(), "easyrsa")
	if _, err := os.Stat(bin); err != nil {
		return false
	}
	lockPath := filepath.Join(pkiDir, ".easyrsa.lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return false
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return false
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	cmdArgs := []string{"--pki-dir=" + pkiDir}
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command(bin, cmdArgs...)
	cmd.Dir = EasyRSADir()
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"EASYRSA_BATCH=1",
		"HOME=" + homeDir(),
	}
	if DebugEnabled || os.Getenv("OVNODE_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "DEBUG easyrsa: dir=%s args=%v\n", cmd.Dir, cmd.Args)
	}
	// ensure PATH default
	if os.Getenv("PATH") == "" {
		cmd.Env[0] = "PATH=/usr/sbin:/usr/bin:/sbin:/bin"
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case err := <-done:
		if err != nil {
			if DebugEnabled || os.Getenv("OVNODE_DEBUG") != "" {
				fmt.Fprintf(os.Stderr, "DEBUG easyrsa run error: %v\n", err)
			}
			return false
		}
		return true
	case <-time.After(time.Duration(timeout) * time.Second):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return false
	}
}

func EnsureDirTree() {
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
		os.MkdirAll(filepath.Join(PKIDir(), sd), 0o755)
	}
	for _, fname := range []string{"index.txt", "index.txt.attr", "serial", "serial.old", "crlnumber", "crlnumber.old"} {
		path := filepath.Join(PKIDir(), fname)
		if _, err := os.Stat(path); err != nil {
			f, _ := os.Create(path)
			if f != nil {
				if fname == "serial" || fname == "crlnumber" {
					f.WriteString("1000\n")
				}
				f.Close()
			}
		}
	}
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
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	os.MkdirAll(filepath.Dir(path), 0o755)
	cmd := exec.Command("openvpn", "--genkey", "secret", path)
	if err := cmd.Run(); err != nil {
		// Fallback for older openvpn versions with --secret flag
		cmd2 := exec.Command("openvpn", "--genkey", "--secret", path)
		if err2 := cmd2.Run(); err2 != nil {
			return err2
		}
	}
	return os.Chmod(path, 0o644)
}
