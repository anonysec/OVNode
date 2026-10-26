// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

// Package fsx is the one place that knows where things live on disk.
package fsx

import (
	"os"
	"os/exec"
	"path/filepath"
)

func envOr(name, fallback string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return fallback
}

// EnvOr reads an environment variable by its full name.
func EnvOr(name, fallback string) string { return envOr(name, fallback) }

// Env reads an OVNODE_* environment variable (name is uppercased and prefixed).
func Env(name, defaultVal string) string {
	return envOr("OVNODE_"+toUpper(name), defaultVal)
}

func toUpper(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		out[i] = c
	}
	return string(out)
}

const DefaultOpenVPNRoot = "/etc/openvpn"

func OpenVPNRoot() string { return envOr("OVNODE_OPENVPN_ROOT", DefaultOpenVPNRoot) }

func IsInstalledTree() bool {
	return filepath.Clean(OpenVPNRoot()) == DefaultOpenVPNRoot
}

func joinRoot(parts ...string) string {
	all := append([]string{OpenVPNRoot()}, parts...)
	return filepath.Join(all...)
}

func EasyRSADir() string { return joinRoot("server", "easy-rsa") }
func PKIDir() string     { return joinRoot("server", "pki") }
func ServerConf() string { return joinRoot("server", "server.conf") }
func ClientTemplate() string {
	return joinRoot("server", "client-common.txt")
}
func TLSKey() string { return joinRoot("server", "tls.key") }
func CACert() string { return filepath.Join(PKIDir(), "ca.crt") }
func ServerCert() string {
	return filepath.Join(PKIDir(), "issued", "server.crt")
}
func ServerKey() string { return filepath.Join(PKIDir(), "private", "server.key") }
func DHPem() string     { return filepath.Join(PKIDir(), "dh.pem") }
func CRLFile() string   { return filepath.Join(PKIDir(), "crl.pem") }
func PIDFile() string   { return joinRoot("server", "ovnode.pid") }
func MgmtPassFile() string {
	return joinRoot("server", "mgmt-pass")
}

func OVNodeDir() string { return joinRoot("ovnode") }

func UsersDir() string {
	return envOr("OVNODE_USERS_DIR", filepath.Join(OVNodeDir(), "users"))
}
func SessionsDir() string {
	return envOr("OVNODE_SESSIONS_DIR", filepath.Join(OVNodeDir(), "sessions"))
}
func UsageDir() string {
	return envOr("OVNODE_USAGE_DIR", filepath.Join(OVNodeDir(), "usage"))
}
func ScriptsDir() string {
	return filepath.Join(OVNodeDir(), "scripts")
}

func RequiredDirs() []string {
	return []string{
		joinRoot("server"),
		joinRoot("ccd"),
	}
}

func OpenVPNBin() string {
	if p, err := exec.LookPath("openvpn"); err == nil {
		return p
	}
	for _, c := range []string{"/usr/sbin/openvpn", "/usr/local/sbin/openvpn", "/sbin/openvpn"} {
		if _, err := exec.LookPath(c); err == nil {
			return c
		}
	}
	return "openvpn"
}
