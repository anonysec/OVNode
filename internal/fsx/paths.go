// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

// Package fsx is the one place that knows where things live on disk.
package fsx

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// envFileValues reads uncommented KEY=VALUE pairs from the first .env file
// found, so a user can force an option by editing the file (PasarGuard-style:
// .env wins over the process environment).
var (
	envFileOnce   sync.Once
	envFileCache  map[string]string
	envFileSource string
)

func loadEnvFile() {
	out := map[string]string{}
	paths := []string{}
	if d := os.Getenv("OVN_APP_DIR"); d != "" {
		paths = append(paths, filepath.Join(d, ".env"))
	}
	paths = append(paths, "/opt/ovnode/.env", "/etc/openvpn/ovnode/.env", "/var/lib/ovnode/openvpn/.env")
	// Instance-aware: search for any instance's .env (PasarGuard-style).
	if matches, err := filepath.Glob("/opt/*/.env"); err == nil {
		paths = append(paths, matches...)
	}
	if matches, err := filepath.Glob("/var/lib/*/openvpn/.env"); err == nil {
		paths = append(paths, matches...)
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
				continue
			}
			k, v, _ := strings.Cut(line, "=")
			k = strings.TrimSpace(k)
			v = strings.Trim(strings.TrimSpace(v), `"'`)
			if k != "" {
				out[k] = v
			}
		}
		envFileSource = p
		break // first readable .env wins
	}
	envFileCache = out
}

func envFileValues() map[string]string {
	envFileOnce.Do(loadEnvFile)
	return envFileCache
}

// EnvFileSource reports the .env path that was loaded (if any).
func EnvFileSource() string {
	envFileOnce.Do(loadEnvFile)
	return envFileSource
}

func envOr(name, fallback string) string {
	// .env wins over the process environment (documented behavior).
	if v := envFileValues()[name]; v != "" {
		return v
	}
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

const DefaultOpenVPNRoot = "/var/lib/ovnode/openvpn"

// InstanceName returns the ovnode instance name, defaulting to "ovnode".
func InstanceName() string {
	return envOr("OVNODE_INSTANCE", "ovnode")
}

func OpenVPNRoot() string {
	if v := envOr("OVNODE_OPENVPN_ROOT", ""); v != "" {
		return v
	}
	return "/var/lib/" + InstanceName() + "/openvpn"
}

func IsInstalledTree() bool {
	_, err := os.Stat(filepath.Join(OpenVPNRoot(), "server", "server.conf"))
	return err == nil
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
func CRLFile() string   { return filepath.Join(PKIDir(), "crl.pem") }
func PIDFile() string   { return joinRoot("server", "ovnode.pid") }
func MgmtPassFile() string {
	return envOr("OVNODE_MGMT_PASS_FILE", joinRoot("server", "mgmt-pass"))
}

func StatusFile() string { return envOr("OVNODE_STATUS_FILE", joinRoot("server", "status.log")) }
func LogDir() string     { return envOr("OVNODE_LOG_DIR", "/var/log/"+InstanceName()) }
func LogFile() string    { return envOr("OVNODE_LOG_FILE", filepath.Join(LogDir(), "hook-events.log")) }

func OVNodeDir() string {
	// Data lives in /var/lib/ovnode by default (consistent with OVManager),
	// overridable via OVNODE_DATA_DIR / DATA_DIR. The OpenVPN root
	// (/etc/openvpn) only holds server.conf + PKI.
	if v := envOr("OVNODE_DATA_DIR", ""); v != "" {
		return v
	}
	if v := envOr("DATA_DIR", ""); v != "" {
		return v
	}
	return "/var/lib/" + InstanceName()
}

func UsersDir() string {
	return envOr("OVNODE_USERS_DIR", filepath.Join(OVNodeDir(), "users"))
}
func SessionsDir() string {
	return envOr("OVNODE_SESSIONS_DIR", filepath.Join(OVNodeDir(), "sessions"))
}
func UsageDir() string {
	return envOr("OVNODE_USAGE_DIR", filepath.Join(OVNodeDir(), "usage"))
}

// AgentBin is the single on-disk location of the node agent binary. It sits
// in OVNodeDir() (not a nested scripts/ dir) so the path does not repeat
// the "ovnode" name.
func AgentBin() string {
	// The binary lives in the app dir (/opt/ovnode/agent by default), not the
	// data dir. Prefer the running executable so multi-instance and renamed
	// installs point at the binary that generated the config; fall back to the
	// env/default app path.
	if appDir := envOr("OVN_APP_DIR", ""); appDir != "" {
		return filepath.Join(appDir, "ovnode-server")
	}
	if exe, err := os.Executable(); err == nil && exe != "" {
		base := filepath.Base(exe)
		if base == "ovnode-server" || base == "agent" || base == "ovnode" {
			if resolved, err := filepath.EvalSymlinks(exe); err == nil && resolved != "" {
				return resolved
			}
			return exe
		}
	}
	return "/opt/" + InstanceName() + "/ovnode-server"
}

func RequiredDirs() []string {
	return []string{
		joinRoot("server"),
		joinRoot("ccd"),
	}
}
