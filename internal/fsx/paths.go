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
	if d := os.Getenv("AppDir"); d != "" {
		paths = append(paths, filepath.Join(d, ".env"))
	}
	instance := "ovnode"
	if v := os.Getenv("Instance"); v != "" {
		instance = v
	}
	// Exactly this instance's file. A glob here would let one instance adopt a
	// neighbour's API key and paths when its own file is missing.
	paths = append(paths, "/opt/"+instance+"/.env")
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

// Get reads a configuration key. Names are explicit PascalCase; there is no
// implicit prefix, because a prefix applied on one side and not the other is
// exactly how a prefixed and an unprefixed key drifted apart.
func Get(name, defaultVal string) string { return envOr(name, defaultVal) }

const DefaultOpenVPNRoot = "/var/lib/ovnode/openvpn"

// InstanceName returns the ovnode instance name, defaulting to "ovnode".
func InstanceName() string {
	return envOr("Instance", "ovnode")
}

func OpenVPNRoot() string {
	if v := envOr("OpenVpnRoot", ""); v != "" {
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
	return envOr("MgmtPassFile", joinRoot("server", "mgmt-pass"))
}

func StatusFile() string { return envOr("StatusFile", joinRoot("server", "status.log")) }
func LogDir() string     { return envOr("LogDir", "/var/log/"+InstanceName()) }
func LogFile() string    { return envOr("LogFile", filepath.Join(LogDir(), "hook-events.log")) }

func OVNodeDir() string {
	// Data lives in /var/lib/ovnode by default (consistent with OVManager),
	// overridable via DataDir / DataDir. The OpenVPN root
	// (/etc/openvpn) only holds server.conf + PKI.
	if v := envOr("DataDir", ""); v != "" {
		return v
	}
	if v := envOr("DataDir", ""); v != "" {
		return v
	}
	return "/var/lib/" + InstanceName()
}

func UsersDir() string {
	return envOr("UsersDir", filepath.Join(OVNodeDir(), "users"))
}
func SessionsDir() string {
	return envOr("SessionsDir", filepath.Join(OVNodeDir(), "sessions"))
}
func UsageDir() string {
	return envOr("UsageDir", filepath.Join(OVNodeDir(), "usage"))
}

// AgentBin is the single on-disk location of the node agent binary. It sits
// in OVNodeDir() (not a nested scripts/ dir) so the path does not repeat
// the "ovnode" name.
func AgentBin() string {
	// The binary lives in the app dir (/opt/ovnode/agent by default), not the
	// data dir. Prefer the running executable so multi-instance and renamed
	// installs point at the binary that generated the config; fall back to the
	// env/default app path.
	if appDir := envOr("AppDir", ""); appDir != "" {
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
