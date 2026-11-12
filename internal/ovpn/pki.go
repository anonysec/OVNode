// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"ovnode/internal/fsx"
	"ovnode/internal/pki"
)

// serverSANOption builds the self-signed server certificate's SAN list. The
// node's API certificate is pinned by the panel, so the SANs are for operators
// and tools that still check the hostname: TlsDomain is a comma-separated list
// of domains and IPs (for example the server's public address).
func serverSANOption() string {
	sans := []string{"DNS:server", "DNS:localhost"}
	seen := map[string]bool{"DNS:server": true, "DNS:localhost": true}
	for _, part := range strings.Split(fsx.Get("TlsDomain", ""), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		entry := ""
		if ip := net.ParseIP(part); ip != nil {
			entry = "IP:" + ip.String()
		} else if validDNSName(part) {
			entry = "DNS:" + strings.ToLower(part)
		}
		if entry == "" || seen[entry] {
			continue
		}
		seen[entry] = true
		sans = append(sans, entry)
	}
	return "--subject-alt-name=" + strings.Join(sans, ",")
}

func validDNSName(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
		default:
			return false
		}
	}
	return !strings.HasPrefix(value, "-") && !strings.HasSuffix(value, "-")
}

func InitPKI() error {
	for _, d := range append(pki.RequiredDirs(), pki.OVNodeDir()) {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	if err := pki.SetupEasyRSA(); err != nil {
		return err
	}
	if err := pki.EnsureDirTree(); err != nil {
		return err
	}
	if err := pki.WithPKILock(func() error {
		caCert, err := materialExists(pki.CACert())
		if err != nil {
			return err
		}
		caKey, err := materialExists(filepath.Join(pki.PKIDir(), "private", "ca.key"))
		if err != nil {
			return err
		}
		if caCert != caKey {
			return fmt.Errorf("incomplete CA identity: restore the missing certificate or key")
		}
		if !caCert {
			for _, subdir := range []string{"private", "issued", "reqs", "certs_by_serial"} {
				entries, err := os.ReadDir(filepath.Join(pki.PKIDir(), subdir))
				if err != nil {
					return err
				}
				if len(entries) != 0 {
					return fmt.Errorf("missing CA identity with existing %s material", subdir)
				}
			}
			index, err := os.ReadFile(filepath.Join(pki.PKIDir(), "index.txt"))
			if err != nil {
				return err
			}
			if strings.TrimSpace(string(index)) != "" {
				return fmt.Errorf("missing CA identity with an existing certificate index")
			}
			if err := pki.RunEasyRSAChecked("build-ca", "nopass"); err != nil {
				return err
			}
		}
		serverCert, err := materialExists(pki.ServerCert())
		if err != nil {
			return err
		}
		serverKey, err := materialExists(pki.ServerKey())
		if err != nil {
			return err
		}
		if serverCert != serverKey {
			return fmt.Errorf("incomplete server identity: restore the missing certificate or key")
		}
		if !serverCert {
			if err := pki.RunEasyRSAChecked(serverSANOption(), "build-server-full", "server", "nopass"); err != nil {
				return err
			}
		}
		ca, err := os.ReadFile(pki.CACert())
		if err != nil {
			return err
		}
		cert, err := os.ReadFile(pki.ServerCert())
		if err != nil {
			return err
		}
		key, err := os.ReadFile(pki.ServerKey())
		if err != nil {
			return err
		}
		if err := pki.ValidateServerCert(string(ca), string(cert), string(key)); err != nil {
			return fmt.Errorf("invalid existing PKI identity: %w", err)
		}
		if err := pki.EnsureCRLChecked(); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	if err := pki.GenTLSKey(); err != nil {
		return err
	}
	for _, proto := range currentSettings().Protos() {
		if _, err := ensureServerConf(proto); err != nil {
			return err
		}
	}
	if err := EnsureClientTemplate(); err != nil {
		return err
	}
	pki.EnsureSecretPerms()
	return nil
}

func materialExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("non-regular PKI material at %s", path)
	}
	return true, nil
}
