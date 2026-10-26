// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"fmt"
	"os"
	"path/filepath"

	"ovnode/internal/pki"
)

// DebugEnabled gates the (potentially noisy) PKI debug output.
var DebugEnabled bool

// InitPKI is the idempotent entrypoint.
func InitPKI() error {
	// Create required directories first
	for _, d := range pki.RequiredDirs() {
		os.MkdirAll(d, 0o755)
	}
	// Ensure scripts dir exists
	os.MkdirAll(pki.ScriptsDir(), 0o755)

	// Setup easy-rsa
	pki.SetupEasyRSA()

	// Check if CA already exists (both cert and private key)
	caPath := pki.CACert()
	caKeyPath := filepath.Join(pki.PKIDir(), "private", "ca.key")
	if DebugEnabled || os.Getenv("OVNODE_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "DEBUG: checking CA at %s\n", caPath)
	}
	caCertExists := false
	caKeyExists := false
	if _, err := os.Stat(caPath); err == nil {
		caCertExists = true
		if DebugEnabled || os.Getenv("OVNODE_DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "DEBUG: CA cert exists at %s\n", caPath)
		}
	}
	if _, err := os.Stat(caKeyPath); err == nil {
		caKeyExists = true
		if DebugEnabled || os.Getenv("OVNODE_DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "DEBUG: CA key exists at %s\n", caKeyPath)
		}
	}
	if caCertExists && caKeyExists {
		if _, err := os.Stat(pki.ServerCert()); err == nil {
			// PKI fully exists
			pki.GenTLSKey()
			if !pki.EnsureCRL() {
				return fmt.Errorf("Certificate revocation list is unavailable")
			}
			EnsureServerConf()
			EnsureClientTemplate()
			return nil
		}
		if DebugEnabled || os.Getenv("OVNODE_DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "DEBUG: CA exists but server cert missing, building server cert\n")
		}
	} else {
		if !caCertExists {
			if DebugEnabled || os.Getenv("OVNODE_DEBUG") != "" {
				fmt.Fprintf(os.Stderr, "DEBUG: CA cert NOT found at %s\n", caPath)
			}
		}
		if !caKeyExists {
			if DebugEnabled || os.Getenv("OVNODE_DEBUG") != "" {
				fmt.Fprintf(os.Stderr, "DEBUG: CA key NOT found at %s\n", caKeyPath)
			}
		}
	}

	// Create required directories for easy-rsa (including private dir for CA keys)
	os.MkdirAll(pki.PKIDir(), 0o755)
	os.MkdirAll(filepath.Join(pki.PKIDir(), "private"), 0o755)
	// Debug: check if private dir exists
	privateDir := filepath.Join(pki.PKIDir(), "private")
	if _, err := os.Stat(privateDir); err != nil {
		if DebugEnabled || os.Getenv("OVNODE_DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "DEBUG: private dir missing: %v\n", err)
		}
	} else {
		if DebugEnabled || os.Getenv("OVNODE_DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "DEBUG: private dir exists\n")
		}
	}
	// Debug: list PKI dir contents
	if entries, err := os.ReadDir(pki.PKIDir()); err == nil {
		for _, e := range entries {
			if DebugEnabled || os.Getenv("OVNODE_DEBUG") != "" {
				fmt.Fprintf(os.Stderr, "DEBUG PKI entry: %s\n", e.Name())
			}
		}
	}

	// Build CA if it doesn't exist
	if !caCertExists || !caKeyExists {
		if DebugEnabled || os.Getenv("OVNODE_DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "DEBUG: CA cert or key NOT found, building CA\n")
		}
		// Clean up any existing partial CA files
		os.Remove(filepath.Join(pki.PKIDir(), "private", "ca.key"))
		os.Remove(caPath)
		if !pki.RunEasyRSA("build-ca", "nopass") {
			return fmt.Errorf("CA creation failed")
		}
	}

	// Ensure directory tree exists before building server cert (creates reqs dir etc.)
	pki.EnsureDirTree()
	// Debug: check if reqs dir exists
	reqsDir := filepath.Join(pki.PKIDir(), "reqs")
	if _, err := os.Stat(reqsDir); err != nil {
		if DebugEnabled || os.Getenv("OVNODE_DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "DEBUG: reqs dir missing: %v\n", err)
		}
	} else {
		if DebugEnabled || os.Getenv("OVNODE_DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "DEBUG: reqs dir exists\n")
		}
	}

	// Clean up any existing server request/key files to avoid "already exists" errors
	os.Remove(filepath.Join(pki.PKIDir(), "reqs", "server.req"))
	os.Remove(filepath.Join(pki.PKIDir(), "private", "server.key"))

	// Build server cert with SANs (global option must come before command)
	// shortcut: omit hardcoded IP SAN; panel pins the CA certificate directly
	if !pki.RunEasyRSA("--subject-alt-name=DNS:server,DNS:localhost", "build-server-full", "server", "nopass") {
		return fmt.Errorf("Server certificate creation failed")
	}

	// Now create the directory tree with index.txt and serial
	pki.EnsureDirTree()

	if !pki.EnsureCRL() {
		return fmt.Errorf("PKI initialization cannot continue without a CRL")
	}
	pki.GenTLSKey()
	EnsureServerConf()
	EnsureClientTemplate()
	return nil
}
