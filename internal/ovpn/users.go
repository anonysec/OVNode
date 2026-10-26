// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ovnode/internal/fsx"
	"ovnode/internal/pki"
	"ovnode/internal/store"
)

// The user lifecycle: certificates, profiles, status and limits.
//
// The panel is the source of truth for the user identity; here a user is a
// certificate common name plus one folder of state in the ovnode tree.

// CreateUser creates or repairs a user: certificate, profile, name and
// limit. It is idempotent.
//
// Without certificate material the node issues one from its own CA. A node
// without a CA (the panel owns the PKI) keeps the user directory and its
// state, so the limits are still tracked, but the user cannot connect.
func CreateUser(cn, name string, maxLogins int, disabled *bool) error {
	if err := store.CreateUser(pki.UsersDir(), cn); err != nil {
		return err
	}
	if !hasCertMaterial(cn) {
		if _, err := os.Stat(pki.CACert()); err != nil {
			return fmt.Errorf("no PKI and no pushed certificate for %q", cn)
		}
		if _, _, err := pki.IssueClientCertToTree(cn); err != nil {
			return err
		}
	}
	if _, err := BuildUserProfile(cn); err != nil {
		return err
	}
	if name != "" {
		if err := store.WriteName(pki.UsersDir(), cn, name); err != nil {
			return err
		}
	}
	if err := store.SetLimit(pki.UsersDir(), cn, maxLogins); err != nil {
		return err
	}
	if disabled != nil {
		if err := store.SetDisabled(pki.UsersDir(), cn, *disabled); err != nil {
			return err
		}
	}
	store.InvalidateNameCache()
	return nil
}

// CreateUserWithCredentials stores panel-pushed credentials and the state
// of a user.
//
// The panel owns the PKI: it signs the user certificate and pushes it here.
// The node stores it passively and never invokes a local CA.
func CreateUserWithCredentials(cn, certPEM, keyPEM, caPEM string, maxLogins int, disabled *bool) error {
	if certPEM == "" || keyPEM == "" {
		return fmt.Errorf("cert_pem and key_pem are required")
	}
	dir, err := store.UserDir(pki.UsersDir(), cn)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, f := range []struct {
		name string
		body string
		perm os.FileMode
	}{
		{"cert.pem", certPEM, 0o644},
		{"key.pem", keyPEM, 0o600},
	} {
		if err := fsx.WriteFileAtomic(filepath.Join(dir, f.name),
			[]byte(ensureTrailingNewline(f.body)), f.perm); err != nil {
			return err
		}
	}
	// The CA: the pushed copy wins, else the node's own CA is mirrored.
	// An existing per-user CA is never clobbered by a re-push.
	if caPEM != "" {
		if err := fsx.WriteFileAtomic(filepath.Join(dir, "ca.pem"),
			[]byte(ensureTrailingNewline(caPEM)), 0o644); err != nil {
			return err
		}
	} else if _, err := os.Stat(filepath.Join(dir, "ca.pem")); err != nil {
		if body, err := os.ReadFile(pki.CACert()); err == nil {
			_ = fsx.WriteFileAtomic(filepath.Join(dir, "ca.pem"), body, 0o644)
		}
	}
	if err := store.SetLimit(pki.UsersDir(), cn, maxLogins); err != nil {
		return err
	}
	if disabled != nil {
		if err := store.SetDisabled(pki.UsersDir(), cn, *disabled); err != nil {
			return err
		}
	}
	if _, err := BuildUserProfile(cn); err != nil {
		return err
	}
	store.InvalidateNameCache()
	return nil
}

// DeleteUser revokes the user's certificate, regenerates the CRL and
// removes the user's tree.
//
// It reports whether the user existed. A certificate the panel pushed was
// never issued by this CA, so only the local material is revoked: revoking a
// serial the local index never knew would produce a CRL the OpenVPN server
// cannot use.
func DeleteUser(cn string) (bool, error) {
	usersDir := pki.UsersDir()
	dir, err := store.UserDir(usersDir, cn)
	if err != nil {
		return false, err
	}
	hasLocalCert := fileExists(pki.IssuedCertPath(cn))
	hasPushedCert := fileExists(filepath.Join(dir, "cert.pem"))
	hasProfile := fileExists(filepath.Join(dir, "client.ovpn"))
	if !hasLocalCert && !hasPushedCert && !hasProfile {
		store.DeleteUser(usersDir, pki.SessionsDir(), pki.UsageDir(), cn)
		return false, nil
	}
	if hasLocalCert {
		if err := pki.RevokeCertByCN(cn); err != nil {
			return true, err
		}
	} else if err := pki.GenerateCRL(); err != nil {
		// The CRL must still cover the local index, but the certificate was
		// not ours: a failure here is not a failed delete.
		return true, fmt.Errorf("could not regenerate the CRL: %w", err)
	}
	pki.RemoveClientMaterial(cn)
	_ = os.Remove(filepath.Join(pki.OpenVPNRoot(), "ccd", cn))
	store.DeleteUser(usersDir, pki.SessionsDir(), pki.UsageDir(), cn)
	store.InvalidateNameCache()
	return true, nil
}

// SetUserStatus activates or deactivates a user.
//
// Deactivating also drops the user's live sessions: the disabled marker
// blocks the reconnects, but a session that is already up keeps running.
func SetUserStatus(cn, status string) error {
	switch status {
	case "deactivate":
		if err := store.SetDisabled(pki.UsersDir(), cn, true); err != nil {
			return err
		}
		// Best effort: the disabled marker blocks the reconnects even when
		// the management socket is unavailable.
		DisconnectUser(cn, false)
		return nil
	case "activate":
		return store.SetDisabled(pki.UsersDir(), cn, false)
	}
	return fmt.Errorf("unknown status %q", status)
}

// SetUserLimit sets the max simultaneous logins of a user.
//
// The panel sends the numeric user id or, when it has none, the display
// name. The name is resolved to the common name so the connect hook, which
// only knows common names, finds the limit.
func SetUserLimit(ident string, maxLogins int) error {
	cn := ident
	if !store.UserExists(pki.UsersDir(), cn) {
		if resolved := store.CNForName(pki.UsersDir(), ident); resolved != "" {
			cn = resolved
		}
	}
	return store.SetLimit(pki.UsersDir(), cn, maxLogins)
}

// BuildUserProfile builds the .ovpn profile of a user and caches it.
//
// The material comes from the panel-pushed files when they are there and
// from the local PKI otherwise. The CA chain and the tls-crypt key are
// always embedded: the handshake fails without them.
//
// The body is the operator's client template (client-common.txt), not a
// hardcoded preamble: the template carries the remote lines and every other
// client option, and it is the file the panel's config push rewrites. A
// profile built from a hardcoded preamble would ignore a template the
// operator edited.
func BuildUserProfile(cn string) (string, error) {
	usersDir := pki.UsersDir()
	dir, err := store.UserDir(usersDir, cn)
	if err != nil {
		return "", err
	}
	certPEM := readFirstFile(filepath.Join(dir, "cert.pem"), pki.IssuedCertPath(cn))
	keyPEM := readFirstFile(filepath.Join(dir, "key.pem"), pki.ClientKeyPath(cn))
	if certPEM == "" || keyPEM == "" {
		return "", fmt.Errorf("no certificate material for %q", cn)
	}
	caPEM := readFirstFile(filepath.Join(dir, "ca.pem"), pki.CACert())
	text, err := BuildTemplate(pki.ClientTemplate(), Parts{
		ClientCert: certPEM,
		ClientKey:  keyPEM,
		CACert:     caPEM,
		TLSCrypt:   pki.ReadTLSCryptKey(),
	})
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "client.ovpn")
	// 0600: the profile embeds the client private key and the tls-crypt
	// pre-shared key.
	if err := fsx.WriteFileAtomic(path, []byte(text), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// UserProfilePath returns the path of the cached profile of a user.
func UserProfilePath(cn string) (string, error) {
	return store.OVPNPath(pki.UsersDir(), cn)
}

// hasCertMaterial reports whether a user has a certificate the node can
// build a profile from.
func hasCertMaterial(cn string) bool {
	dir, err := store.UserDir(pki.UsersDir(), cn)
	if err != nil {
		return false
	}
	if fileExists(filepath.Join(dir, "cert.pem")) && fileExists(filepath.Join(dir, "key.pem")) {
		return true
	}
	return fileExists(pki.IssuedCertPath(cn)) && fileExists(pki.ClientKeyPath(cn))
}

// endpoint returns the tunnel address, the port and the protocol the
// profiles carry.
//
// The on-disk values win: an environment default would hand out a profile
// that cannot connect, because the server runs udp while the default says
// tcp.

// readFirstFile returns the content of the first file that exists.
func readFirstFile(paths ...string) string {
	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return ""
}

// fileExists reports whether a path exists.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ensureTrailingNewline appends the newline a PEM block needs.
func ensureTrailingNewline(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}
