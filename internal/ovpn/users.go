// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"errors"
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
	return withUserLifecycle(cn, func() error {
		return createUserLocked(cn, name, maxLogins, disabled)
	})
}

func createUserLocked(cn, name string, maxLogins int, disabled *bool) error {
	if err := store.CreateUser(pki.UsersDir(), cn); err != nil {
		return err
	}
	if !hasCertMaterial(cn) {
		dir, err := store.UserDir(pki.UsersDir(), cn)
		if err != nil {
			return err
		}
		if fileExists(filepath.Join(dir, "cert.pem")) || fileExists(filepath.Join(dir, "key.pem")) {
			return fmt.Errorf("incomplete pushed credentials for %q", cn)
		}
		if _, err := os.Stat(pki.CACert()); err != nil {
			return fmt.Errorf("no PKI and no pushed certificate for %q", cn)
		}
		if _, _, err := pki.IssueClientCertToTree(cn); err != nil {
			return err
		}
	}
	if _, err := buildUserProfileLocked(cn); err != nil {
		return err
	}
	var namePtr *string
	if name != "" {
		namePtr = &name
	}
	var limitPtr *int
	if maxLogins >= 0 {
		limitPtr = &maxLogins
	}
	if err := store.WriteUserPolicy(pki.UsersDir(), cn, namePtr, limitPtr, disabled); err != nil {
		return err
	}
	store.InvalidateNameCache()
	return nil
}

// CreateUserWithCredentials stores panel-pushed credentials and the state
// of a user.
//
// The panel owns the PKI: it signs the user certificate and pushes it here.
// The node stores it passively and never invokes a local CA.
func CreateUserWithCredentials(cn, certPEM, keyPEM, caPEM string, maxLogins *int, disabled *bool) error {
	return withUserLifecycle(cn, func() error {
		return createUserWithCredentialsLocked(cn, certPEM, keyPEM, caPEM, maxLogins, disabled)
	})
}

func createUserWithCredentialsLocked(cn, certPEM, keyPEM, caPEM string, maxLogins *int, disabled *bool) error {
	if certPEM == "" || keyPEM == "" {
		return fmt.Errorf("cert_pem and key_pem are required")
	}
	if err := pki.ValidateClientCert(cn, certPEM, keyPEM, caPEM); err != nil {
		return err
	}
	// clean PEMs
	if c, err := pki.CleanPEM(certPEM); err == nil {
		certPEM = c
	}
	if c, err := pki.CleanPEM(keyPEM); err == nil {
		keyPEM = c
	}
	if caPEM != "" {
		if c, err := pki.CleanPEM(caPEM); err == nil {
			caPEM = c
		}
	}
	dir, err := store.UserDir(pki.UsersDir(), cn)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
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
	if err := store.WriteUserPolicy(pki.UsersDir(), cn, nil, maxLogins, disabled); err != nil {
		return err
	}
	if _, err := buildUserProfileLocked(cn); err != nil {
		return err
	}
	store.InvalidateNameCache()
	return nil
}

// Unverifiable revocation keeps the disabled tombstone and recoverable material.
func DeleteUser(cn string) (bool, error) {
	var found bool
	err := withUserLifecycle(cn, func() error {
		var err error
		found, err = deleteUserLocked(cn)
		return err
	})
	if errors.Is(err, errUserGenerationChanged) {
		return false, nil
	}
	return found, err
}

func deleteUserLocked(cn string) (bool, error) {
	usersDir := pki.UsersDir()
	dir, err := store.UserDir(usersDir, cn)
	if err != nil {
		return false, err
	}
	hasMaterial := false
	for _, path := range []string{pki.IssuedCertPath(cn), filepath.Join(dir, "cert.pem"), filepath.Join(dir, "client.ovpn")} {
		present, err := materialExists(path)
		if err != nil {
			if disableErr := store.SetDisabled(usersDir, cn, true); disableErr != nil {
				return true, disableErr
			}
			DisconnectUser(cn, false)
			return true, err
		}
		hasMaterial = hasMaterial || present
	}
	if !hasMaterial {
		state, err := store.ReadUserState(usersDir, cn)
		if err != nil {
			return false, err
		}
		if !state.Disabled {
			return false, store.DeleteUser(usersDir, "", "", cn)
		}
	}
	// Disable and disconnect before any destructive step, so a failed
	// revocation leaves a disabled tombstone instead of live access.
	if err := store.SetDisabled(usersDir, cn, true); err != nil {
		return true, err
	}
	DisconnectUser(cn, false)

	if err := pki.RemoveClientMaterial(cn); err != nil {
		return true, err
	}
	if err := os.Remove(filepath.Join(pki.OpenVPNRoot(), "ccd", cn)); err != nil && !os.IsNotExist(err) {
		return true, err
	}
	if err := store.DeleteUser(usersDir, "", "", cn); err != nil {
		return true, err
	}
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
		return ApplyUserPolicy(cn, "", -1, true)
	case "activate":
		return ApplyUserPolicy(cn, "", -1, false)
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
	var limit *int
	if maxLogins >= 0 {
		limit = &maxLogins
	}
	return withUserLifecycle(cn, func() error {
		return store.WriteUserState(pki.UsersDir(), cn, limit, nil)
	})
}

// ApplyUserPolicy applies name, limit and disabled state as one checked
// operation. A negative maxLogins keeps the current limit untouched, so a
// status-only or name-only request cannot reset an existing device limit.
func ApplyUserPolicy(cn, name string, maxLogins int, disabled bool) error {
	return withUserLifecycle(cn, func() error {
		return applyUserPolicyLocked(cn, name, maxLogins, disabled)
	})
}

func applyUserPolicyLocked(cn, name string, maxLogins int, disabled bool) error {
	usersDir := pki.UsersDir()
	var namePtr *string
	if name != "" {
		namePtr = &name
	}
	var limitPtr *int
	if maxLogins >= 0 {
		limitPtr = &maxLogins
	}
	if err := store.WriteUserPolicy(usersDir, cn, namePtr, limitPtr, &disabled); err != nil {
		return err
	}
	store.InvalidateNameCache()
	if disabled {
		DisconnectUser(cn, false)
	}
	return nil
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
	var path string
	err := withUserLifecycle(cn, func() error {
		var err error
		path, err = buildUserProfileLocked(cn)
		return err
	})
	return path, err
}

func buildUserProfileLocked(cn string) (string, error) {
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
	if err := os.MkdirAll(dir, 0o700); err != nil {
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

func ReadUserProfile(cn string) ([]byte, error) {
	var data []byte
	err := withUserLifecycle(cn, func() error {
		path, err := UserProfilePath(cn)
		if err != nil {
			return err
		}
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if err := createUserLocked(cn, "", -1, nil); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		data, err = os.ReadFile(path)
		return err
	})
	return data, err
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
