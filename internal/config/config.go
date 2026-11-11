// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

// Package config reads the environment subset the OpenVPN hooks need.
//
// The variable names are the ones the bash hooks already use, so a node can
// switch between the two implementations without touching its environment.
package config

import (
	"strconv"

	"ovnode/internal/fsx"
	"ovnode/internal/logging"
)

// Defaults for the hook paths. They match the bash hooks and the store.
const (
	DefaultUsersDir    = "/var/lib/ovnode/users"
	DefaultSessionsDir = "/var/lib/ovnode/sessions"
	DefaultUsageDir    = "/var/lib/ovnode/usage"
	DefaultOpenVPNRoot = fsx.DefaultOpenVPNRoot
	DefaultLogDir      = "/var/log/ovnode"
	DefaultMgmtHost    = "127.0.0.1"
	DefaultMgmtPort    = 7505
	DefaultSessionTTL  = 86400
	// DefaultLimit is the per-user session limit when the user has no state.
	DefaultLimit = 1
)

// Hook is everything the three hook subcommands read from the environment.
type Hook struct {
	UsersDir     string
	SessionsDir  string
	UsageDir     string
	StatusFile   string
	LogDir       string
	LogFile      string
	MgmtHost     string
	MgmtPort     int
	MgmtPassFile string
	OpenVPNRoot  string
	SessionTTL   int
}

// HookFromEnv reads the hook configuration.
//
// ManagementHost is the only management host key; a broken
// numeric override falls back to the default rather than failing the hook:
// the management port is not worth refusing a client over.
func HookFromEnv() Hook {
	root := fsx.OpenVPNRoot()
	h := Hook{
		UsersDir:    fsx.UsersDir(),
		SessionsDir: fsx.SessionsDir(),
		UsageDir:    fsx.UsageDir(),
		// The status file follows the OpenVPN root so the hook counts the
		// same sessions the panel sees, even in a relocated tree.
		StatusFile:   fsx.Get("StatusFile", fsx.StatusFile("udp")),
		LogDir:       fsx.LogDir(),
		LogFile:      fsx.LogFile(),
		MgmtHost:     fsx.EnvOr("ManagementHost", DefaultMgmtHost),
		MgmtPassFile: fsx.MgmtPassFile(),
		OpenVPNRoot:  root,
		MgmtPort:     DefaultMgmtPort,
		SessionTTL:   DefaultSessionTTL,
	}
	if v := fsx.EnvOr("ManagementPort", ""); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p >= 1 && p <= 65535 {
			h.MgmtPort = p
		} else {
			logging.Event(h.LogFile, "ManagementPort invalid (%s); falling back to %d", v, DefaultMgmtPort)
		}
	}
	if v := fsx.EnvOr("SessionTtlSeconds", ""); v != "" {
		if t, err := strconv.Atoi(v); err == nil && t > 0 {
			h.SessionTTL = t
		} else {
			logging.Event(h.LogFile, "SessionTtlSeconds invalid (%s); falling back to %d", v, DefaultSessionTTL)
		}
	}
	return h
}
