// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

// Package config reads the environment subset the OpenVPN hooks need.
//
// The variable names are the ones the bash hooks already use, so a node can
// switch between the two implementations without touching its environment.
package config

import (
	"os"
	"strconv"

	"ovnode/internal/fsx"
)

// Defaults for the hook paths. They match the bash hooks and the store.
const (
	DefaultUsersDir    = "/etc/openvpn/ovnode/users"
	DefaultSessionsDir = "/etc/openvpn/ovnode/sessions"
	DefaultUsageDir    = "/etc/openvpn/ovnode/usage"
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
// OVNODE_MANAGEMENT_HOST beats the legacy OVNODE_MGMT_HOST, and a broken
// numeric override falls back to the default rather than failing the hook:
// the management port is not worth refusing a client over.
func HookFromEnv() Hook {
	root := fsx.OpenVPNRoot()
	logDir := fsx.EnvOr("OVNODE_LOG_DIR", DefaultLogDir)
	h := Hook{
		UsersDir:    fsx.EnvOr("OVNODE_USERS_DIR", DefaultUsersDir),
		SessionsDir: fsx.EnvOr("OVNODE_SESSIONS_DIR", DefaultSessionsDir),
		UsageDir:    fsx.EnvOr("OVNODE_USAGE_DIR", DefaultUsageDir),
		// The status file follows the OpenVPN root so the hook counts the
		// same sessions the panel sees, even in a relocated tree.
		StatusFile:   fsx.EnvOr("OVNODE_STATUS_FILE", root+"/server/status.log"),
		LogDir:       logDir,
		LogFile:      fsx.EnvOr("OVNODE_LOG_FILE", logDir+"/hook-events.log"),
		MgmtHost:     fsx.EnvOr("OVNODE_MANAGEMENT_HOST", fsx.EnvOr("OVNODE_MGMT_HOST", DefaultMgmtHost)),
		MgmtPassFile: fsx.EnvOr("OVNODE_MGMT_PASS_FILE", root+"/server/mgmt-pass"),
		OpenVPNRoot:  root,
		MgmtPort:     DefaultMgmtPort,
		SessionTTL:   DefaultSessionTTL,
	}
	if v, ok := os.LookupEnv("OVNODE_MANAGEMENT_PORT"); ok && v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			h.MgmtPort = p
		}
	}
	if v, ok := os.LookupEnv("OVNODE_SESSION_TTL"); ok && v != "" {
		if t, err := strconv.Atoi(v); err == nil {
			h.SessionTTL = t
		}
	}
	return h
}
