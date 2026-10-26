// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

// Package pki holds the local PKI: easy-rsa bootstrap, certificate and CRL
// lifecycle, and the hardened server.conf writer.
//
// Paths live in internal/fsx. This file re-exports them so callers that
// already address the PKI by name keep working; the resolution happens in
// one place.
package pki

import (
	"ovnode/internal/fsx"
)

const DefaultOpenVPNRoot = fsx.DefaultOpenVPNRoot

func OpenVPNRoot() string    { return fsx.OpenVPNRoot() }
func IsInstalledTree() bool  { return fsx.IsInstalledTree() }
func EasyRSADir() string     { return fsx.EasyRSADir() }
func PKIDir() string         { return fsx.PKIDir() }
func ServerConf() string     { return fsx.ServerConf() }
func ClientTemplate() string { return fsx.ClientTemplate() }
func TLSKey() string         { return fsx.TLSKey() }
func CACert() string         { return fsx.CACert() }
func ServerCert() string     { return fsx.ServerCert() }
func ServerKey() string      { return fsx.ServerKey() }
func DHPem() string          { return fsx.DHPem() }
func CRLFile() string        { return fsx.CRLFile() }
func PIDFile() string        { return fsx.PIDFile() }
func MgmtPassFile() string   { return fsx.MgmtPassFile() }
func OVNodeDir() string      { return fsx.OVNodeDir() }
func UsersDir() string       { return fsx.UsersDir() }
func SessionsDir() string    { return fsx.SessionsDir() }
func UsageDir() string       { return fsx.UsageDir() }
func ScriptsDir() string     { return fsx.ScriptsDir() }
func RequiredDirs() []string { return fsx.RequiredDirs() }
