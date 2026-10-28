// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

// Package ovnode carries the release assets the agent ships.
//
// The shell files the installer and the operator CLI are made of live inside
// the binary, and the binary writes them out. Three things fall out of that:
//
//   - One authored copy of each. The installer on a box and the installer in
//     the repository are the same bytes.
//   - The scripts on a box cannot disagree with the binary beside them. The
//     installer used to fetch its helpers from a branch while the product came
//     from a release, which is two versions that can drift.
//   - The installer downloads the product and nothing else.
//
// The embed lives in the module root because go:embed cannot reach outside
// its own directory, and install.sh has to stay at the repository root: its
// URL is the published install command.
package ovnode

import (
	_ "embed"
	"os"
	"path/filepath"
)

// Installer is the installer script: install, update, recover-update,
// repair-unit, uninstall.
//
//go:embed install.sh
var Installer []byte

// Operator is the operator CLI: status, logs, doctor, backup, restore, auth,
// tls. It is a script and not a subcommand because it is the only thing on a
// box that still works when the agent binary does not.
//
//go:embed ovnode.sh
var Operator []byte

// Lib is the shared shell toolkit the two scripts above source.
//
//go:embed lib.sh
var Lib []byte

// Doctor is the operator CLI's health checks.
//
//go:embed doctor.sh
var Doctor []byte

// Asset is one embedded shell file and the mode it must land with.
type Asset struct {
	Name string
	Mode os.FileMode
	Body []byte
}

// Assets returns every shell file the binary installs.
func Assets() []Asset {
	return []Asset{
		{Name: "install.sh", Mode: 0o755, Body: Installer},
		{Name: "ovnode.sh", Mode: 0o755, Body: Operator},
		{Name: "lib.sh", Mode: 0o644, Body: Lib},
		{Name: "doctor.sh", Mode: 0o644, Body: Doctor},
	}
}

// Write writes every embedded shell file into dir and returns the paths.
//
// Each file is written to a temporary name and renamed into place. A rename
// replaces the directory entry, so a script that is running right now keeps
// reading the inode it opened: bash reads a script by byte offset as it goes,
// and rewriting it in place under a running installer corrupts the run.
func Write(dir string) ([]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	// Stage every file first; only rename once all writes succeed, so a
	// failure never leaves a half-updated set (PasarGuard-style bootstrap).
	type staged struct {
		path string
		tmp  string
	}
	stageds := make([]staged, 0, len(Assets()))
	for _, a := range Assets() {
		p := filepath.Join(dir, a.Name)
		tmp, err := os.CreateTemp(dir, "."+a.Name+".*")
		if err != nil {
			for _, st := range stageds {
				os.Remove(st.tmp)
			}
			return nil, err
		}
		name := tmp.Name()
		if _, err := tmp.Write(a.Body); err != nil {
			tmp.Close()
			os.Remove(name)
			for _, st := range stageds {
				os.Remove(st.tmp)
			}
			return nil, err
		}
		if err := tmp.Close(); err != nil {
			os.Remove(name)
			for _, st := range stageds {
				os.Remove(st.tmp)
			}
			return nil, err
		}
		if err := os.Chmod(name, a.Mode); err != nil {
			os.Remove(name)
			for _, st := range stageds {
				os.Remove(st.tmp)
			}
			return nil, err
		}
		stageds = append(stageds, staged{path: p, tmp: name})
	}
	written := make([]string, 0, len(stageds))
	for _, st := range stageds {
		if err := os.Rename(st.tmp, st.path); err != nil {
			for _, s2 := range stageds {
				os.Remove(s2.tmp)
			}
			return written, err
		}
		written = append(written, st.path)
	}
	return written, nil
}
