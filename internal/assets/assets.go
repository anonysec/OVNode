// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

// Package ovnode embeds the installer, operator CLI, and shell library, so
// the binary and the scripts on a box are always the same release.
package assets

import (
	_ "embed"
	"os"
	"path/filepath"
)

// Installer is the install, update, recover, repair, and uninstall script.
//
//go:embed install.sh
var Installer []byte

// Operator is the operator CLI. It is a script because it has to work when
// the agent binary does not.
//
//go:embed ovnode.sh
var Operator []byte

// Lib is the shared shell toolkit the two scripts above source.
//
//go:embed lib.sh
var Lib []byte

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
	}
}

// Write installs every embedded script into dir. The rename keeps a running
// bash script readable: it reads by offset, so an in-place rewrite corrupts it.
func Write(dir string) ([]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	// Stage every file first, then rename, so a failure leaves no half set.
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
