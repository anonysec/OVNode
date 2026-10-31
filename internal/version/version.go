// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

// Package version holds the agent version.
//
// The same string is written in four places — this const, pyproject.toml,
// install.sh and manager.sh — and tests/test_version_parity.py is what keeps
// them from drifting apart.
package version

// Version is the agent version.
const Version = "1.4.2"
