// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

// Package fsx is the one place that knows where things live on disk.
package fsx

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	StoreKeyRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	HookCNRe   = regexp.MustCompile(`^[A-Za-z0-9_.][A-Za-z0-9_.-]*$`)
)

// SafeCN validates a CN before it becomes a path component (strict rule:
// store/API side). Rejects leading dash, ".", "..", and non-alphanumeric chars.
func SafeCN(cn string) (string, error) {
	cn = strings.TrimSpace(cn)
	if cn == "" || cn == "." || cn == ".." {
		return "", fmt.Errorf("invalid common name: %q", cn)
	}
	if !StoreKeyRe.MatchString(cn) {
		return "", fmt.Errorf("invalid common name: %q", cn)
	}
	if cn[0] == '-' {
		return "", fmt.Errorf("invalid common name: %q", cn)
	}
	return cn, nil
}

// Sanitize replaces every character outside [A-Za-z0-9_.-] with an underscore.
// It mirrors the sed in the bash hooks.
func Sanitize(s string) string {
	out := []byte(s)
	for i, c := range out {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '_', c == '.', c == '-':
		default:
			out[i] = '_'
		}
	}
	return string(out)
}

// HookCNValid reports whether a sanitized CN is acceptable to the hook.
func HookCNValid(safe string) bool {
	if safe == "" || len(safe) > 64 {
		return false
	}
	if safe == "." || safe == ".." {
		return false
	}
	return HookCNRe.MatchString(safe)
}

// StoreCNValid reports whether a CN may be used as a store path component.
func StoreCNValid(cn string) bool {
	_, err := SafeCN(cn)
	return err == nil
}
