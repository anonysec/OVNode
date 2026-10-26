// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package hooks

import (
	"ovnode/internal/fsx"
)

var (
	HookCN  = fsx.HookCNRe
	StoreCN = fsx.StoreKeyRe
)

// Sanitize replaces every character outside [A-Za-z0-9_.-] with an underscore.
func Sanitize(s string) string { return fsx.Sanitize(s) }

// HookCNValid reports whether a sanitized CN is acceptable to the hook.
func HookCNValid(safe string) bool { return fsx.HookCNValid(safe) }

// StoreCNValid reports whether a CN may be used as a store path component.
func StoreCNValid(cn string) bool { return fsx.StoreCNValid(cn) }
