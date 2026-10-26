// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package pki

import "crypto/rand"

func fillRand(b []byte) {
	rand.Read(b)
}
