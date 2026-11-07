// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"testing"

	"ovnode/internal/fsx"
	"ovnode/internal/testenv"
)

func TestMain(m *testing.M) { testenv.Run(m, fsx.EnvFileSource) }
