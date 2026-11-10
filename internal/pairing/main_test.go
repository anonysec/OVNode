package pairing

import (
	"testing"

	"ovnode/internal/fsx"
	"ovnode/internal/testenv"
)

func TestMain(m *testing.M) { testenv.Run(m, fsx.EnvFileSource) }
