// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package httpapi

import _ "embed"

// ContractJSON is the vendored copy of the panel's contract.json. The panel
// is the authority; this file is a copy that the node's CI checks against
// the panel's published version. Embedding it lets `ovnode probe` verify
// the node's own routes against the contract without a network fetch.
//
//go:embed contract.json
var ContractJSON []byte
