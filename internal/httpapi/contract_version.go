// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package httpapi

// ContractVersion is the wire-contract version this node implements.
//
// The panel and node version independently and may be upgraded in any
// order; what they must agree on is this contract constant. A panel
// requiring a newer contract than the node implements returns a typed 409
// ("contract_version_mismatch"), not an empty field downstream.
// Bump this only when a request/response shape in contract.json changes.
const ContractVersion = 3

// ContractFloor is the lowest panel version this node will serve.
const ContractFloor = 2
