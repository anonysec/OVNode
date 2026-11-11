// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"os"
	"strings"

	"ovnode/internal/pki"
)

// Build assembles a .ovpn profile from named parts.
type Parts struct {
	ClientCert string
	ClientKey  string
	CACert     string
	TLSCrypt   string
}

// BuildTemplate assembles a profile from the operator's client template.
//
// The template (client-common.txt) is the body: it carries the remote lines
// and every other client option, and the panel's config push rewrites it.
// A hardcoded preamble would silently ignore a template the operator
// edited, so the file wins.
//
// Comment lines are dropped: the template is written for humans and a
// comment is not an OpenVPN directive.
func BuildTemplate(path string, p Parts) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	caCert := p.CACert
	if caCert != "" {
		if c, err := pki.CleanPEM(caCert); err == nil {
			caCert = c
		}
	}
	clientCert := p.ClientCert
	if clientCert != "" {
		if c, err := pki.CleanPEM(clientCert); err == nil {
			clientCert = c
		}
	}
	clientKey := p.ClientKey
	if clientKey != "" {
		if c, err := pki.CleanPEM(clientKey); err == nil {
			clientKey = c
		}
	}
	// Inline material is global too, so it goes before the connection blocks;
	// a top-level option after a <connection> block is ignored by OpenVPN.
	inline := ""
	if caCert != "" {
		inline += "\n<ca>\n" + caCert + "\n</ca>\n"
	}
	if clientCert != "" {
		inline += "\n<cert>\n" + clientCert + "\n</cert>\n"
	}
	if clientKey != "" {
		inline += "\n<key>\n" + clientKey + "\n</key>\n"
	}
	if p.TLSCrypt != "" {
		inline += "\n<tls-crypt>\n" + p.TLSCrypt + "\n</tls-crypt>\n"
	}
	body := b.String()
	if i := strings.Index(body, "<connection>"); i >= 0 {
		return body[:i] + inline + body[i:], nil
	}
	return body + inline, nil
}
