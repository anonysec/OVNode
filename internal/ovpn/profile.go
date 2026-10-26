// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"os"
	"strings"
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
	if p.CACert != "" {
		b.WriteString("\n<ca>\n" + p.CACert + "\n</ca>\n")
	}
	if p.ClientCert != "" {
		b.WriteString("\n<cert>\n" + p.ClientCert + "\n</cert>\n")
	}
	if p.ClientKey != "" {
		b.WriteString("\n<key>\n" + p.ClientKey + "\n</key>\n")
	}
	if p.TLSCrypt != "" {
		b.WriteString("\n<tls-crypt>\n" + p.TLSCrypt + "\n</tls-crypt>\n")
	}
	return b.String(), nil
}

// NormalizeBlocks extracts inline blocks in order for golden comparison.
func NormalizeBlocks(s string) []string {
	var blocks []string
	lines := strings.Split(s, "\n")
	i := 0
	for i < len(lines) {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") && !strings.HasPrefix(line, "</") {
			tag := strings.Trim(line, "<>")
			block := line + "\n"
			i++
			for i < len(lines) {
				block += lines[i] + "\n"
				if strings.TrimSpace(lines[i]) == "</"+tag+">" {
					break
				}
				i++
			}
			blocks = append(blocks, strings.TrimSpace(block))
		}
		i++
	}
	return blocks
}
