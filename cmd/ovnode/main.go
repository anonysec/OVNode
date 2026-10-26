// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

// Command ovnode is the OVNode OpenVPN agent.
//
// One binary, several jobs: the /sync API the panel polls, the OpenVPN hook
// that admits or refuses a client, and the PKI commands. The subcommands
// arrive in phases of the Python-to-Go rewrite; the ones that do not exist
// yet say so instead of pretending to work.
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	assets "ovnode"
	"ovnode/internal/config"
	"ovnode/internal/hooks"
	"ovnode/internal/httpapi"
	"ovnode/internal/installer"
	"ovnode/internal/ovpn"
	"ovnode/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "version":
		fmt.Println(version.Version)
	case "hook":
		runHook()
	case "ca":
		runCA()
	case "serve":
		if err := httpapi.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "ovnode serve: "+err.Error())
			os.Exit(1)
		}
	case "probe":
		runProbe()
	case "state":
		runState()
	case "identity-sha":
		runIdentitySHA()
	case "installer":
		runInstaller()
	case "assets":
		runAssets()
	default:
		usage()
		os.Exit(2)
	}
}

// runHook dispatches the OpenVPN hooks.
//
// The hook is called by OpenVPN on every connect and disconnect, so the
// exit code is the decision: 0 admits, anything else refuses the client.
func runHook() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: ovnode hook <connect|disconnect|purge-stale> [common_name]")
		os.Exit(2)
	}
	event := os.Args[2]
	arg := ""
	if len(os.Args) > 3 {
		arg = os.Args[3]
	}
	cfg := config.HookFromEnv()
	switch event {
	case "connect":
		os.Exit(hooks.Connect(cfg, arg))
	case "disconnect":
		os.Exit(hooks.Disconnect(cfg, arg))
	case "purge-stale":
		os.Exit(hooks.PurgeStale(cfg))
	default:
		fmt.Fprintf(os.Stderr, "ovnode hook: unknown event %q (connect|disconnect|purge-stale)\n", event)
		os.Exit(2)
	}
}

// runCA dispatches PKI subcommands.
func runCA() {
	if len(os.Args) < 3 {
		// default: init
		if err := ovpn.InitPKI(); err != nil {
			fmt.Fprintln(os.Stderr, "ovnode ca: "+err.Error())
			os.Exit(1)
		}
		fmt.Println("PKI initialized")
		return
	}
	switch os.Args[2] {
	case "init", "init-pki":
		if err := ovpn.InitPKI(); err != nil {
			fmt.Fprintln(os.Stderr, "ovnode ca: "+err.Error())
			os.Exit(1)
		}
		fmt.Println("PKI initialized")
	default:
		fmt.Fprintf(os.Stderr, "ovnode ca: unknown subcommand %q\n", os.Args[2])
		os.Exit(2)
	}
}

func runState() {
	if len(os.Args) >= 3 && os.Args[2] == "read" {
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: ovnode state read <path>")
			os.Exit(2)
		}
		m, err := installer.ReadUpdateState(os.Args[3])
		if err != nil {
			fmt.Fprintln(os.Stderr, "ovnode state: "+err.Error())
			os.Exit(1)
		}
		phase, _ := m["phase"].(string)
		from, _ := m["from_version"].(string)
		target, _ := m["to_version"].(string)
		safety, _ := m["safety_backup"].(string)
		identity, _ := m["identity_sha"].(string)
		fmt.Printf("%s %s %s %s %s\n", phase, from, target, safety, identity)
		return
	}
	if len(os.Args) < 4 || os.Args[2] != "write" {
		fmt.Fprintln(os.Stderr, "usage: ovnode state write <path> <phase> <from> <target> [backup] [identity]")
		os.Exit(2)
	}
	path := os.Args[3]
	phase := os.Args[4]
	from := ""
	target := ""
	if len(os.Args) > 5 {
		from = os.Args[5]
	}
	if len(os.Args) > 6 {
		target = os.Args[6]
	}
	backup := ""
	identity := ""
	if len(os.Args) > 7 {
		backup = os.Args[7]
	}
	if len(os.Args) > 8 {
		identity = os.Args[8]
	}
	if err := installer.WriteUpdateState(path, phase, from, target, backup, identity); err != nil {
		fmt.Fprintln(os.Stderr, "ovnode state: "+err.Error())
		os.Exit(1)
	}
}

func runInstaller() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: ovnode installer <bundle|restore> ...")
		os.Exit(2)
	}
	switch os.Args[2] {
	case "bundle":
		// ovnode installer bundle <appDir> <nodeData> <ovpnRoot> <backupRoot> <node> <fromVersion>
		if len(os.Args) < 9 {
			fmt.Fprintln(os.Stderr, "usage: ovnode installer bundle <appDir> <nodeData> <ovpnRoot> <backupRoot> <node> <fromVersion>")
			os.Exit(2)
		}
		b, err := installer.Bundle(os.Args[3], os.Args[4], os.Args[5], os.Args[6], os.Args[7], os.Args[8])
		if err != nil {
			fmt.Fprintln(os.Stderr, "ovnode installer: "+err.Error())
			os.Exit(1)
		}
		fmt.Println(b)
	case "restore":
		// ovnode installer restore <bundle> <appDir> <dataBase> <ovpnRoot>
		if len(os.Args) < 7 {
			fmt.Fprintln(os.Stderr, "usage: ovnode installer restore <bundle> <appDir> <dataBase> <ovpnRoot>")
			os.Exit(2)
		}
		if err := installer.Restore(os.Args[3], os.Args[4], os.Args[5], os.Args[6]); err != nil {
			fmt.Fprintln(os.Stderr, "ovnode installer: "+err.Error())
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "ovnode installer: unknown %q\n", os.Args[2])
		os.Exit(2)
	}
}

// runAssets writes the shell files the binary carries into a directory.
//
// The installer calls this right after it lands the binary: the scripts it
// runs next come from the binary it just verified, so they cannot disagree
// with it and the installer downloads nothing but the product.
func runAssets() {
	if len(os.Args) < 3 || os.Args[2] != "write" {
		fmt.Fprintln(os.Stderr, "usage: ovnode assets write --dest DIR")
		os.Exit(2)
	}
	dest := ""
	for i := 3; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--dest":
			if i+1 >= len(os.Args) {
				fmt.Fprintln(os.Stderr, "ovnode assets: --dest needs a directory")
				os.Exit(2)
			}
			dest = os.Args[i+1]
			i++
		default:
			fmt.Fprintf(os.Stderr, "ovnode assets: unknown option %q\n", os.Args[i])
			os.Exit(2)
		}
	}
	if dest == "" {
		fmt.Fprintln(os.Stderr, "ovnode assets: --dest is required")
		os.Exit(2)
	}
	written, err := assets.Write(dest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ovnode assets: "+err.Error())
		os.Exit(1)
	}
	for _, p := range written {
		fmt.Println(p)
	}
}

// runProbeCheck makes a request to every route in the contract and reports
// pass/fail. It reads the API key and port from the installed .env, so it
// runs against the local agent without any panel involvement.
func runProbeCheck() {
	// Read the .env for the port and key.
	appDir := os.Getenv("OVN_APP_DIR")
	if appDir == "" {
		appDir = "/opt/ovnode"
	}
	envGet := func(key string) string {
		for _, path := range []string{appDir + "/.env", "/etc/openvpn/ovnode/.env"} {
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				if k, v, ok := strings.Cut(line, "="); ok && k == key {
					return strings.TrimSpace(v)
				}
			}
		}
		return ""
	}
	port := envGet("SERVICE_PORT")
	if port == "" {
		port = "2083"
	}
	key := envGet("API_KEY")
	if key == "" {
		fmt.Fprintln(os.Stderr, "ovnode probe: no API key found in .env")
		os.Exit(1)
	}

	var rows []struct {
		Method string `json:"method"`
		Path   string `json:"path"`
	}
	if err := json.Unmarshal(httpapi.ContractJSON, &rows); err != nil {
		fmt.Fprintln(os.Stderr, "ovnode probe: bad contract.json: "+err.Error())
		os.Exit(1)
	}

	pass, fail := 0, 0
	for _, r := range rows {
		// Only probe envelope routes; raw routes need special handling.
		if r.Path == "/sync/download/ovpn/{uid}" {
			continue
		}
		url := "https://127.0.0.1:" + port + r.Path
		req, _ := http.NewRequest(r.Method, url, nil)
		req.Header.Set("key", key)
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
		resp, err := client.Do(req)
		status := "FAIL"
		if err == nil && resp.StatusCode < 500 {
			status = "OK"
			pass++
		} else {
			fail++
		}
		if resp != nil {
			resp.Body.Close()
		}
		fmt.Printf("  %-7s %-32s %s\n", r.Method, r.Path, status)
	}
	fmt.Printf("\n  %d passed, %d failed\n", pass, fail)
	if fail > 0 {
		os.Exit(1)
	}
}

func runIdentitySHA() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: ovnode identity-sha <name> <key>")
		os.Exit(2)
	}
	fmt.Println(installer.IdentitySHA(os.Args[2], os.Args[3]))
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ovnode <command>")
	fmt.Fprintln(os.Stderr, "commands: version, serve, hook, ca, probe, state, identity-sha, installer, assets")
}

// runProbe reads the embedded contract and checks every route the panel
// expects against the running agent. It is the acceptance probe in binary
// form: one row per route, pass or fail, no network to the panel.
func runProbe() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: ovnode probe <contract|check>")
		os.Exit(2)
	}
	switch os.Args[2] {
	case "contract":
		fmt.Println(string(httpapi.ContractJSON))
	case "check":
		runProbeCheck()
	default:
		fmt.Fprintf(os.Stderr, "ovnode probe: unknown %q (contract|check)\n", os.Args[2])
		os.Exit(2)
	}
}
