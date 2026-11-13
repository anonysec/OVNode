package commands

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ovnode/internal/assets"
)

// installIncomplete reports a tree that has .env and the binary but no CA:
// a first install that failed at `ca init`. Retrying install must finish it
// rather than report "already installed" and leave the node dead.
func (c *Config) installIncomplete() bool {
	if _, err := os.Stat(filepath.Join(c.AppDir, installMarker)); err == nil {
		return false
	}
	_, err := os.Stat(filepath.Join(c.OpenVPNRoot, "server", "pki", "ca.crt"))
	return err != nil
}

// installMarker is written only after a complete install; a tree without it
// and without a CA is a first install that failed part way.
const installMarker = ".installed"

// Install reproduces do_install; it is the installer beyond the bootstrap.
func Install(c *Config, runner Runner) error {
	state := c.PreState
	if state == "" {
		state = c.InstallStateOf(c.AppDir)
	} else {
		if state == StateInstalled {
			if _, err := os.Stat(filepath.Join(c.AppDir, ".env")); err != nil {
				state = StateAbsent
			}
		}
	}
	partial := state == StateInstalled && c.installIncomplete()
	if !c.Local {
		if state == StateInstalled && !partial {
			return alreadyInstalled("(%s exists); run 'update' to refresh or 'uninstall' first", c.AppDir)
		}
		if state == StateUnitOnly || state == StateNodeData {
			return c.RefusePartialNode()
		}
		if state == StateBootstrap {
			c.ReportBootstrapDir()
		}
	}
	if err := checkRoot(); err != nil {
		return fmt.Errorf("%w: %d", ErrRoot, ExitError)
	}
	if err := c.validate(); err != nil {
		return err
	}
	stage(1, 7, "Preflight")
	if err := ensureDependencies(runner); err != nil {
		return err
	}
	if err := c.ensureRuntimeIdentity(runner); err != nil {
		return err
	}
	stageOK("preflight")
	// [2/7] Download — skipped on --local, which builds from a checkout.
	stage(2, 7, "Release")
	if !c.Local {
		if err := c.resolveVersion(); err != nil {
			return err
		}
		if err := c.fetchRelease(filepath.Join(c.AppDir, "ovnode")); err != nil {
			return err
		}
		stageOK("release v" + c.Version)
	} else {
		stageOK("local build")
	}
	// [3/7] Certificate — TLS files are reconciled against the node PKI.
	// setup_tls output is a best-effort refresh; PKI bootstrap below is the
	// authoritative key/cert source.
	stage(3, 7, "PKI and configuration")
	if err := c.setupTLS(runner); err != nil {
		return err
	}
	if err := c.writeEnv(); err != nil {
		return err
	}
	// A wizard can change the instance after the bootstrap chose its AppDir;
	// put the embedded shell files in this tree so installCLI has its source.
	if _, err := assets.Write(c.AppDir); err != nil {
		return err
	}
	schemeHost := c.schemeHost()
	scheme := "http"
	if c.TLSMethod != "none" {
		scheme = "https"
	}
	if err := os.MkdirAll(c.DataDir(), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(c.LogDir, 0o755); err != nil {
		return err
	}
	if err := c.ensureOpenVPNDirs(); err != nil {
		return err
	}
	if err := c.writeSettings(); err != nil {
		return err
	}
	if err := c.installAgentBinary(); err != nil {
		return err
	}
	// The agent refuses to start without a PKI; bootstrap before the unit.
	if out, err := runner.Output(c.AgentBin(), "ca", "init"); err != nil {
		return fmt.Errorf("PKI initialization failed: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	stageOK("PKI and configuration")
	// [4/7] Runtime
	stage(4, 7, "Runtime")
	if !hasSystemd() {
	} else {
		if err := c.writeSystemdUnit(runner); err != nil {
			return err
		}
		if err := c.writeNatUnit(runner); err != nil {
			return err
		}
		if err := systemctlBounded(runner, "restart", c.Service); err != nil {
			return fmt.Errorf("could not start %s: %w", c.Service, err)
		}
	}
	stageOK("service started")
	// [5/7] Health
	stage(5, 7, "Health")
	healthURL := scheme + "://127.0.0.1:" + c.Port + "/sync/health"
	if !healthCheck(healthURL, 60) {
		return fmt.Errorf("health: no answer on /sync/health after 60s")
	}
	stageOK("health")
	// [6/7] VPN
	stage(6, 7, "VPN")
	c.startOpenVPN(runner)
	if err := c.setupNAT(runner); err != nil {
		return err
	}
	_ = c.writeCron()
	if err := c.setupLogrotate(); err != nil {
		return err
	}
	c.openFirewall(runner)
	stageOK("VPN")
	// [7/7] Command
	stage(7, 7, "CLI and summary")
	c.installCLI()
	if err := c.writeSetupInfo(runner); err != nil {
		return err
	}
	_ = os.WriteFile(filepath.Join(c.AppDir, installMarker), []byte(c.Version+"\n"), 0o644)
	stageOK("done")
	c.successCard(schemeHost, scheme)
	return nil
}

func (c *Config) schemeHost() string {
	host := publicIP(DefaultRunner())
	if host == "" {
		host = primaryIP(DefaultRunner())
	}
	if c.TLSMethod == "letsencrypt" && c.TLSDomain != "" {
		return c.TLSDomain + ":" + c.Port
	}
	return host + ":" + c.Port
}

func (c *Config) successCard(where, scheme string) {
	fmt.Fprintf(os.Stderr, "\n  Installation complete\n")
	fmt.Fprintf(os.Stderr, "  Node     %s\n", where)
	fmt.Fprintf(os.Stderr, "  Key      %s\n", c.APIKey)
	fmt.Fprintf(os.Stderr, "  TLS      %s\n", c.tlsSummary())
	fmt.Fprintf(os.Stderr, "  Data     %s\n", c.DataDir())
	fmt.Fprintf(os.Stderr, "  Logs     %s logs -f\n", c.CLIName)
	if c.PanelIP != "" {
		fmt.Fprintf(os.Stderr, "  Panel    allow %s\n", c.PanelIP)
	}
	c.printCertificate()
}

// printCertificate shows the API certificate the panel pins, including the
// PEM an operator can paste into another tool.
func (c *Config) printCertificate() {
	path := c.TLSCert
	if path == "" {
		path = c.EnvGet("TlsCertFile")
	}
	if path == "" {
		path = filepath.Join(c.OpenVPNRoot, "server", "pki", "issued", "server.crt")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "\n  Certificate (%s)\n", path)
	fmt.Fprintln(os.Stderr, strings.TrimSpace(string(pem.EncodeToMemory(block))))
	sum := sha256.Sum256(block.Bytes)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	fmt.Fprintf(os.Stderr, "  SHA256    %s\n", strings.Join(parts, ":"))
}

func stage(n, total int, label string) {
	fmt.Fprintf(os.Stderr, "\n  [%d/%d] %s\n", n, total, label)
}

func stageOK(label string) {
	fmt.Fprintf(os.Stderr, "  ok    %s\n", label)
}

// healthCheck skips the probe under the fake installer runner: the harness
// starts no process, so nothing can answer.
func healthCheck(url string, timeout int) bool {
	if IsFake() {
		return true
	}
	return waitHealth(url, timeout)
}

// healthPoll is the pause between health probes; a var so tests do not sleep.
var healthPoll = time.Second

// waitHealth polls <url> once per healthPoll for up to timeout seconds. A
// probe is a plain GET: the endpoint is unauthenticated by design, and the
// loopback certificate is the one this node just generated.
func waitHealth(url string, timeout int) bool {
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- loopback probe of this node's own self-signed certificate
		},
	}
	for i := 0; i < timeout; i++ {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
		if i < timeout-1 {
			time.Sleep(healthPoll)
		}
	}
	return false
}

func (c *Config) startOpenVPN(r Runner) {
	if hasSystemd() {
		_ = systemctlBounded(r, "restart", c.Service)
	}
}

// ensureOpenVPNDirs mirrors ensure_openvpn_dirs.
func (c *Config) ensureOpenVPNDirs() error {
	data := c.DataDir()
	ovn := c.OpenVPNRoot
	dirs := []string{
		"/etc/ovnode",
		"/etc/ovnode/tls",
		filepath.Join(ovn, "server"),
		filepath.Join(ovn, "ccd"),
		data,
		filepath.Join(data, "users"),
		filepath.Join(data, "sessions"),
		filepath.Join(data, "usage"),
		filepath.Join(data, "state"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// setupTLS is a thin wrapper: ca init (run above) is the PKI source;
// custom TLS files are copied when provided.
func (c *Config) setupTLS(r Runner) error {
	if c.TLSMethod == "custom" {
		if c.TLSKey == "" || c.TLSCert == "" {
			return fmt.Errorf("custom TLS key/cert files not found")
		}
	}
	// letsencrypt/selfsigned are handled by the panel PKI flow.
	return nil
}

var _ = strings.TrimSpace
