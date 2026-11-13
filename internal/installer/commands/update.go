package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"ovnode/internal/assets"
	"ovnode/internal/installer"
	"ovnode/internal/version"
)

type updateCtx struct {
	from, safety, identity string
}

// stageStaticAssets carries everything the new tree needs besides the binary:
// the identity file, the version marker and the embedded shell scripts. The
// update renames the staged directory into place, so without this the service
// starts with no EnvironmentFile and systemd refuses to spawn it.
func stageStaticAssets(oldDir, stage string) error {
	for _, item := range []struct {
		name string
		mode os.FileMode
	}{{".env", 0o600}, {"VERSION", 0o644}, {installMarker, 0o644}} {
		data, err := os.ReadFile(filepath.Join(oldDir, item.name))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if err := os.WriteFile(filepath.Join(stage, item.name), data, item.mode); err != nil {
			return err
		}
	}
	return writeStagedAssets(stage)
}

// writeStagedAssets writes the shell files embedded in the release being
// installed, not the ones in the process doing the update. Running the staged
// binary is what keeps install.sh, ovnode.sh and lib.sh in step with the new
// agent; the running binary's copy is a fallback for a local update that has
// no downloaded binary.
func writeStagedAssets(stage string) error {
	bin := filepath.Join(stage, "ovnode")
	if info, err := os.Stat(bin); err == nil && !info.IsDir() && info.Mode().Perm()&0o111 != 0 {
		out, err := exec.Command(bin, "assets", "write", "--dest", stage).CombinedOutput()
		if err != nil {
			return fmt.Errorf("staged release cannot write its assets: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	_, err := assets.Write(stage)
	return err
}

// Update reproduces do_update, including the failover ordering.
func Update(c *Config, runner Runner) error {
	if _, err := os.Stat(c.AppDir); err != nil {
		return notInstalled("(%s missing)", c.AppDir)
	}
	if _, err := os.Stat(c.AgentBin()); err != nil {
		return fmt.Errorf("the node agent binary is missing (%s), reinstall instead of updating", c.AgentBin())
	}
	if err := checkRoot(); err != nil {
		return fmt.Errorf("%w: %d", ErrRoot, ExitError)
	}
	if !c.Local {
		if err := c.resolveVersion(); err != nil {
			return err
		}
	}
	if err := c.operationBegin("update"); err != nil {
		return err
	}
	defer c.operationEnd()
	c.recoverEnvFromDotEnv()
	// [1/6] Backup — safety bundle before anything else.
	safety, err := installer.Bundle(c.AppDir, c.DataDir(), c.OpenVPNRoot, "/var/backups", c.NodeName, version.Version)
	if err != nil {
		return fmt.Errorf("could not create the mandatory state safety snapshot: %w", err)
	}
	from := version.Version
	identity := installer.IdentitySHA(c.NodeName, c.APIKey)
	u := &updateCtx{from: from, safety: safety, identity: identity}
	_ = u
	// [2/6] Stage — fetch and stage the candidate.
	stage := c.AppDir + ".staging"
	_ = os.RemoveAll(stage)
	if err := os.MkdirAll(stage, 0o755); err != nil {
		return err
	}
	if err := c.fetchRelease(filepath.Join(stage, "ovnode")); err != nil {
		return err
	}
	if err := stageStaticAssets(c.AppDir, stage); err != nil {
		return err
	}
	// [3/6] Maintenance
	marker := u.marker(c)
	if err := os.MkdirAll(filepath.Dir(marker), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(marker, []byte{}, 0o600); err != nil {
		return err
	}
	_ = installer.WriteUpdateState(u.statePath(c), "activating", from, c.Version, safety, identity)
	// [4/6] Activate — atomic rename, previous is kept for failover.
	previous := c.AppDir + ".previous"
	_ = os.RemoveAll(previous)
	if err := os.Rename(c.AppDir, previous); err != nil {
		// Previous tree vanished mid-flight: maintenance stays, journal says so.
		_ = installer.WriteUpdateState(u.statePath(c), "recovery_required", from, c.Version, safety, identity)
		return fmt.Errorf("could not activate the staged release; the previous release remains active and state was not changed: %d", ExitError)
	}
	if err := os.Rename(stage, c.AppDir); err != nil {
		// Put the old tree back, clear the marker — rollback contract.
		state := "failed_over"
		if _, err := os.Stat(c.AppDir); err != nil && os.IsNotExist(err) {
			state = "recovery_required"
		}
		_ = os.Remove(marker)
		_ = installer.WriteUpdateState(u.statePath(c), state, from, c.Version, safety, identity)
		if _, err := os.Stat(c.AppDir); err != nil {
			_ = os.Rename(previous, c.AppDir)
		}
		return fmt.Errorf("could not activate or restore release files; writes remain blocked; run: ovnode recover-update: %d", ExitError)
	}
	// Candidate starts.
	if err := c.writeSystemdUnit(runner); err != nil {
		return err
	}
	if err := c.writeNatUnit(runner); err != nil {
		return err
	}
	_ = c.installAgentBinary()
	if err := systemctlBounded(runner, "restart", c.Service); err != nil {
		return failover(c, u, runner)
	}
	// [5/6] Verify
	scheme := "http"
	if c.TLSMethod != "none" {
		scheme = "https"
	}
	healthURL := scheme + "://127.0.0.1:" + c.Port + "/sync/health"
	if !healthCheck(healthURL, 60) {
		return failover(c, u, runner)
	}
	// [6/6] Commit
	_ = os.Remove(marker)
	_ = c.setupNAT(runner)
	_ = c.setupLogrotate()
	if !healthCheck(healthURL, 60) {
		_ = os.WriteFile(marker, []byte{}, 0o600)
		_ = installer.WriteUpdateState(u.statePath(c), "recovery_required", from, c.Version, safety, identity)
		return fmt.Errorf("candidate passed verification but failed its final check; writes are blocked; run: ovnode recover-update")
	}
	_ = installer.WriteUpdateState(u.statePath(c), "committed", from, c.Version, safety, identity)
	_ = os.RemoveAll(previous)
	c.installCLI()
	return nil
}

func failover(c *Config, u *updateCtx, runner Runner) error {
	// Same ordering as node_failover: stop, restore previous + state, restart.
	_ = systemctlBounded(runner, "stop", c.Service)
	previous := c.AppDir + ".previous"
	stage := c.AppDir + ".staging"
	_ = os.RemoveAll(stage)
	_ = os.Rename(c.AppDir, stage)
	if err := os.Rename(previous, c.AppDir); err != nil {
		_ = installer.WriteUpdateState(u.statePath(c), "recovery_required", u.from, c.Version, u.safety, u.identity)
		return fmt.Errorf("automatic failover could not restore the previous release; snapshot: %s", u.safety)
	}
	if err := installer.Restore(u.safety, c.AppDir, c.DataBase, c.OpenVPNRoot); err != nil {
		_ = installer.WriteUpdateState(u.statePath(c), "recovery_required", u.from, c.Version, u.safety, u.identity)
		return fmt.Errorf("previous code was restored but state could not be restored")
	}
	if err := systemctlBounded(runner, "restart", c.Service); err != nil {
		_ = installer.WriteUpdateState(u.statePath(c), "recovery_required", u.from, c.Version, u.safety, u.identity)
		return fmt.Errorf("previous release restored but will not start")
	}
	scheme := "http"
	if c.TLSMethod != "none" {
		scheme = "https"
	}
	healthURL := scheme + "://127.0.0.1:" + c.Port + "/sync/health"
	if healthCheck(healthURL, 60) {
		_ = os.Remove(u.marker(c))
		_ = installer.WriteUpdateState(u.statePath(c), "failed_over", u.from, c.Version, u.safety, u.identity)
		return fmt.Errorf("update failed over safely to v%s; state was restored from %s; check logs before retrying", u.from, u.safety)
	}
	_ = installer.WriteUpdateState(u.statePath(c), "recovery_required", u.from, c.Version, u.safety, u.identity)
	return fmt.Errorf("failover did not restore health either; state backup at %s", u.safety)
}

func (u *updateCtx) marker(c *Config) string {
	return filepath.Join(c.DataDir(), "update-maintenance")
}

func (u *updateCtx) statePath(c *Config) string {
	return filepath.Join(c.DataBase, "update-state.json")
}

func (c *Config) recoverEnvFromDotEnv() {
	if c.NodeName == "" {
		c.NodeName = c.EnvGet("Instance")
	}
	if c.NodeName == "" {
		c.NodeName = "ovnode"
	}
	if c.Port == "" {
		c.Port = c.EnvGet("ApiPort")
	}
	if c.Port == "" {
		c.Port = "2083"
	}
	// Identity is never regenerated on update.
	c.APIKey = c.EnvGet("ApiKey")
	// Keep the install's TLS material unless the caller passed one.
	if c.TLSKey == "" {
		c.TLSKey = c.EnvGet("TlsKeyFile")
	}
	if c.TLSCert == "" {
		c.TLSCert = c.EnvGet("TlsCertFile")
	}
	if os.Getenv("TlsMethod") == "" {
		if c.TLSCert != "" && c.TLSKey != "" {
			c.TLSMethod = "custom"
		}
	}
	if !c.IPv6 && c.EnvGet("EnableIpv6") == "1" {
		c.IPv6 = true
	}
	_ = strings.TrimSpace
}
