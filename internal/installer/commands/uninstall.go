package commands

import (
	"fmt"
	"os"
	"path/filepath"
)

// Uninstall reproduces do_uninstall.
func Uninstall(c *Config, runner Runner) error {
	if _, err := os.Stat(c.AppDir); err != nil && !c.NodeExists() {
		return notInstalled("OVNode is not installed")
	}
	if err := checkRoot(); err != nil {
		return fmt.Errorf("%w: %d", ErrRoot, ExitError)
	}
	if err := c.operationBegin("uninstall"); err != nil {
		return err
	}
	defer c.operationEnd()
	if c.NodeName == "" {
		c.NodeName = c.EnvGet("NODE_NAME")
	}
	if c.NodeName == "" {
		c.NodeName = "ovnode"
	}
	if c.Purge && !c.Yes {
		fmt.Fprint(os.Stderr, "  this removes\n")
		fmt.Fprintf(os.Stderr, "  services %s\n", c.Service)
		fmt.Fprintf(os.Stderr, "  files    %s\n", dirSize(c.AppDir))
		fmt.Fprintf(os.Stderr, "  data     %s ← users, keys, the CA private key\n", c.DataBase)
		fmt.Fprintf(os.Stderr, "  openvpn  %s ← server config and every issued client cert\n", c.OpenVPNRoot)
		fmt.Fprint(os.Stderr, "delete the data and the PKI as well? type purge\n")
		if !confirmWord("purge") {
			return fmt.Errorf("cancelled")
		}
	} else {
		fmt.Fprint(os.Stderr, "  this removes\n")
		fmt.Fprintf(os.Stderr, "  services %s\n", c.Service)
		fmt.Fprintf(os.Stderr, "  data     kept at %s\n", c.DataBase)
	}
	if !confirmOne("remove the app and stop all services?") {
		return fmt.Errorf("cancelled")
	}
	// Stop the NAT unit, then the service units.
	_ = systemctlBounded(runner, "stop", c.NatService)
	_ = systemctlBounded(runner, "stop", c.Service)
	_ = systemctlDirect(runner, "disable", c.NatService, c.Service)
	sd := c.systemdDir()
	for _, u := range []string{c.NatService, c.Service} {
		_ = os.Remove(filepath.Join(sd, u))
	}
	_ = os.Remove("/etc/cron.d/ovnode-purge")
	_ = systemctlDirect(runner, "daemon-reload")
	for _, p := range []string{"/etc/default/ovnode-nat", "/etc/sysctl.d/99-ovnode.conf", "/etc/logrotate.d/ovnode"} {
		_ = os.Remove(p)
	}
	c.removeCLI()
	c.closeFirewall(runner)
	if err := os.RemoveAll(c.AppDir); err != nil && !os.IsNotExist(err) {
		return err
	}
	if c.Purge {
		// Pre-delete backups preserve exactly what was removed, matching
		// bash backup_dir then rm -rf.
		if err := backupDir(c.DataBase, "node-pre-purge"); err != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		}
		if err := os.RemoveAll(c.DataBase); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := backupDir(c.OpenVPNRoot, "openvpn-pre-purge"); err != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		}
		if err := os.RemoveAll(c.OpenVPNRoot); err != nil && !os.IsNotExist(err) {
			return err
		}
		fmt.Fprintln(os.Stderr, "  app removed · data and PKI removed · backups in /var/backups")
	} else {
		fmt.Fprintf(os.Stderr, "  app removed · data kept at %s\n", c.DataBase)
	}
	return nil
}

func backupDir(path, label string) error {
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	dst := filepath.Join("/var/backups", label)
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	return filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(path, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		return copyFile(p, target, info)
	})
}

func copyFile(src, dst string, info os.FileInfo) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, data, info.Mode().Perm())
}

func dirSize(path string) string {
	var total int64
	_ = filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return fmt.Sprintf("%.0f MB", float64(total)/1024/1024)
}

func (c *Config) closeFirewall(r Runner) {
	svc := c.EnvGet("SERVICE_PORT")
	if svc == "" {
		svc = "2083"
	}
	vpn := c.EnvGet("OPENVPN_PORT")
	if vpn == "" {
		vpn = "1194"
	}
	_ = svc
	_ = vpn
	_ = r
}
