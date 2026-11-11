package commands

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"

	"ovnode/internal/fsx"
)

func (c *Config) ensureRuntimeIdentity(r Runner) error {
	userName := c.RuntimeUser
	groupName := c.RuntimeGroup
	// Existing .env wins (update path reads it back).
	if v := c.EnvGet("OVNODE_RUNTIME_USER"); v != "" {
		userName = v
	}
	if v := c.EnvGet("OVNODE_RUNTIME_GROUP"); v != "" {
		groupName = v
	}
	confUser, confGroup := readServerConfUserGroup(c.OpenVPNRoot)
	if userName == "" {
		userName = confUser
	}
	if groupName == "" {
		groupName = confGroup
	}
	if userName == "" && groupName == "" {
		if _, err := os.Stat(filepath.Join(c.AppDir, ".env")); err == nil {
			userName, groupName = "nobody", "nogroup"
		} else {
			userName, groupName = "ovnode-vpn", "ovnode-vpn"
		}
	} else if userName == "" {
		userName = "nobody"
	} else if groupName == "" {
		g, err := lookupGroupOf(userName)
		if err != nil {
			return fmt.Errorf("unknown runtime user: %s", userName)
		}
		groupName = g
	}
	c.RuntimeUser, c.RuntimeGroup = userName, groupName
	if !regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`).MatchString(userName) {
		return &UsageError{"Invalid runtime user"}
	}
	if !regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`).MatchString(groupName) {
		return &UsageError{"Invalid runtime group"}
	}
	if _, err := lookupGroup(groupName); err != nil {
		if groupName != "ovnode-vpn" {
			return fmt.Errorf("unknown runtime group: %s", groupName)
		}
		if err := r.Run("groupadd", "--system", groupName); err != nil {
			return fmt.Errorf("could not create runtime group: %w", err)
		}
	}
	if _, err := lookupUser(userName); err != nil {
		if userName != "ovnode-vpn" {
			return fmt.Errorf("unknown runtime user: %s", userName)
		}
		if err := r.Run("useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "-g", groupName, userName); err != nil {
			return fmt.Errorf("could not create runtime user: %w", err)
		}
	}
	return nil
}

func readServerConfUserGroup(root string) (string, string) {
	data, err := os.ReadFile(filepath.Join(root, "server", "server.conf"))
	if err != nil {
		return "", ""
	}
	var u, g string
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "user":
			if u == "" {
				u = strings.Trim(f[1], `"'`)
			}
		case "group":
			if g == "" {
				g = strings.Trim(f[1], `"'`)
			}
		}
	}
	return u, g
}

func lookupGroup(name string) (string, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return "", err
	}
	return g.Name, nil
}

func lookupUser(name string) (*user.User, error) { return user.Lookup(name) }

func lookupGroupOf(name string) (string, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return "", err
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		return "", err
	}
	return g.Name, nil
}

// fetchRelease mirrors fetch_release_binary (verify + install).
func (c *Config) fetchRelease(dest string) error {
	// Stage 3 keeps the download in bash; Stage 2's Go path only installs
	// what the bootstrap already placed at $APP_DIR/ovnode, or when called
	// from a tree that already has it.
	if info, err := os.Stat(dest); err == nil && !info.IsDir() && info.Mode().Perm()&0o111 != 0 {
		return nil
	}
	if c.Local {
		return nil
	}
	// Without a bootstrap download there is nothing honest to do: the fake
	// release fixture (test-installer-go.sh) only exercises the harness. Return the
	// same failures bash would.
	repo := c.Repo
	url := "https://github.com/" + repo + "/releases/download/v" + c.Version + "/ovnode-linux-" + archName()
	sumsURL := "https://github.com/" + repo + "/releases/download/v" + c.Version + "/SHA256SUMS"
	work, err := os.MkdirTemp("", "ovnode.XXXXXX")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	asset := "ovnode-linux-" + archName()
	if err := download(url, filepath.Join(work, asset)); err != nil {
		return fmt.Errorf("no release file for v%s, see https://github.com/%s/releases", c.Version, repo)
	}
	if err := download(sumsURL, filepath.Join(work, "SHA256SUMS")); err != nil {
		return fmt.Errorf("could not download SHA256SUMS for v%s, refusing to install an unverified release", c.Version)
	}
	if err := verifySum(work, asset); err != nil {
		return fmt.Errorf("checksum verification failed for %s (v%s): %w", asset, c.Version, err)
	}
	if err := os.MkdirAll(c.AppDir, 0o755); err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(work, asset))
	if err != nil {
		return err
	}
	return os.WriteFile(dest, data, 0o755)
}

var _ = fsx.EnvOr
