package commands

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// githubAPI is a variable so the tests can point resolution at a stub.
var githubAPI = "https://api.github.com"

// resolveVersion turns Version "latest" (the default) into a concrete release.
// It runs once per install/update, before any download: the previous code
// built .../download/vlatest/... and always failed with a 404.
func (c *Config) resolveVersion() error {
	if c.Version != "" && c.Version != "latest" {
		return nil
	}
	v, err := latestRelease(c.Repo)
	if err != nil {
		return err
	}
	c.Version = v
	return nil
}

// latestRelease reads the tag of the newest published release.
func latestRelease(repo string) (string, error) {
	url := strings.TrimRight(githubAPI, "/") + "/repos/" + repo + "/releases/latest"
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "ovnode-installer")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("could not reach the release API: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("release API answered %s for %s", resp.Status, repo)
	}
	var body struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("could not read the release API response: %w", err)
	}
	v := strings.TrimSpace(strings.TrimPrefix(body.TagName, "v"))
	if !validReleaseVersion(v) {
		return "", fmt.Errorf("release API returned an unusable tag %q", body.TagName)
	}
	return v, nil
}
