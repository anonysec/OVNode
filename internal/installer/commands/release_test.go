package commands

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLatestReleaseReadsTheTag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/anonysec/OVNode/releases/latest" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"tag_name":"v2.0.0"}`))
	}))
	defer srv.Close()
	old := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = old }()

	got, err := latestRelease("anonysec/OVNode")
	if err != nil {
		t.Fatal(err)
	}
	if got != "2.0.0" {
		t.Fatalf("version = %q, want 2.0.0", got)
	}
}

func TestLatestReleaseRejectsBadPayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"not-a-version"}`))
	}))
	defer srv.Close()
	old := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = old }()

	if _, err := latestRelease("anonysec/OVNode"); err == nil {
		t.Fatal("unusable tag was accepted")
	}
}

// A pinned release must never touch the network: update -v 2.0.0 works on a
// box with no route to the API.
func TestResolveVersionKeepsAPin(t *testing.T) {
	old := githubAPI
	githubAPI = "http://127.0.0.1:1"
	defer func() { githubAPI = old }()

	c := &Config{Version: "2.0.0", Repo: "anonysec/OVNode"}
	if err := c.resolveVersion(); err != nil {
		t.Fatalf("pinned version resolved over the network: %v", err)
	}
	if c.Version != "2.0.0" {
		t.Fatalf("version = %q", c.Version)
	}
}

func TestResolveVersionFillsLatest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v2.0.0"}`))
	}))
	defer srv.Close()
	old := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = old }()

	c := &Config{Version: "latest", Repo: "anonysec/OVNode"}
	if err := c.resolveVersion(); err != nil {
		t.Fatal(err)
	}
	if c.Version != "2.0.0" {
		t.Fatalf("version = %q, want 2.0.0", c.Version)
	}
}
