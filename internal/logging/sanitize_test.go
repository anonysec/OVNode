package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEventStripsNewlines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.log")
	Event(path, "CN=%s bad\nline\rhere", "u\n1")
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "\nu1") || strings.Contains(string(data), "\nline") {
		t.Fatalf("newline survived: %q", string(data))
	}
	if !strings.Contains(string(data), "CN=u1 badlinehere") {
		t.Fatalf("unexpected: %q", string(data))
	}
}
