package pairing

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestPairingConcurrent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OpenVpnRoot", dir)
	t.Setenv("DataDir", dir+"/ovnode-data")
	os.MkdirAll(filepath.Join(dir, "ovnode-data", "state"), 0o755)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pid := "panel-a"
			if i%2 == 1 {
				pid = "panel-b"
			}
			_ = Enforce(pid)
		}(i)
	}
	wg.Wait()
}
