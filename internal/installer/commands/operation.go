package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

func (c *Config) operationBegin(name string) error {
	lock := filepath.Join(c.DataBase, ".operation.lock")
	if err := os.MkdirAll(c.DataBase, 0o755); err != nil {
		return err
	}
	if err := os.Mkdir(lock, 0o700); err == nil {
		_ = os.WriteFile(filepath.Join(lock, "pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644)
		_ = os.WriteFile(filepath.Join(lock, "action"), []byte(name+"\n"), 0o644)
		return nil
	}
	ownerBytes, _ := os.ReadFile(filepath.Join(lock, "pid"))
	owner := string(ownerBytes)
	if pid, err := strconv.Atoi(owner); err == nil && killProcess(pid) {
		return fmt.Errorf("Another maintenance operation is running (process %d). Try again later.", pid)
	}
	if owner != "" {
		_ = os.RemoveAll(lock)
		if err := os.Mkdir(lock, 0o700); err == nil {
			_ = os.WriteFile(filepath.Join(lock, "pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644)
			_ = os.WriteFile(filepath.Join(lock, "action"), []byte(name+"\n"), 0o644)
			return nil
		}
	}
	return fmt.Errorf("Another maintenance operation is running. Try again later.")
}

func (c *Config) operationEnd() {
	_ = os.RemoveAll(filepath.Join(c.DataBase, ".operation.lock"))
}
