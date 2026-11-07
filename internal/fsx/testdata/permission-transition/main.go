// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"

	"ovnode/internal/fsx"
	"ovnode/internal/logging"
	"ovnode/internal/store"
)

func init() { runtime.LockOSThread() }

func main() {
	mode, path := os.Args[1], os.Args[2]
	var err error
	switch mode {
	case "transition":
		err = fsx.SetPermissions(path, 0o640, 0, 65533)
	case "repair":
		err = store.FixRuntimePermissions(path)
	case "mkdir":
		err = fsx.MkdirAllNoFollow(path, 0o750)
	case "exchange":
		if err = os.Rename(path, path+"-original"); err == nil {
			err = os.Rename(os.Args[3], path)
		}
	case "read":
		var data []byte
		data, err = os.ReadFile(path)
		if err == nil {
			fmt.Print(string(data))
		}
	case "repair-umask":
		syscall.Umask(0o077)
		err = store.FixRuntimePermissions(path)
	case "append-log":
		logging.Event(path, "restrictive-umask runtime append")
		var data []byte
		data, err = os.ReadFile(path)
		if err == nil && !strings.Contains(string(data), "restrictive-umask runtime append") {
			err = fmt.Errorf("dropped UID did not append its event")
		}
	case "probe":
		status := os.NewFile(3, "status")
		resume := os.NewFile(4, "resume")
		f, openErr := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if openErr != nil {
			fmt.Fprintln(status, "denied")
			return
		}
		defer f.Close()
		fmt.Fprintln(status, "opened")
		var byte [1]byte
		if _, err = resume.Read(byte[:]); err == nil {
			_, err = f.WriteString("descriptor-write-after-transition\n")
		}
		if err == nil {
			fmt.Fprintln(status, "wrote after final mode")
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
