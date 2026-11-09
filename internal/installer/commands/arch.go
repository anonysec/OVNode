package commands

import "runtime"

func archName() string {
	if runtime.GOARCH == "amd64" {
		return "amd64"
	}
	if runtime.GOARCH == "arm64" {
		return "arm64"
	}
	return runtime.GOARCH
}
