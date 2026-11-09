package commands

import "os"

// GetStderr returns os.Stderr for output helpers.
func GetStderr() *os.File { return os.Stderr }
