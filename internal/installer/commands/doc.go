// Package commands implements ovnode install, update and uninstall.
//
// Bash remains the default path until Stage 3. Commands here reproduce the
// bash contract: flag names, OVN_* variables, file locations, unit names,
// file permissions, exit codes and rollback ordering.
package commands
