//go:build !windows

package cmd

import "errors"

// The Windows service commands check the platform before calling these, so outside Windows they only report it.
var errAgentWindowsServiceUnsupported = errors.New("Windows service management is only supported on Windows")

// runAgentAsWindowsService never applies outside Windows.
func runAgentAsWindowsService(configPath string) (bool, int) {
	return false, 0
}

func checkAgentServiceAdministrator() error             { return errAgentWindowsServiceUnsupported }
func installAgentService(name, configPath string) error { return errAgentWindowsServiceUnsupported }
func uninstallAgentService(name string) error           { return errAgentWindowsServiceUnsupported }
func startAgentService(name string) error               { return errAgentWindowsServiceUnsupported }
func stopAgentService(name string) error                { return errAgentWindowsServiceUnsupported }
