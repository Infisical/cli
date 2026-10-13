//go:build !windows

package cmd

// runAgentAsWindowsService never applies outside Windows.
func runAgentAsWindowsService(configPath string) (bool, int) {
	return false, 0
}
