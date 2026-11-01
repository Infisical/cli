//go:build linux

package cmd

import (
	"os"

	"github.com/Infisical/infisical-merge/packages/sandbox"
	"github.com/spf13/cobra"
)

// sandboxSupervisorCmd is an internal, hidden entry point: the Linux hard-fence path re-execs the CLI
// as this subcommand inside the bwrap netns to run the in-namespace bridge. Not for users.
var sandboxSupervisorCmd = &cobra.Command{
	Use:                   sandbox.SupervisorSubcommand,
	Hidden:                true,
	DisableFlagsInUseLine: true,
	// No-op override of root's PersistentPreRun: skip the update check / notices / keyring read (a
	// network call) that would otherwise run inside the network-less namespace.
	PersistentPreRun: func(_ *cobra.Command, _ []string) {},
	Run: func(cmd *cobra.Command, args []string) {
		probe, _ := cmd.Flags().GetBool("probe")
		port, _ := cmd.Flags().GetInt("port")
		socket, _ := cmd.Flags().GetString("socket")
		os.Exit(sandbox.RunSupervisor(probe, port, socket, args))
	},
}

func init() {
	sandboxSupervisorCmd.Flags().Bool("probe", false, "capability probe: bring loopback up and exit")
	sandboxSupervisorCmd.Flags().Int("port", 0, "loopback port to bridge from")
	sandboxSupervisorCmd.Flags().String("socket", "", "proxy unix socket to bridge to")
	RootCmd.AddCommand(sandboxSupervisorCmd)
}
