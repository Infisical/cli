//go:build linux

package cmd

import (
	"os"

	"github.com/Infisical/infisical-merge/packages/sandbox"
	"github.com/spf13/cobra"
)

// sandboxSupervisorCmd is an internal, hidden entry point. It is NOT meant to be run by users: the
// Linux hard-fence path re-execs the CLI binary as this subcommand inside the bwrap network namespace,
// where it brings loopback up, bridges the child's loopback proxy port to the parent's proxy unix
// socket, and then execs the agent. Everything after `--` is the agent command.
var sandboxSupervisorCmd = &cobra.Command{
	Use:                   sandbox.SupervisorSubcommand,
	Hidden:                true,
	DisableFlagParsing:    false,
	FParseErrWhitelist:    cobra.FParseErrWhitelist{UnknownFlags: true},
	DisableFlagsInUseLine: true,
	// Override the root PersistentPreRun so this internal re-exec does NOT run the human-facing
	// preamble (update check, package-repo notice, keyring read). Those make a network call, and this
	// runs inside an empty network namespace where that call would waste the timeout and print stray
	// notices. The supervisor needs none of it; it only brings loopback up, bridges, and execs.
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
