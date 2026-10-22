package cmd

import (
	"github.com/spf13/cobra"
)

const smCommandName = "sm"

// secretsManagementCommands live both at the top level (`infisical run`) and under the
// Secrets Management namespace (`infisical sm run`). Each entry is a constructor because a
// cobra command can only have one parent, so every registration needs its own instance.
var secretsManagementCommands = []func() *cobra.Command{
	buildRunCmd,
	buildExportCmd,
	buildSecretsCmd,
	buildDynamicSecretsCmd,
}

func init() {
	smCmd := &cobra.Command{
		Use:   smCommandName,
		Short: "Secrets Management commands (run, export, secrets, dynamic-secrets, agent-proxy, projects)",
		Example: `  infisical sm run --env=dev -- npm run dev
  infisical sm export --env=prod --format=json
  infisical sm secrets get DB_PASSWORD
  infisical sm dynamic-secrets lease create my-db-credentials
  infisical sm agent-proxy run --env=dev --path=/myapp -- claude
  infisical sm projects create --name my-app`,
		DisableFlagsInUseLine: true,
		// Without Args and Run, cobra prints help and exits 0 for `infisical sm rnu`, so a typo
		// would look like success. NoArgs turns it into an "unknown command" error instead.
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
		// No PersistentPreRun here: cobra runs only the nearest one, and the root's resolves
		// the domain, profile and org for every command.
	}

	for _, buildCommand := range secretsManagementCommands {
		RootCmd.AddCommand(buildCommand())
		smCmd.AddCommand(buildCommand())
	}

	smCmd.AddCommand(buildAgentProxyCmd())
	smCmd.AddCommand(buildProjectsCmd())

	RootCmd.AddCommand(smCmd)
}
