package cmd

import (
	"github.com/spf13/cobra"
)

const (
	secretsManagerCommandName = "secrets-manager"
	secretsManagerAlias       = "sm"
)

// secretsManagementCommands live both at the top level (`infisical run`) and under the
// Secrets Management namespace (`infisical secrets-manager run`). Each entry is a constructor
// because a cobra command can only have one parent, so every registration needs its own instance.
var secretsManagementCommands = []func() *cobra.Command{
	buildRunCmd,
	buildExportCmd,
	buildSecretsCmd,
	buildDynamicSecretsCmd,
}

// hiddenUnderSecretsManager are kept working under `secrets-manager` for backwards compatibility,
// but no longer listed in its help. The top-level copies are unchanged.
var hiddenUnderSecretsManager = [][]string{
	{"secrets", "generate-example-env"},
	{"secrets", "agent-proxy"},
	{"agent-proxy"},
}

func init() {
	secretsManagerCmd := &cobra.Command{
		Use:     secretsManagerCommandName,
		Aliases: []string{secretsManagerAlias},
		Short:   "Secrets Management commands (secrets, projects, dynamic-secrets, run, export)",
		Example: `  infisical secrets-manager secrets get DB_PASSWORD
  infisical secrets-manager projects create --name my-app
  infisical secrets-manager dynamic-secrets lease create my-db-credentials
  infisical secrets-manager run --env=dev -- npm run dev
  infisical secrets-manager export --env=prod --format=json`,
		DisableFlagsInUseLine: true,
		// Without Args and Run, cobra prints help and exits 0 for `infisical secrets-manager rnu`,
		// so a typo would look like success. NoArgs turns it into an "unknown command" error instead.
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
		// No PersistentPreRun here: cobra runs only the nearest one, and the root's resolves
		// the domain, profile and org for every command.
	}

	for _, buildCommand := range secretsManagementCommands {
		RootCmd.AddCommand(buildCommand())
		secretsManagerCmd.AddCommand(buildCommand())
	}

	secretsManagerCmd.AddCommand(buildAgentProxyCmd())
	secretsManagerCmd.AddCommand(buildProjectsCmd())

	for _, path := range hiddenUnderSecretsManager {
		if cmd, rest, err := secretsManagerCmd.Find(path); err == nil && len(rest) == 0 {
			cmd.Hidden = true
		}
	}

	RootCmd.AddCommand(secretsManagerCmd)
}
