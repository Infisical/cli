package cmd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Infisical/infisical-merge/packages/util"
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

// Deletes under `secrets-manager` ask for confirmation (see CLI.md). The legacy top-level copies keep
// deleting without asking, so existing scripts that use them are unaffected.
var confirmedUnderSecretsManager = map[string]func(cmd *cobra.Command, args []string) (destructiveAction, bool){
	"secrets delete":               describeSecretsDelete,
	"secrets folders delete":       describeFolderDelete,
	"dynamic-secrets lease delete": describeLeaseDelete,
}

func describeSecretsDelete(cmd *cobra.Command, args []string) (destructiveAction, bool) {
	if len(args) == 0 {
		return destructiveAction{}, false
	}
	where := fmt.Sprintf("from the %s environment at %s", util.ResolveEnvironmentName(cmd), util.ResolveSecretPath(cmd))
	if len(args) == 1 {
		return destructiveAction{Target: fmt.Sprintf("secret %q", args[0]), Expected: args[0], Label: "the secret name",
			Description: fmt.Sprintf("secret %s %s", args[0], where)}, true
	}
	return destructiveAction{Target: fmt.Sprintf("%d secrets", len(args)), Expected: strconv.Itoa(len(args)), Label: "the number of secrets",
		Description: fmt.Sprintf("%d secrets (%s) %s", len(args), strings.Join(args, ", "), where)}, true
}

func describeFolderDelete(cmd *cobra.Command, args []string) (destructiveAction, bool) {
	name, _ := cmd.Flags().GetString("name")
	if name == "" {
		return destructiveAction{}, false
	}
	path, _ := cmd.Flags().GetString("path")
	return destructiveAction{Target: fmt.Sprintf("folder %q", name), Expected: name, Label: "the folder name",
		Description: fmt.Sprintf("folder %s at %s in the %s environment, with every secret and folder inside it", name, path, util.ResolveEnvironmentName(cmd))}, true
}

func describeLeaseDelete(cmd *cobra.Command, args []string) (destructiveAction, bool) {
	if len(args) != 1 {
		return destructiveAction{}, false
	}
	return destructiveAction{Target: fmt.Sprintf("lease %q", args[0]), Expected: args[0], Label: "the lease ID",
		Description: fmt.Sprintf("dynamic secret lease %s, which revokes its credentials", args[0])}, true
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

	for path, describe := range confirmedUnderSecretsManager {
		cmd, rest, err := secretsManagerCmd.Find(strings.Fields(path))
		if err != nil || len(rest) != 0 {
			panic(fmt.Sprintf("secrets-manager %s is not registered", path))
		}
		requireConfirmation(cmd, describe)
	}

	for _, path := range hiddenUnderSecretsManager {
		if cmd, rest, err := secretsManagerCmd.Find(path); err == nil && len(rest) == 0 {
			cmd.Hidden = true
		}
	}

	RootCmd.AddCommand(secretsManagerCmd)
}
