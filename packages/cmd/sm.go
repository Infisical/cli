package cmd

import (
	"fmt"
	"os"
	"path/filepath"
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

// deleteProject resolves the project a delete acts on, in the order the deletes themselves use
// (--project-slug, --projectId, INFISICAL_PROJECT_ID, then the workspace file), so the question can
// name it. pinned is set when no flag chose the project. ok is false when nothing resolves; the
// command then reports that itself.
func deleteProject(cmd *cobra.Command) (phrase, pinned string, ok bool) {
	if slug, _ := cmd.Flags().GetString("project-slug"); slug != "" {
		return "in project " + util.SuggestedValue(slug, "project-slug"), "", true
	}
	if id, _ := cmd.Flags().GetString("projectId"); id != "" {
		return "in project " + util.SuggestedValue(id, "project-id"), "", true
	}
	if id := strings.TrimSpace(os.Getenv(util.INFISICAL_PROJECT_ID_NAME)); id != "" {
		return fmt.Sprintf("in project %s (from %s)", util.SuggestedValue(id, "project-id"), util.INFISICAL_PROJECT_ID_NAME), id, true
	}
	file, err := util.FindWorkspaceConfigFile()
	if err != nil {
		return "", "", false
	}
	workspace, err := util.GetWorkSpaceFromFilePath(filepath.Dir(file))
	if err != nil || workspace.WorkspaceId == "" {
		return "", "", false
	}
	return fmt.Sprintf("in project %s (from %s)", util.SuggestedValue(workspace.WorkspaceId, "project-id"), file), workspace.WorkspaceId, true
}

func describeSecretsDelete(cmd *cobra.Command, args []string) (destructiveAction, bool) {
	project, pinned, ok := deleteProject(cmd)
	if len(args) == 0 || !ok {
		return destructiveAction{}, false
	}
	where := fmt.Sprintf("from the %s environment at %s %s", util.SuggestedValue(util.ResolveEnvironmentName(cmd), "env"),
		util.SuggestedValue(util.ResolveSecretPath(cmd), "path"), project)
	names := make([]string, len(args))
	for i, arg := range args {
		names[i] = util.SuggestedValue(arg, "name")
	}
	if len(args) == 1 {
		return destructiveAction{Target: "secret " + quoted(args[0], "name"), Expected: args[0], Label: "the secret name",
			Description: fmt.Sprintf("secret %s %s", names[0], where), ProjectID: pinned}, true
	}
	return destructiveAction{Target: fmt.Sprintf("%d secrets", len(args)), Expected: strconv.Itoa(len(args)), Label: "the number of secrets",
		Description: fmt.Sprintf("%d secrets (%s) %s", len(args), strings.Join(names, ", "), where), ProjectID: pinned}, true
}

func describeFolderDelete(cmd *cobra.Command, args []string) (destructiveAction, bool) {
	project, pinned, ok := deleteProject(cmd)
	name, _ := cmd.Flags().GetString("name")
	if name == "" || !ok {
		return destructiveAction{}, false
	}
	path, _ := cmd.Flags().GetString("path")
	return destructiveAction{Target: "folder " + quoted(name, "name"), Expected: name, Label: "the folder name",
		Description: fmt.Sprintf("folder %s at %s in the %s environment %s, with every secret and folder inside it",
			util.SuggestedValue(name, "name"), util.SuggestedValue(path, "path"), util.SuggestedValue(util.ResolveEnvironmentName(cmd), "env"), project),
		ProjectID: pinned}, true
}

func describeLeaseDelete(cmd *cobra.Command, args []string) (destructiveAction, bool) {
	project, pinned, ok := deleteProject(cmd)
	if len(args) != 1 || !ok {
		return destructiveAction{}, false
	}
	return destructiveAction{Target: "lease " + quoted(args[0], "lease-id"), Expected: args[0], Label: "the lease ID",
		Description: fmt.Sprintf("dynamic secret lease %s %s, which revokes its credentials", util.SuggestedValue(args[0], "lease-id"), project),
		ProjectID:   pinned}, true
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
