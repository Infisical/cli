/*
Copyright (c) 2026 Infisical Inc.
*/
package cmd

import (
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/spf13/cobra"
)

// namespaceSecretsCmd gives the `secrets` instance under `secrets-manager` the CLI.md shape: `get`
// without names lists, and `create` and `update` replace the upsert `set`, which keeps working but
// leaves the help. The top-level `infisical secrets` is a separate instance and keeps its old shape.
func namespaceSecretsCmd(secretsCmd *cobra.Command) {
	get, _, err := secretsCmd.Find([]string{"get"})
	if err != nil || get == secretsCmd {
		panic("secrets-manager secrets get is not registered")
	}
	getByNames := get.Run
	get.Args = cobra.ArbitraryArgs
	get.Run = func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			runSecrets(cmd, args)
			return
		}
		getByNames(cmd, args)
	}

	secretsCmd.AddCommand(buildSecretsWriteCmd("create", util.SecretWriteCreateOnly,
		"Create secrets, failing without writing anything if one already exists",
		`infisical secrets-manager secrets create API_KEY=abc123 --env dev
infisical secrets-manager secrets create DB_URL=postgres://localhost/app SSH_KEY=@./id_rsa --env staging --path /backend

# From a .env or YAML file
infisical secrets-manager secrets create --file .env --env dev`))
	secretsCmd.AddCommand(buildSecretsWriteCmd("update", util.SecretWriteUpdateOnly,
		"Change the values of existing secrets, failing without writing anything if one doesn't exist",
		`infisical secrets-manager secrets update API_KEY=new-value --env dev
infisical secrets-manager secrets update DB_URL=postgres://db/app --tag backend --env prod`))
}

func buildSecretsWriteCmd(action string, mode util.SecretWriteMode, short, example string) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   action + " <name=value>...",
		Short:                 short,
		Example:               example,
		DisableFlagsInUseLine: true,
		Args:                  validateSecretsSetArgs,
		Run: func(cmd *cobra.Command, args []string) {
			runSecretsWrite(cmd, args, mode)
		},
	}
	cmd.Flags().String("token", "", "Write the secrets using a service token or machine identity access token")
	cmd.Flags().String("projectId", "", "ID of the project (falls back to INFISICAL_PROJECT_ID, then .infisical.yaml)")
	cmd.Flags().String("path", "/", "Folder path of the secrets")
	cmd.Flags().String("type", util.SECRET_TYPE_SHARED, "Type of the secrets: shared or personal")
	cmd.Flags().String("file", "", "Read the secrets from a .env or YAML file (comments: # or //) instead of arguments")
	cmd.Flags().StringArray("tag", []string{}, "Tag the secrets (repeatable: --tag backend --tag production). On update, replaces the existing tags")
	cmd.Flags().Bool("show-values", false, "Show secret values in the output table instead of masking them")
	util.AddOutputFlagsToCmd(cmd, "The output to format the written secrets in.")
	return cmd
}
