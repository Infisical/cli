/*
Copyright (c) 2026 Infisical Inc.
*/
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/posthog/posthog-go"
	"github.com/spf13/cobra"
)

var migrateConfigCmd = &cobra.Command{
	Use:                   "migrate-config",
	Short:                 "Convert this project's legacy .infisical.json into .infisical.yaml",
	Example:               "infisical migrate-config",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if err := migrateLegacyWorkspaceConfig(); err != nil {
			util.HandleError(err, fmt.Sprintf("Unable to migrate %s to %s", util.INFISICAL_WORKSPACE_CONFIG_FILE_NAME, util.INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME))
		}

		Telemetry.CaptureEvent("cli-command:migrate-config", posthog.NewProperties().Set("version", util.CLI_VERSION))
	},
}

func migrateLegacyWorkspaceConfig() error {
	configFilePath, err := util.FindWorkspaceConfigFile()
	if err != nil {
		return fmt.Errorf("no %s found in this directory or any parent directory", util.INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
	}
	configFileDir := filepath.Dir(configFilePath)

	if filepath.Base(configFilePath) == util.INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME {
		util.PrintlnStderr(fmt.Sprintf("This project already uses %s. Nothing to migrate.", configFilePath))
		if _, err := os.Stat(filepath.Join(configFileDir, util.INFISICAL_WORKSPACE_CONFIG_FILE_NAME)); err == nil {
			util.PrintWarning(fmt.Sprintf("The legacy %s in %s is no longer used because %s takes precedence. You can delete it.", util.INFISICAL_WORKSPACE_CONFIG_FILE_NAME, configFileDir, util.INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME))
		}
		return nil
	}

	yamlConfigFilePath := filepath.Join(configFileDir, util.INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME)
	if err := util.ConvertLegacyWorkspaceConfigToYaml(configFilePath, yamlConfigFilePath); err != nil {
		return err
	}

	if err := os.Remove(configFilePath); err != nil {
		util.PrintWarning(fmt.Sprintf("Wrote %s but unable to remove the legacy %s; delete it manually [err=%s]", yamlConfigFilePath, configFilePath, err))
		return nil
	}

	util.PrintSuccessMessage(fmt.Sprintf("Migrated %s to %s.", configFilePath, yamlConfigFilePath))
	util.PrintlnStderr(fmt.Sprintf("If this project is under version control, commit the new %s and the removal of %s.", util.INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME, util.INFISICAL_WORKSPACE_CONFIG_FILE_NAME))

	return nil
}

func init() {
	RootCmd.AddCommand(migrateConfigCmd)
}
