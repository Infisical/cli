package util

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const workspaceConfigMigrationNoticeID = "workspace-config-yaml"

const workspaceConfigMigrationGuideURL = "https://infisical.com/docs/cli/project-config-migration"

// DisplayWorkspaceConfigMigrationNoticeWithWriter prints a once-per-day notice when the
// workspace config in use is a legacy .infisical.json and the CLI can't create a .infisical.yaml
// next to it. It first tries to create the yaml itself, so the notice only shows when that fails
// (read-only directory, invalid json, ...).
// Stays quiet in --silent mode, and can be disabled with INFISICAL_DISABLE_WORKSPACE_CONFIG_MIGRATION_NOTICE.
//
// projectConfigDir is the value of --project-config-dir when the command defines it; when set,
// only that directory is considered so the notice names the same file the command reads.
func DisplayWorkspaceConfigMigrationNoticeWithWriter(isSilent bool, projectConfigDir string, w io.Writer) {
	if isSilent {
		return
	}
	if os.Getenv("INFISICAL_DISABLE_WORKSPACE_CONFIG_MIGRATION_NOTICE") != "" {
		return
	}

	// if the workspace config is not a legacy .infisical.json, don't print the notice
	legacyConfigFilePath, err := ResolveWorkspaceConfigFile(projectConfigDir)
	if err != nil || filepath.Base(legacyConfigFilePath) != INFISICAL_WORKSPACE_CONFIG_FILE_NAME {
		return
	}

	// nothing to tell the user once the yaml exists, whether created here or by another command
	configFileDir := filepath.Dir(legacyConfigFilePath)
	yamlConfigFilePath := filepath.Join(configFileDir, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME)
	if createWorkspaceConfigYamlFromLegacy(legacyConfigFilePath, yamlConfigFilePath) {
		return
	}
	if _, err := os.Stat(yamlConfigFilePath); err == nil {
		return
	}

	DisplayMigrationNoticeWithWriter(MigrationNotice{
		ID:    workspaceConfigMigrationNoticeID,
		Title: fmt.Sprintf("Important: unable to create %s. This project still uses the deprecated %s.", INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME, INFISICAL_WORKSPACE_CONFIG_FILE_NAME),
		Message: fmt.Sprintf(
			"What's happening: the CLI is reading a legacy %s, and support for it will be removed\n"+
				"in a future release. File in use: %s\n"+
				"The CLI creates %s next to it automatically, but could not write it in %s.\n"+
				"What to do: make sure that directory is writable and the file is valid JSON, then run\n"+
				"any infisical command again, or create %s there yourself.",
			INFISICAL_WORKSPACE_CONFIG_FILE_NAME, legacyConfigFilePath,
			INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME, configFileDir, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME,
		),
		DocsURL: workspaceConfigMigrationGuideURL,
	}, w)
}
