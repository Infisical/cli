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
// workspace config in use is a legacy .infisical.json rather than a .infisical.yaml.
// Stays quiet in --silent mode, and can be disabled with INFISICAL_DISABLE_WORKSPACE_CONFIG_MIGRATION_NOTICE.
func DisplayWorkspaceConfigMigrationNoticeWithWriter(isSilent bool, w io.Writer) {
	if isSilent {
		return
	}
	if os.Getenv("INFISICAL_DISABLE_WORKSPACE_CONFIG_MIGRATION_NOTICE") != "" {
		return
	}

	// if the workspace config is not a legacy .infisical.json, don't print the notice
	legacyConfigFilePath, err := FindWorkspaceConfigFile()
	if err != nil || filepath.Base(legacyConfigFilePath) != INFISICAL_WORKSPACE_CONFIG_FILE_NAME {
		return
	}

	DisplayMigrationNoticeWithWriter(MigrationNotice{
		ID:    workspaceConfigMigrationNoticeID,
		Title: fmt.Sprintf("Important: %s is deprecated. Move this project to %s.", INFISICAL_WORKSPACE_CONFIG_FILE_NAME, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME),
		Message: fmt.Sprintf(
			"What's happening: the CLI is reading a legacy %s, and support for it will be removed\n"+
				"in a future release. File in use: %s\n"+
				"What to do: run `infisical migrate-config` to convert it to %s.",
			INFISICAL_WORKSPACE_CONFIG_FILE_NAME, legacyConfigFilePath,
			INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME,
		),
		DocsURL: workspaceConfigMigrationGuideURL,
	}, w)
}
