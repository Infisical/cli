package util

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"testing"
)

func TestFindWorkspaceConfigFile(t *testing.T) {
	tmp := t.TempDir()

	// Set the temp folder as the current working directory
	os.Chdir(tmp)
	os.WriteFile(".infisical.json", []byte("{}"), 0644)

	configFile, err := FindWorkspaceConfigFile()
	if configFile == fmt.Sprintf("%s/%s", tmp, ".infisical.json") {
		t.Errorf("Expected config file to be found in the current working directory, found: %s", configFile)
	}
	if err != nil {
		t.Errorf("Expected error to be nil, got %s", err.Error())
	}
}

func TestFindWorkspaceConfigFile_NoConfigFile(t *testing.T) {
	tmp := t.TempDir()

	// Set the temp folder as the current working directory
	os.Chdir(tmp)

	configFile, err := FindWorkspaceConfigFile()
	if configFile != "" {
		t.Errorf("Expected config file to be empty, got %s", configFile)
	}
	if err.Error() != "file not found: .infisical.json" {
		t.Errorf("Expected error to be 'file not found: .inifisical.json', got %s", err.Error())
	}
}

func TestGetWorkspaceConfigFromCommandOrFile_NoConfigFile_NoProjectId(t *testing.T) {
	defer func() {
		errorMessage := recover().(string)
		expectedErrorMessage := "Please either run infisical init to connect to a project or pass in project id with --projectId flag"
		if errorMessage != expectedErrorMessage {
			t.Errorf("Unexpected error message: %s", errorMessage)
		}
	}()

	tmp := t.TempDir()
	os.Chdir(tmp)

	emptyCmd := getCommandWithFullConfig()
	GetWorkspaceConfigFromCommandOrFile(emptyCmd)

	t.Errorf("Expected the function to panic")
}

func TestGetWorkspaceConfigFromCommandOrFile_ConfigFile_EmptyProjectId(t *testing.T) {
	defer func() {
		errorMessage := recover().(string)
		expectedErrorMessage := "Your project id is missing in your local config file. Please add it or run again [infisical init]"
		if errorMessage != expectedErrorMessage {
			t.Errorf("Unexpected error message: %s", errorMessage)
		}
	}()

	tmp := t.TempDir()
	os.Chdir(tmp)

	os.WriteFile(".infisical.json", []byte(`{"workspaceId": ""}`), 0644)

	emptyCmd := getCommandWithFullConfig()
	GetWorkspaceConfigFromCommandOrFile(emptyCmd)

	t.Errorf("Expected the function to panic")
}

func TestGetWorkspaceConfigFromCommandOrFile_OverrideConfigFile(t *testing.T) {
	tmp := t.TempDir()
	os.Chdir(tmp)

	os.WriteFile(".infisical.json", []byte(`{"workspaceId": "default-project", "defaultEnvironment": "default-env"}`), 0644)

	overrideDir := t.TempDir()
	os.WriteFile(fmt.Sprintf("%s/.infisical.json", overrideDir), []byte(`{"workspaceId": "override-project", "defaultEnvironment": "override-env"}`), 0644)

	cmd := getCommandWithFullConfig()
	cmd.Flags().Set("project-config-dir", overrideDir)
	projectConfig := GetWorkspaceConfigFromCommandOrFile(cmd)

	if projectConfig.WorkspaceId != "override-project" {
		t.Errorf("Expected project id to be 'override-project', got %s", projectConfig.WorkspaceId)
	}
}

func TestGetWorkspaceConfigFromCommandOrFile_ReadFromCommand(t *testing.T) {
	tmp := t.TempDir()
	os.Chdir(tmp)

	os.WriteFile(".infisical.json", []byte(`{"workspaceId": "default-project", "defaultEnvironment": "default-env", "tags": ["file", "tags"], "path": "/override"}`), 0644)

	cmd := getCommandWithFullConfig()
	cmd.Flags().Set("projectId", "cmd-project")
	cmd.Flags().Set("env", "cmd-env")
	cmd.Flags().Set("tags", "cmd,tags")
	cmd.Flags().Set("path", "/cmd")
	projectConfig := GetWorkspaceConfigFromCommandOrFile(cmd)

	if projectConfig.WorkspaceId != "cmd-project" {
		t.Errorf("Expected project id to be 'cmd-project', got %s", projectConfig.WorkspaceId)
	}
	if projectConfig.TagSlugs != "cmd,tags" {
		t.Errorf("Expected tags to be 'cmd,tags', got %s", projectConfig.TagSlugs)
	}
	if projectConfig.SecretsPath != "/cmd" {
		t.Errorf("Expected secrets path to be '/cmd', got %s", projectConfig.SecretsPath)
	}
	if projectConfig.Environment != "cmd-env" {
		t.Errorf("Expected environment to be 'cmd-env', got %s", projectConfig.Environment)
	}
}

func TestGetWorkspaceConfigFromCommandOrFile_ReadFromFile(t *testing.T) {
	tmp := t.TempDir()
	os.Chdir(tmp)

	os.WriteFile(".infisical.json", []byte(`{"workspaceId": "default-project", "defaultEnvironment": "default-env", "tags": ["file", "tags"], "path": "/override"}`), 0644)

	emptyCmd := getCommandWithFullConfig()
	projectConfig := GetWorkspaceConfigFromCommandOrFile(emptyCmd)

	if projectConfig.WorkspaceId != "default-project" {
		t.Errorf("Expected project id to be 'override-project', got %s", projectConfig.WorkspaceId)
	}
	if projectConfig.TagSlugs != "file,tags" {
		t.Errorf("Expected tags to be 'file,tags', got %s", projectConfig.TagSlugs)
	}
	if projectConfig.SecretsPath != "/override" {
		t.Errorf("Expected secrets path to be '/override', got %s", projectConfig.SecretsPath)
	}
	if projectConfig.Environment != "default-env" {
		t.Errorf("Expected environment to be 'default-env', got %s", projectConfig.Environment)
	}
}

func TestGetWorkspaceConfigFromCommandOrFile_Defaults(t *testing.T) {
	tmp := t.TempDir()
	os.Chdir(tmp)

	os.WriteFile(".infisical.json", []byte(`{"workspaceId": "default-project"}`), 0644)

	emptyCmd := getCommandWithFullConfig()
	projectConfig := GetWorkspaceConfigFromCommandOrFile(emptyCmd)

	if projectConfig.WorkspaceId != "default-project" {
		t.Errorf("Expected project id to be 'override-project', got %s", projectConfig.WorkspaceId)
	}
	if projectConfig.SecretsPath != "/" {
		t.Errorf("Expected secrets path to be default value '/', got %s", projectConfig.SecretsPath)
	}
	if projectConfig.Environment != "default" {
		t.Errorf("Expected environment to be default value 'default', got %s", projectConfig.Environment)
	}
}

func getCommandWithProjectAndEnv() *cobra.Command {
	cmd := &cobra.Command{
		Use: "test",
		Run: func(cmd *cobra.Command, args []string) {
		},
	}
	cmd.Flags().String("project-config-dir", "", "The directory .infisical.json is stored in. Defaults to the current working directory.")
	cmd.Flags().String("projectId", "", "Project name")
	cmd.Flags().String("env", "default", "Environment name")
	return cmd
}

func getCommandWithFullConfig() *cobra.Command {
	cmd := getCommandWithProjectAndEnv()
	cmd.Flags().String("path", "/", "Secrets path")
	cmd.Flags().String("tags", "", "Comma separated list of tags")
	return cmd
}
