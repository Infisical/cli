package util

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
	"strings"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/rs/zerolog/log"
)

func WriteInitalConfig(userCredentials *models.UserCredentials) error {
	fullConfigFilePath, fullConfigFileDirPath, err := GetFullConfigFilePath()
	if err != nil {
		return err
	}

	// create directory
	if _, err := os.Stat(fullConfigFileDirPath); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(fullConfigFileDirPath, os.ModePerm)
		if err != nil {
			return err
		}
	}

	// get existing config
	existingConfigFile, err := GetConfigFile()
	if err != nil {
		return fmt.Errorf("writeInitalConfig: unable to write config file because [err=%s]", err)
	}

	//if profiles exists
	loggedInUser := models.LoggedInUser{
		Email:  userCredentials.Email,
		Domain: config.INFISICAL_URL,
	}
	//if empty or if email not in loggedinUsers
	if len(existingConfigFile.LoggedInUsers) == 0 || !ConfigContainsEmail(existingConfigFile.LoggedInUsers, userCredentials.Email) {
		existingConfigFile.LoggedInUsers = append(existingConfigFile.LoggedInUsers, loggedInUser)
	} else {
		//if exists update domain of loggedin users
		for idx, user := range existingConfigFile.LoggedInUsers {
			if user.Email == userCredentials.Email {
				existingConfigFile.LoggedInUsers[idx] = loggedInUser
			}
		}
	}

	configFile := models.ConfigFile{
		LoggedInUserEmail:      userCredentials.Email,
		LoggedInUserDomain:     config.INFISICAL_URL,
		LoggedInUsers:          existingConfigFile.LoggedInUsers,
		VaultBackendType:       existingConfigFile.VaultBackendType,
		VaultBackendPassphrase: existingConfigFile.VaultBackendPassphrase,
		Domains:                existingConfigFile.Domains,
	}

	configFileMarshalled, err := json.Marshal(configFile)
	if err != nil {
		return err
	}

	// Create file in directory
	err = WriteToFile(fullConfigFilePath, configFileMarshalled, 0600)
	if err != nil {
		return err
	}

	return err
}

func ConfigFileExists() bool {
	fullConfigFileURI, _, err := GetFullConfigFilePath()
	if err != nil {
		log.Debug().Err(err).Msgf("There was an error when creating the full path to config file")
		return false
	}

	if _, err := os.Stat(fullConfigFileURI); err == nil {
		return true
	} else {
		return false
	}
}

func WorkspaceConfigFileExistsInCurrentPath() bool {
	if _, err := os.Stat(INFISICAL_WORKSPACE_CONFIG_FILE_NAME); err == nil {
		return true
	} else {
		log.Debug().Err(err)
		return false
	}
}

func GetWorkspaceConfigFromCommandOrFile(cmd *cobra.Command) models.WorkspaceConfig {
	var configFilePath string
	if cmd.Flag("project-config-dir").Changed {
		configFileDir := GetStringArgument(cmd, "project-config-dir", "Unable to parse flag --project-config-dir")
		configFilePath = filepath.Join(configFileDir, ".infisical.json")

		_, err := os.Stat(configFilePath)
		if os.IsNotExist(err) {
			// The user explicitly provided the path, it must exist
			PrintErrorMessageAndExit(fmt.Sprintf("file %s does not exist", configFilePath))
		}
	} else {
		configFilePath, _ = FindWorkspaceConfigFile()
	}

	workspaceConfig := models.WorkspaceConfig{}
	var workspaceConfigFile models.WorkspaceConfigFile

	if configFilePath != "" {
		workspaceConfigFile = getWorkspaceConfigByPath(configFilePath)
	}

	if cmd.Flag("projectId") != nil && cmd.Flag("projectId").Changed {
		workspaceConfig.WorkspaceId = GetStringArgument(cmd, "projectId", "Unable to parse argument --projectId")
	} else {
		workspaceConfig.WorkspaceId = workspaceConfigFile.WorkspaceId
	}

	if workspaceConfig.WorkspaceId == "" {
		// We have no project to work with from args or the file
		if configFilePath == "" {
			PrintErrorMessageAndExit("Please either run infisical init to connect to a project or pass in project id with --projectId flag")
		}
		PrintErrorMessageAndExit("Your project id is missing in your local config file. Please add it or run again [infisical init]")
	}

	if cmd.Flag("tags") != nil && cmd.Flag("tags").Changed {
		workspaceConfig.TagSlugs = GetStringArgument(cmd, "tags", "Unable to parse argument --tags")
	} else {
		workspaceConfig.TagSlugs = strings.Join(workspaceConfigFile.TagSlugs, ",")
	}

	if cmd.Flag("path") != nil && cmd.Flag("path").Changed {
		workspaceConfig.SecretsPath = GetStringArgument(cmd, "path", "Unable to parse argument --path")
	} else {
		workspaceConfig.SecretsPath = workspaceConfigFile.SecretsPath
	}

	if cmd.Flag("environment") != nil && cmd.Flag("environment").Changed {
		workspaceConfig.Environment = GetStringArgument(cmd, "environment", "Unable to parse argument --environment")
	} else {
		workspaceConfig.Environment = getEnvelopmentBasedOnGitBranch(workspaceConfigFile)
	}

	return workspaceConfig
}

// FindWorkspaceConfigFile searches for a .infisical.json file in the current directory and all parent directories.
func FindWorkspaceConfigFile() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		path := filepath.Join(dir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
		_, err := os.Stat(path)
		if err == nil {
			// file found
			log.Debug().Msgf("FindWorkspaceConfigFile: workspace file found at [path=%s]", path)

			return path, nil
		}

		// check if we have reached the root directory
		if dir == filepath.Dir(dir) {
			break
		}

		// move up one directory
		dir = filepath.Dir(dir)
	}

	// file not found
	return "", fmt.Errorf("file not found: %s", INFISICAL_WORKSPACE_CONFIG_FILE_NAME)

}

func GetFullConfigFilePath() (fullPathToFile string, fullPathToDirectory string, err error) {
	homeDir, err := GetHomeDir()
	if err != nil {
		return "", "", err
	}

	fullPath := fmt.Sprintf("%s/%s/%s", homeDir, CONFIG_FOLDER_NAME, CONFIG_FILE_NAME)
	fullDirPath := fmt.Sprintf("%s/%s", homeDir, CONFIG_FOLDER_NAME)
	return fullPath, fullDirPath, err
}

// Given a path to a workspace config, unmarshal workspace config
func getWorkspaceConfigByPath(path string) models.WorkspaceConfigFile {
	workspaceConfigFileAsBytes, err := os.ReadFile(path)
	if err != nil {
		log.Debug().Msgf("GetWorkspaceConfigByPath: Unable to read workspace config file because [%s]", err)
		PrintErrorMessageAndExit(fmt.Sprintf("Unable to read workspace config file %s", path))
	}

	workspaceConfigFile := models.WorkspaceConfigFile{}
	err = json.Unmarshal(workspaceConfigFileAsBytes, &workspaceConfigFile)
	if err != nil {
		log.Debug().Msgf("GetWorkspaceConfigByPath: Unable to unmarshal workspace config file because [%s]", err)
		PrintErrorMessageAndExit(fmt.Sprintf("Unable to read workspace config file %s", path))
	}

	return workspaceConfigFile
}

func getEnvelopmentBasedOnGitBranch(workspaceFile models.WorkspaceConfigFile) string {
	branch, err := getCurrentBranch()
	if err != nil {
		log.Debug().Msgf("getEnvelopmentBasedOnGitBranch: [err=%s]", err)
	}

	envBasedOnGitBranch, ok := workspaceFile.GitBranchToEnvironmentMapping[branch]

	log.Debug().Msgf("GetEnvelopmentBasedOnGitBranch: [envBasedOnGitBranch=%s] [ok=%t]", envBasedOnGitBranch, ok)

	if err == nil && ok {
		return envBasedOnGitBranch
	} else {
		log.Debug().Msgf("getEnvelopmentBasedOnGitBranch: [err=%s]", err)
		return workspaceFile.DefaultEnvironment
	}
}

// Get the infisical config file and if it doesn't exist, return empty config model, otherwise raise error
func GetConfigFile() (models.ConfigFile, error) {
	fullConfigFilePath, _, err := GetFullConfigFilePath()
	if err != nil {
		return models.ConfigFile{}, err
	}

	configFileAsBytes, err := os.ReadFile(fullConfigFilePath)
	if err != nil {
		if err, ok := err.(*os.PathError); ok {
			return models.ConfigFile{}, nil
		} else {
			return models.ConfigFile{}, err
		}
	}

	var configFile models.ConfigFile
	err = json.Unmarshal(configFileAsBytes, &configFile)
	if err != nil {
		return models.ConfigFile{}, err
	}

	if configFile.VaultBackendPassphrase != "" {
		decodedPassphrase, err := base64.StdEncoding.DecodeString(configFile.VaultBackendPassphrase)
		if err != nil {
			return models.ConfigFile{}, fmt.Errorf("GetConfigFile: Unable to decode base64 passphrase [err=%s]", err)
		}
		os.Setenv("INFISICAL_VAULT_FILE_PASSPHRASE", string(decodedPassphrase))
	}

	return configFile, nil
}

// Write a ConfigFile to disk. Raise error if unable to save the model to disk
func WriteConfigFile(configFile *models.ConfigFile) error {
	fullConfigFilePath, fullConfigFileDirPath, err := GetFullConfigFilePath()
	if err != nil {
		return fmt.Errorf("writeConfigFile: unable to write config file because an error occurred when getting config file path [err=%s]", err)
	}

	configFileMarshalled, err := json.Marshal(configFile)
	if err != nil {
		return fmt.Errorf("writeConfigFile: unable to write config file because an error occurred when marshalling the config file [err=%s]", err)
	}

	// check if config folder exists and if not create it
	if _, err := os.Stat(fullConfigFileDirPath); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(fullConfigFileDirPath, os.ModePerm)
		if err != nil {
			return err
		}
	}

	// Create file in directory
	err = os.WriteFile(fullConfigFilePath, configFileMarshalled, 0600)
	if err != nil {
		return fmt.Errorf("writeConfigFile: Unable to write to file [err=%s]", err)
	}

	return nil
}
