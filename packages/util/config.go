package util

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

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
	for _, fileName := range []string{INFISICAL_WORKSPACE_CONFIG_FILE_NAME, LEGACY_INFISICAL_WORKSPACE_CONFIG_FILE_NAME} {
		if _, err := os.Stat(fileName); err == nil {
			return true
		} else {
			log.Debug().Err(err)
		}
	}
	return false
}

func GetWorkSpaceFromFile() (models.WorkspaceConfigFile, error) {
	cfgFile, err := FindWorkspaceConfigFile()
	if err != nil {
		return models.WorkspaceConfigFile{}, err
	}

	return GetWorkSpaceFromFilePath(filepath.Dir(cfgFile))
}

func GetDomainFromFile() (domain string, valid bool) {
	workspaceFile, err := GetWorkSpaceFromFile()
	if err != nil {
		log.Debug().Msgf("GetDomainFromFile: [err=%s]", err)
		return "", false
	}

	domain = strings.TrimSpace(workspaceFile.Domain)
	parsed, err := url.Parse(domain)
	valid = err == nil &&
		(parsed.Scheme == "http" || parsed.Scheme == "https") &&
		parsed.Host != ""
	return domain, valid
}

func GetWorkSpaceFromFilePath(configFileDir string) (models.WorkspaceConfigFile, error) {
	yamlConfigFilePath := filepath.Join(configFileDir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
	jsonConfigFilePath := filepath.Join(configFileDir, LEGACY_INFISICAL_WORKSPACE_CONFIG_FILE_NAME)

	// the yaml file takes precedence over the legacy json file when both exist
	if workspaceConfigFile, exists, err := readWorkspaceConfigYamlIfExists(yamlConfigFilePath); exists {
		return workspaceConfigFile, err
	}

	if _, err := os.Stat(jsonConfigFilePath); os.IsNotExist(err) {
		return models.WorkspaceConfigFile{}, fmt.Errorf("no %s or %s found in %s", INFISICAL_WORKSPACE_CONFIG_FILE_NAME, LEGACY_INFISICAL_WORKSPACE_CONFIG_FILE_NAME, configFileDir)
	}

	return GetWorkspaceConfigByPath(jsonConfigFilePath)
}

func readWorkspaceConfigYamlIfExists(path string) (workspaceConfigFile models.WorkspaceConfigFile, exists bool, err error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return models.WorkspaceConfigFile{}, false, nil
		}
		return models.WorkspaceConfigFile{}, true, err
	}

	workspaceConfigFile, err = readWorkspaceConfigYaml(path)
	return workspaceConfigFile, true, err
}

func readWorkspaceConfigYaml(path string) (models.WorkspaceConfigFile, error) {
	configFileAsBytes, err := os.ReadFile(path)
	if err != nil {
		return models.WorkspaceConfigFile{}, fmt.Errorf("readWorkspaceConfigYaml: unable to read workspace config file because [%s]", err)
	}

	var workspaceConfigFileYaml models.WorkspaceConfigFileYaml
	err = yaml.Unmarshal(configFileAsBytes, &workspaceConfigFileYaml)
	if err != nil {
		return models.WorkspaceConfigFile{}, fmt.Errorf("readWorkspaceConfigYaml: unable to unmarshal workspace config file because [%s]", err)
	}

	return workspaceConfigFromYaml(workspaceConfigFileYaml), nil
}

// workspaceConfigFromYaml accepts both the current keys and the deprecated default-environment /
// default-secret-path / mappings ones. Each field is resolved on its own: environment wins over
// default-environment and secret-path wins over default-secret-path when set, and overrides.git-branch replaces
// the mappings when present, so a partial migration keeps the deprecated value for whichever field has not been
// moved yet.
func workspaceConfigFromYaml(workspaceConfigYaml models.WorkspaceConfigFileYaml) models.WorkspaceConfigFile {
	secretsManagement := workspaceConfigYaml.SecretsManagement
	workspaceConfigFile := models.WorkspaceConfigFile{
		WorkspaceId:                   secretsManagement.ProjectID,
		DefaultEnvironment:            secretsManagement.DefaultEnvironment,
		GitBranchToEnvironmentMapping: secretsManagement.Mappings.GitBranchToEnvironment,
		DefaultSecretPath:             secretsManagement.DefaultSecretPath,
		Domain:                        workspaceConfigYaml.General.Domain,
	}

	if secretsManagement.Environment != "" {
		workspaceConfigFile.DefaultEnvironment = secretsManagement.Environment
	}

	if secretsManagement.SecretPath != "" {
		workspaceConfigFile.DefaultSecretPath = secretsManagement.SecretPath
	}

	if len(secretsManagement.Overrides.GitBranch) > 0 {
		workspaceConfigFile.GitBranchToEnvironmentMapping = gitBranchMapFromOverrides(secretsManagement.Overrides.GitBranch)
	}

	return workspaceConfigFile
}

// gitBranchMapFromOverrides builds the in-memory branch map from the git-branch overrides list. Entries
// without a branch are skipped, and the first entry for a branch wins.
func gitBranchMapFromOverrides(gitBranchOverrides []models.GitBranchEnvironmentOverride) map[string]string {
	if len(gitBranchOverrides) == 0 {
		return nil
	}
	branchToEnvironment := make(map[string]string, len(gitBranchOverrides))
	for _, override := range gitBranchOverrides {
		if override.Branch == "" {
			continue
		}
		if _, exists := branchToEnvironment[override.Branch]; exists {
			continue
		}
		branchToEnvironment[override.Branch] = override.Environment
	}
	return branchToEnvironment
}

// findWorkspaceConfigFileInDir looks for a .infisical.yaml (or legacy .infisical.json) in exactly
// the given directory, without walking up. The YAML file takes precedence.
func findWorkspaceConfigFileInDir(dir string) (string, bool) {
	for _, fileName := range []string{INFISICAL_WORKSPACE_CONFIG_FILE_NAME, LEGACY_INFISICAL_WORKSPACE_CONFIG_FILE_NAME} {
		path := filepath.Join(dir, fileName)
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}
	return "", false
}

// FindWorkspaceConfigFile searches for a .infisical.yaml (or legacy .infisical.json) file in the current directory
// and all parent directories. In each directory the YAML file takes precedence.
func FindWorkspaceConfigFile() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		if path, found := findWorkspaceConfigFileInDir(dir); found {
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
	return "", fmt.Errorf("file not found: %s or %s", INFISICAL_WORKSPACE_CONFIG_FILE_NAME, LEGACY_INFISICAL_WORKSPACE_CONFIG_FILE_NAME)

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
func GetWorkspaceConfigByPath(path string) (workspaceConfig models.WorkspaceConfigFile, err error) {
	workspaceConfigFileAsBytes, err := os.ReadFile(path)
	if err != nil {
		return models.WorkspaceConfigFile{}, fmt.Errorf("GetWorkspaceConfigByPath: Unable to read workspace config file because [%s]", err)
	}

	var workspaceConfigFile models.WorkspaceConfigFile
	err = json.Unmarshal(workspaceConfigFileAsBytes, &workspaceConfigFile)
	if err != nil {
		return models.WorkspaceConfigFile{}, fmt.Errorf("GetWorkspaceConfigByPath: Unable to unmarshal workspace config file because [%s]", err)
	}

	return workspaceConfigFile, nil
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
