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
	for _, fileName := range []string{INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME, INFISICAL_WORKSPACE_CONFIG_FILE_NAME} {
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
	yamlConfigFilePath := filepath.Join(configFileDir, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME)
	jsonConfigFilePath := filepath.Join(configFileDir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)

	// the yaml file takes precedence over the legacy json file when both exist
	if workspaceConfigFile, exists, err := readWorkspaceConfigYamlIfExists(yamlConfigFilePath); exists {
		return workspaceConfigFile, err
	}

	if _, err := os.Stat(jsonConfigFilePath); os.IsNotExist(err) {
		return models.WorkspaceConfigFile{}, fmt.Errorf("no %s or %s found in %s", INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME, INFISICAL_WORKSPACE_CONFIG_FILE_NAME, configFileDir)
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

func ConvertLegacyWorkspaceConfigToYaml(jsonConfigFilePath string, yamlConfigFilePath string) error {
	if _, err := os.Stat(yamlConfigFilePath); err == nil {
		return fmt.Errorf("ConvertLegacyWorkspaceConfigToYaml: %s already exists", yamlConfigFilePath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("ConvertLegacyWorkspaceConfigToYaml: unable to check %s [err=%s]", yamlConfigFilePath, err)
	}

	legacyWorkspaceConfig, err := GetWorkspaceConfigByPath(jsonConfigFilePath)
	if err != nil {
		return err
	}

	yamlConfigFileAsBytes, err := yaml.Marshal(workspaceConfigToYaml(legacyWorkspaceConfig))
	if err != nil {
		return fmt.Errorf("ConvertLegacyWorkspaceConfigToYaml: unable to marshal yaml [err=%s]", err)
	}

	// written atomically so a partially written .infisical.yaml is never left behind
	if err := WriteFileAtomic(yamlConfigFilePath, yamlConfigFileAsBytes, 0600); err != nil {
		return fmt.Errorf("ConvertLegacyWorkspaceConfigToYaml: unable to create %s [err=%s]", yamlConfigFilePath, err)
	}

	if _, err := readWorkspaceConfigYaml(yamlConfigFilePath); err != nil {
		os.Remove(yamlConfigFilePath)
		return err
	}

	return nil
}

func workspaceConfigToYaml(workspaceConfig models.WorkspaceConfigFile) models.WorkspaceConfigFileYaml {
	var workspaceConfigYaml models.WorkspaceConfigFileYaml
	workspaceConfigYaml.General.Domain = workspaceConfig.Domain
	workspaceConfigYaml.SecretsManagement.ProjectID = workspaceConfig.WorkspaceId
	workspaceConfigYaml.SecretsManagement.DefaultEnvironment = workspaceConfig.DefaultEnvironment
	workspaceConfigYaml.SecretsManagement.DefaultSecretPath = workspaceConfig.DefaultSecretPath
	workspaceConfigYaml.SecretsManagement.Mappings.GitBranchToEnvironment = workspaceConfig.GitBranchToEnvironmentMapping
	return workspaceConfigYaml
}

func workspaceConfigFromYaml(workspaceConfigYaml models.WorkspaceConfigFileYaml) models.WorkspaceConfigFile {
	return models.WorkspaceConfigFile{
		WorkspaceId:                   workspaceConfigYaml.SecretsManagement.ProjectID,
		DefaultEnvironment:            workspaceConfigYaml.SecretsManagement.DefaultEnvironment,
		GitBranchToEnvironmentMapping: workspaceConfigYaml.SecretsManagement.Mappings.GitBranchToEnvironment,
		DefaultSecretPath:             workspaceConfigYaml.SecretsManagement.DefaultSecretPath,
		Domain:                        workspaceConfigYaml.General.Domain,
	}
}

// findWorkspaceConfigFileInDir looks for a .infisical.yaml (or legacy .infisical.json) in exactly
// the given directory, without walking up. The YAML file takes precedence.
func findWorkspaceConfigFileInDir(dir string) (string, bool) {
	for _, fileName := range []string{INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME, INFISICAL_WORKSPACE_CONFIG_FILE_NAME} {
		path := filepath.Join(dir, fileName)
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}
	return "", false
}

// ResolveWorkspaceConfigFile returns the path of the workspace config file a command will read.
// With an explicit projectConfigDir (the --project-config-dir flag) only that directory is
// considered, matching GetWorkSpaceFromFilePath. Otherwise it walks up from the current directory.
func ResolveWorkspaceConfigFile(projectConfigDir string) (string, error) {
	if projectConfigDir == "" {
		return FindWorkspaceConfigFile()
	}

	path, found := findWorkspaceConfigFileInDir(projectConfigDir)
	if !found {
		return "", fmt.Errorf("no %s or %s found in %s", INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME, INFISICAL_WORKSPACE_CONFIG_FILE_NAME, projectConfigDir)
	}

	if absPath, err := filepath.Abs(path); err == nil {
		path = absPath
	}
	return path, nil
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
	return "", fmt.Errorf("file not found: %s or %s", INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)

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
