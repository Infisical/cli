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

// WorkspaceConfigFileExistsInCurrentPath reports whether the current directory
// has a workspace config file, either the YAML one or a legacy .infisical.json.
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

	// check if the yaml config file exists
	_, err := os.Stat(yamlConfigFilePath)
	if err == nil {
		return readWorkspaceConfigYaml(yamlConfigFilePath)
	}
	if !os.IsNotExist(err) {
		return models.WorkspaceConfigFile{}, err
	}

	if _, err := os.Stat(jsonConfigFilePath); os.IsNotExist(err) {
		return models.WorkspaceConfigFile{}, fmt.Errorf("no %s or %s found in %s", INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME, INFISICAL_WORKSPACE_CONFIG_FILE_NAME, configFileDir)
	}

	workspaceConfigFile, err := migrateWorkspaceConfigToYaml(jsonConfigFilePath, yamlConfigFilePath)
	if err != nil {
		log.Debug().Err(err).Msgf("GetWorkSpaceFromFilePath: unable to migrate [path=%s] to yaml, reading the legacy file instead", jsonConfigFilePath)
		return GetWorkspaceConfigByPath(jsonConfigFilePath)
	}

	return workspaceConfigFile, nil
}

// migrateWorkspaceConfigToYaml converts the legacy JSON workspace config into YAML. The JSON file is only
// removed once the YAML file has been fully written and read back successfully.
func migrateWorkspaceConfigToYaml(jsonConfigFilePath string, yamlConfigFilePath string) (models.WorkspaceConfigFile, error) {
	legacyWorkspaceConfig, err := GetWorkspaceConfigByPath(jsonConfigFilePath)
	if err != nil {
		return models.WorkspaceConfigFile{}, err
	}

	yamlConfigFileAsBytes, err := yaml.Marshal(workspaceConfigToYaml(legacyWorkspaceConfig))
	if err != nil {
		return models.WorkspaceConfigFile{}, fmt.Errorf("migrateWorkspaceConfigToYaml: unable to marshal yaml [err=%s]", err)
	}

	// write to a temp file and rename it so a partially written .infisical.yaml is never left behind
	tempFile, err := os.CreateTemp(filepath.Dir(yamlConfigFilePath), INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME+".tmp-*")
	if err != nil {
		return models.WorkspaceConfigFile{}, fmt.Errorf("migrateWorkspaceConfigToYaml: unable to create temp file [err=%s]", err)
	}
	defer os.Remove(tempFile.Name()) // no-op once the rename succeeds

	if _, err := tempFile.Write(yamlConfigFileAsBytes); err != nil {
		tempFile.Close()
		return models.WorkspaceConfigFile{}, fmt.Errorf("migrateWorkspaceConfigToYaml: unable to write temp file [err=%s]", err)
	}
	if err := tempFile.Close(); err != nil {
		return models.WorkspaceConfigFile{}, fmt.Errorf("migrateWorkspaceConfigToYaml: unable to close temp file [err=%s]", err)
	}
	if err := os.Rename(tempFile.Name(), yamlConfigFilePath); err != nil {
		return models.WorkspaceConfigFile{}, fmt.Errorf("migrateWorkspaceConfigToYaml: unable to create %s [err=%s]", yamlConfigFilePath, err)
	}

	workspaceConfigFile, err := readWorkspaceConfigYaml(yamlConfigFilePath)
	if err != nil {
		os.Remove(yamlConfigFilePath)
		return models.WorkspaceConfigFile{}, err
	}

	if err := os.Remove(jsonConfigFilePath); err != nil {
		PrintWarning(fmt.Sprintf("Wrote %s but unable to remove the legacy %s; delete it manually [err=%s]", yamlConfigFilePath, jsonConfigFilePath, err))
		return workspaceConfigFile, nil
	}
	PrintlnStderr(fmt.Sprintf("Migrated the legacy %s to %s.", jsonConfigFilePath, yamlConfigFilePath))

	return workspaceConfigFile, nil
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

// FindWorkspaceConfigFile searches for a .infisical.yaml (or legacy .infisical.json) file in the current directory
// and all parent directories. In each directory the YAML file takes precedence.
func FindWorkspaceConfigFile() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		for _, fileName := range []string{INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME, INFISICAL_WORKSPACE_CONFIG_FILE_NAME} {
			path := filepath.Join(dir, fileName)
			_, err := os.Stat(path)
			if err == nil {
				// file found
				log.Debug().Msgf("FindWorkspaceConfigFile: workspace file found at [path=%s]", path)

				return path, nil
			}
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
