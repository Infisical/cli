package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

var composeFilenames = []string{"compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml"}

func prepareComposeCommand(args []string, secretNames []string, env []string) ([]string, func(), error) {
	composeIndex, subcommandIndex, ok := findComposeUp(args)
	if !ok {
		return args, func() {}, nil
	}

	secretValues := make(map[string]string, len(secretNames))
	for _, entry := range env {
		key, value, found := strings.Cut(entry, "=")
		if found {
			secretValues[key] = value
		}
	}

	composeFile, fileFlagIndex, err := resolveComposeFile(args, composeIndex)
	if err != nil {
		return nil, nil, err
	}

	contents, err := os.ReadFile(composeFile)
	if err != nil {
		return nil, nil, fmt.Errorf("could not read Compose file %q: %w", composeFile, err)
	}

	var document map[string]interface{}
	if err := yaml.Unmarshal(contents, &document); err != nil {
		return nil, nil, fmt.Errorf("could not parse Compose file %q: %w", composeFile, err)
	}

	services, ok := document["services"].(map[string]interface{})
	if !ok {
		return nil, nil, errors.New("could not inject secrets: Compose file has no services map")
	}

	for serviceName, rawService := range services {
		service, ok := rawService.(map[string]interface{})
		if !ok {
			return nil, nil, fmt.Errorf("could not inject secrets: service %q has an invalid definition", serviceName)
		}
		if err := addSecretsToService(service, secretNames, secretValues); err != nil {
			return nil, nil, fmt.Errorf("could not inject secrets into service %q: %w", serviceName, err)
		}
	}

	updated, err := yaml.Marshal(document)
	if err != nil {
		return nil, nil, fmt.Errorf("could not serialize temporary Compose file: %w", err)
	}

	tempFile, err := os.CreateTemp(filepath.Dir(composeFile), ".infisical-compose-*.yaml")
	if err != nil {
		return nil, nil, fmt.Errorf("could not create temporary Compose file: %w", err)
	}
	tempPath := tempFile.Name()
	cleanup := func() {
		_ = os.Remove(tempPath)
	}

	if _, err := tempFile.Write(updated); err != nil {
		tempFile.Close()
		cleanup()
		return nil, nil, fmt.Errorf("could not write temporary Compose file: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("could not close temporary Compose file: %w", err)
	}

	updatedArgs := append([]string(nil), args...)
	if fileFlagIndex >= 0 {
		updatedArgs[fileFlagIndex+1] = tempPath
	} else {
		updatedArgs = append(updatedArgs[:subcommandIndex], append([]string{"--file", tempPath}, updatedArgs[subcommandIndex:]...)...)
	}

	return updatedArgs, cleanup, nil
}

func findComposeUp(args []string) (int, int, bool) {
	if len(args) == 0 {
		return -1, -1, false
	}

	composeIndex := -1
	switch filepath.Base(args[0]) {
	case "docker-compose":
		composeIndex = 0
	case "docker", "nerdctl":
		if len(args) > 1 && args[1] == "compose" {
			composeIndex = 1
		}
	}
	if composeIndex < 0 {
		return -1, -1, false
	}

	for i := composeIndex + 1; i < len(args); i++ {
		if args[i] == "up" {
			return composeIndex, i, true
		}
	}
	return -1, -1, false
}

func resolveComposeFile(args []string, composeIndex int) (string, int, error) {
	fileFlags := 0
	fileFlagIndex := -1
	for i := composeIndex + 1; i < len(args)-1; i++ {
		if args[i] == "--file" || args[i] == "-f" {
			fileFlags++
			fileFlagIndex = i
		}
	}
	if fileFlags > 1 {
		return "", -1, errors.New("could not inject secrets into multiple Compose files; use one --file option")
	}
	if fileFlagIndex >= 0 {
		path, err := filepath.Abs(args[fileFlagIndex+1])
		if err != nil {
			return "", -1, fmt.Errorf("could not resolve Compose file path: %w", err)
		}
		return path, fileFlagIndex, nil
	}

	for _, filename := range composeFilenames {
		path := filepath.Join(".", filename)
		if _, err := os.Stat(path); err == nil {
			absolutePath, err := filepath.Abs(path)
			if err != nil {
				return "", -1, fmt.Errorf("could not resolve Compose file path: %w", err)
			}
			return absolutePath, -1, nil
		}
	}

	return "", -1, errors.New("could not find a Compose file; pass one with --file")
}

func addSecretsToService(service map[string]interface{}, secretNames []string, secretValues map[string]string) error {
	rawEnvironment, exists := service["environment"]
	if !exists || rawEnvironment == nil {
		rawEnvironment = map[string]interface{}{}
		service["environment"] = rawEnvironment
	}

	switch environment := rawEnvironment.(type) {
	case map[string]interface{}:
		for _, name := range secretNames {
			if _, exists := environment[name]; !exists {
				environment[name] = secretValues[name]
			}
		}
	case []interface{}:
		existing := make(map[string]struct{}, len(environment))
		for _, item := range environment {
			value, ok := item.(string)
			if !ok {
				return errors.New("environment list contains a non-string value")
			}
			name, _, _ := strings.Cut(value, "=")
			existing[name] = struct{}{}
		}
		for _, name := range secretNames {
			if _, exists := existing[name]; !exists {
				environment = append(environment, name+"="+secretValues[name])
			}
		}
		service["environment"] = environment
	default:
		return errors.New("environment must be a map or list")
	}

	return nil
}
