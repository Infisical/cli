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

type composeFileInput struct {
	path       string
	flagIndex  int
	valueIndex int
}

func prepareComposeCommand(args []string, secretNames []string, _ []string) ([]string, func(), error) {
	composeIndex, subcommandIndex, ok := findComposeUp(args)
	if !ok {
		return args, func() {}, nil
	}

	files, err := resolveComposeFiles(args, composeIndex, subcommandIndex)
	if err != nil {
		return nil, nil, err
	}

	protectedNames := make(map[string]map[string]struct{})
	serviceNames := make(map[string]struct{})
	for _, file := range files {
		names, err := explicitEnvironmentNames(file.path)
		if err != nil {
			return nil, nil, err
		}
		for serviceName, namesForService := range names {
			serviceNames[serviceName] = struct{}{}
			if protectedNames[serviceName] == nil {
				protectedNames[serviceName] = make(map[string]struct{})
			}
			for name := range namesForService {
				protectedNames[serviceName][name] = struct{}{}
			}
		}
	}

	updatedArgs := append([]string(nil), args...)
	override, err := buildComposeOverride(serviceNames, secretNames, protectedNames)
	if err != nil {
		return nil, nil, err
	}
	if len(override) == 0 {
		return updatedArgs, func() {}, nil
	}

	tempFile, err := os.CreateTemp("", "infisical-compose-*.yaml")
	if err != nil {
		return nil, nil, fmt.Errorf("could not create temporary Compose file: %w", err)
	}
	tempPath := tempFile.Name()
	cleanup := func() {
		_ = os.Remove(tempPath)
	}
	if _, err := tempFile.Write(override); err != nil {
		_ = tempFile.Close()
		cleanup()
		return nil, nil, fmt.Errorf("could not write temporary Compose file: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("could not close temporary Compose file: %w", err)
	}

	updatedArgs = append(updatedArgs[:subcommandIndex], append([]string{"--file", tempPath}, updatedArgs[subcommandIndex:]...)...)
	return updatedArgs, cleanup, nil
}

func buildComposeOverride(serviceNames map[string]struct{}, secretNames []string, protectedNames map[string]map[string]struct{}) ([]byte, error) {
	services := make(map[string]interface{})
	for serviceName := range serviceNames {
		environment := make(map[string]interface{})
		for _, name := range secretNames {
			if _, protected := protectedNames[serviceName][name]; !protected {
				environment[name] = nil
			}
		}
		if len(environment) > 0 {
			services[serviceName] = map[string]interface{}{"environment": environment}
		}
	}
	if len(services) == 0 {
		return nil, nil
	}
	return yaml.Marshal(map[string]interface{}{"services": services})
}

func explicitEnvironmentNames(composeFile string) (map[string]map[string]struct{}, error) {
	contents, err := os.ReadFile(composeFile)
	if err != nil {
		return nil, fmt.Errorf("could not read Compose file %q: %w", composeFile, err)
	}

	var document map[string]interface{}
	if err := yaml.Unmarshal(contents, &document); err != nil {
		return nil, fmt.Errorf("could not parse Compose file %q: %w", composeFile, err)
	}

	names := make(map[string]map[string]struct{})
	services, ok := document["services"].(map[string]interface{})
	if !ok {
		return names, nil
	}
	for serviceName, rawService := range services {
		if _, ok := rawService.(map[string]interface{}); !ok {
			return nil, fmt.Errorf("could not inject secrets: service %q has an invalid definition", serviceName)
		}
		serviceNames, err := collectServiceEnvironmentNames(services, serviceName, filepath.Dir(composeFile), make(map[string]bool))
		if err != nil {
			return nil, err
		}
		names[serviceName] = serviceNames
	}
	return names, nil
}

func collectServiceEnvironmentNames(services map[string]interface{}, serviceName, baseDir string, visiting map[string]bool) (map[string]struct{}, error) {
	visitKey := filepath.Join(baseDir, serviceName)
	if visiting[visitKey] {
		return nil, fmt.Errorf("could not inspect Compose service %q: extends cycle detected", serviceName)
	}
	rawService, exists := services[serviceName]
	if !exists {
		return nil, fmt.Errorf("could not inspect Compose service %q: service does not exist", serviceName)
	}
	service, ok := rawService.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("could not inject secrets: service %q has an invalid definition", serviceName)
	}

	visiting[visitKey] = true
	defer delete(visiting, visitKey)

	names := make(map[string]struct{})
	rawEnvironment, exists := service["environment"]
	if exists && rawEnvironment != nil {
		switch environment := rawEnvironment.(type) {
		case map[string]interface{}:
			for name := range environment {
				names[name] = struct{}{}
			}
		case []interface{}:
			for _, item := range environment {
				value, ok := item.(string)
				if !ok {
					return nil, errors.New("environment list contains a non-string value")
				}
				name, _, _ := strings.Cut(value, "=")
				names[name] = struct{}{}
			}
		default:
			return nil, errors.New("environment must be a map or list")
		}
	}

	rawExtends, exists := service["extends"]
	if !exists || rawExtends == nil {
		return names, nil
	}
	extends, ok := rawExtends.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("could not inspect Compose service %q: extends must be a map", serviceName)
	}
	parentName, ok := extends["service"].(string)
	if !ok || parentName == "" {
		return nil, fmt.Errorf("could not inspect Compose service %q: extends has no service name", serviceName)
	}

	parentServices := services
	parentBaseDir := baseDir
	if fileName, ok := extends["file"].(string); ok && fileName != "" {
		parentFile := filepath.Join(baseDir, fileName)
		parentDocument, err := readComposeDocument(parentFile)
		if err != nil {
			return nil, err
		}
		var servicesOK bool
		parentServices, servicesOK = parentDocument["services"].(map[string]interface{})
		if !servicesOK {
			return nil, fmt.Errorf("could not inspect Compose service %q: external file has no services map", parentName)
		}
		parentBaseDir = filepath.Dir(parentFile)
	}

	parentNames, err := collectServiceEnvironmentNames(parentServices, parentName, parentBaseDir, visiting)
	if err != nil {
		return nil, err
	}
	for name := range parentNames {
		names[name] = struct{}{}
	}
	return names, nil
}

func readComposeDocument(composeFile string) (map[string]interface{}, error) {
	contents, err := os.ReadFile(composeFile)
	if err != nil {
		return nil, fmt.Errorf("could not read Compose file %q: %w", composeFile, err)
	}
	var document map[string]interface{}
	if err := yaml.Unmarshal(contents, &document); err != nil {
		return nil, fmt.Errorf("could not parse Compose file %q: %w", composeFile, err)
	}
	return document, nil
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
		for i := 1; i < len(args); i++ {
			if args[i] == "compose" {
				composeIndex = i
				break
			}
			if optionTakesValue(args[i]) && !strings.Contains(args[i], "=") {
				i++
				continue
			}
			if !strings.HasPrefix(args[i], "-") {
				return -1, -1, false
			}
		}
	}
	if composeIndex < 0 {
		return -1, -1, false
	}

	for i := composeIndex + 1; i < len(args); i++ {
		if optionTakesValue(args[i]) && !strings.Contains(args[i], "=") {
			i++
			continue
		}
		if !strings.HasPrefix(args[i], "-") {
			return composeIndex, i, args[i] == "up"
		}
	}
	return -1, -1, false
}

func optionTakesValue(arg string) bool {
	name := strings.SplitN(arg, "=", 2)[0]
	switch name {
	case "--context", "--config", "--host", "--log-level", "--tlsverify", "--tlscacert", "--tlscert", "--tlskey",
		"--file", "-f", "--env-file", "--project-directory", "--project-name", "-p", "--parallel", "--profile", "--progress":
		return true
	default:
		return false
	}
}

func resolveComposeFiles(args []string, composeIndex, subcommandIndex int) ([]composeFileInput, error) {
	projectDirectory := "."
	files := make([]composeFileInput, 0)
	for i := composeIndex + 1; i < subcommandIndex; i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--project-directory=") {
			projectDirectory = strings.TrimPrefix(arg, "--project-directory=")
		} else if arg == "--project-directory" && i+1 < subcommandIndex {
			projectDirectory = args[i+1]
			i++
		} else if arg == "--file" || arg == "-f" {
			if i+1 >= subcommandIndex {
				return nil, errors.New("could not inject secrets: Compose file option has no path")
			}
			files = append(files, composeFileInput{path: args[i+1], flagIndex: i, valueIndex: i + 1})
			i++
		} else if strings.HasPrefix(arg, "--file=") {
			files = append(files, composeFileInput{path: strings.TrimPrefix(arg, "--file="), flagIndex: i, valueIndex: i})
		} else if strings.HasPrefix(arg, "-f") && len(arg) > 2 {
			files = append(files, composeFileInput{path: arg[2:], flagIndex: i, valueIndex: i})
		}
	}

	if len(files) == 0 {
		composeFileEnv := os.Getenv("COMPOSE_FILE")
		if composeFileEnv != "" {
			for _, path := range strings.Split(composeFileEnv, string(os.PathListSeparator)) {
				files = append(files, composeFileInput{path: path, flagIndex: -1})
			}
		} else {
			for _, filename := range composeFilenames {
				path := filepath.Join(projectDirectory, filename)
				if _, err := os.Stat(path); err == nil {
					files = append(files, composeFileInput{path: path, flagIndex: -1})
					override := filepath.Join(projectDirectory, "compose.override.yaml")
					if filename != "compose.override.yaml" {
						if _, err := os.Stat(override); err == nil {
							files = append(files, composeFileInput{path: override, flagIndex: -1})
						}
					}
					break
				}
			}
		}
	}
	if len(files) == 0 {
		return nil, errors.New("could not find a Compose file; pass one with --file")
	}

	for i := range files {
		path, err := filepath.Abs(files[i].path)
		if err != nil {
			return nil, fmt.Errorf("could not resolve Compose file path: %w", err)
		}
		files[i].path = path
	}
	return files, nil
}
