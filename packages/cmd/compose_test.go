package cmd

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestPrepareComposeCommandInjectsSecretsIntoEveryService(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	composePath := filepath.Join(dir, "compose.yaml")
	original := `services:
  api:
    image: example/api
    environment:
      EXISTING: explicit
      TOKEN: explicit
  worker:
    image: example/worker
    environment:
      - EXISTING=explicit
`
	if err := os.WriteFile(composePath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	args, cleanup, err := prepareComposeCommand(
		[]string{"docker", "compose", "--file", composePath, "up"},
		[]string{"SECRET", "EXISTING", "TOKEN"},
		[]string{"SECRET=from-infisical", "EXISTING=from-infisical", "TOKEN=from-infisical"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	if args[2] != "--file" || args[3] == composePath {
		t.Fatalf("expected Compose file argument to be replaced, got %v", args)
	}
	if _, err := os.Stat(args[3]); err != nil {
		t.Fatalf("temporary Compose file does not exist: %v", err)
	}

	contents, err := os.ReadFile(args[3])
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]interface{}
	if err := yaml.Unmarshal(contents, &document); err != nil {
		t.Fatal(err)
	}

	services := document["services"].(map[string]interface{})
	apiEnvironment := services["api"].(map[string]interface{})["environment"].(map[string]interface{})
	secret, exists := apiEnvironment["SECRET"]
	if !exists || secret != nil {
		t.Fatalf("expected SECRET to be present as an unset Compose variable, got %v", apiEnvironment["SECRET"])
	}
	if apiEnvironment["EXISTING"] != "explicit" {
		t.Fatalf("expected explicit api value to win, got %v", apiEnvironment["EXISTING"])
	}
	if apiEnvironment["TOKEN"] != "explicit" {
		t.Fatalf("expected explicit api token to win, got %v", apiEnvironment["TOKEN"])
	}

	workerEnvironment := services["worker"].(map[string]interface{})["environment"].([]interface{})
	values := make([]string, 0, len(workerEnvironment))
	for _, value := range workerEnvironment {
		values = append(values, value.(string))
	}
	if !slices.Contains(values, "SECRET") {
		t.Fatalf("expected SECRET in worker environment, got %v", values)
	}
	if !slices.Contains(values, "EXISTING=explicit") {
		t.Fatalf("expected explicit worker value to remain, got %v", values)
	}
	if !slices.Contains(values, "TOKEN") {
		t.Fatalf("expected TOKEN to be injected into worker, got %v", values)
	}

	unchanged, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged) != original {
		t.Fatal("source Compose file was modified")
	}
}

func TestPrepareComposeCommandUsesDefaultComposeFile(t *testing.T) {
	dir := t.TempDir()
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(workingDirectory)
	})

	if err := os.WriteFile("docker-compose.yml", []byte("services:\n  app:\n    image: example/app\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	args, cleanup, err := prepareComposeCommand(
		[]string{"docker-compose", "up"},
		[]string{"SECRET"},
		[]string{"SECRET=value"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	if !strings.Contains(strings.Join(args, " "), "--file") {
		t.Fatalf("expected generated --file argument, got %v", args)
	}
	if _, err := os.Stat(args[2]); err != nil {
		t.Fatalf("expected generated Compose file, got %v", err)
	}
}

func TestPrepareComposeCommandLeavesNonComposeCommandsUnchanged(t *testing.T) {
	t.Parallel()

	args := []string{"node", "server.js"}
	updated, cleanup, err := prepareComposeCommand(args, []string{"SECRET"}, []string{"SECRET=value"})
	if err != nil {
		t.Fatal(err)
	}
	cleanup()

	if !slices.Equal(args, updated) {
		t.Fatalf("expected non-Compose command to remain unchanged, got %v", updated)
	}
}

func TestPrepareComposeCommandRejectsMultipleComposeFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"base.yaml", "local.yaml"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("services:\n  app:\n    image: example/app\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	args, cleanup, err := prepareComposeCommand(
		[]string{"docker", "compose", "--file", filepath.Join(dir, "base.yaml"), "--file", filepath.Join(dir, "local.yaml"), "up"},
		[]string{"SECRET"},
		[]string{"SECRET=value"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	if args[3] == filepath.Join(dir, "base.yaml") || args[5] == filepath.Join(dir, "local.yaml") {
		t.Fatalf("expected all Compose files to be replaced, got %v", args)
	}
}

func TestPrepareComposeCommandSupportsAttachedFileOptionsAndDockerOptions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	composePath := filepath.Join(dir, "deploy.yaml")
	if err := os.WriteFile(composePath, []byte("services:\n  app:\n    image: example/app\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	args, cleanup, err := prepareComposeCommand(
		[]string{"docker", "--context", "prod", "compose", "--file=" + composePath, "--project-name", "up", "up"},
		[]string{"SECRET"},
		[]string{"SECRET=value"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	if !strings.HasPrefix(args[4], "--file=") || strings.HasSuffix(args[4], composePath) {
		t.Fatalf("expected attached Compose file option to be replaced, got %v", args)
	}
	if args[len(args)-1] != "up" {
		t.Fatalf("expected actual Compose subcommand to remain intact, got %v", args)
	}
}

func TestPrepareComposeCommandLeavesOrdinaryDockerCommandsUnchanged(t *testing.T) {
	t.Parallel()

	args := []string{"docker", "run", "--rm", "alpine", "echo", "compose", "up"}
	updated, cleanup, err := prepareComposeCommand(args, []string{"SECRET"}, []string{"SECRET=value"})
	if err != nil {
		t.Fatal(err)
	}
	cleanup()

	if !slices.Equal(args, updated) {
		t.Fatalf("expected ordinary Docker command to remain unchanged, got %v", updated)
	}
}

func TestPrepareComposeCommandPreservesExplicitValuesAcrossFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.yaml")
	overridePath := filepath.Join(dir, "override.yaml")
	if err := os.WriteFile(basePath, []byte("services:\n  app:\n    environment:\n      TOKEN: explicit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overridePath, []byte("services:\n  app:\n    image: example/app\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	args, cleanup, err := prepareComposeCommand(
		[]string{"docker", "compose", "-f", basePath, "-f", overridePath, "up"},
		[]string{"TOKEN"},
		[]string{"TOKEN=from-infisical"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	contents, err := os.ReadFile(args[5])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), "TOKEN") {
		t.Fatal("override file should not replace the explicit value from the base file")
	}
}

func TestPrepareComposeCommandAllowsPartialOverrideFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.yaml")
	overridePath := filepath.Join(dir, "override.yaml")
	if err := os.WriteFile(basePath, []byte("services:\n  app:\n    image: example/app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overridePath, []byte("networks:\n  internal:\n    driver: bridge\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, cleanup, err := prepareComposeCommand(
		[]string{"docker", "compose", "-f", basePath, "-f", overridePath, "up"},
		[]string{"SECRET"},
		[]string{"SECRET=value"},
	)
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
}

func TestPrepareComposeCommandPreservesInheritedEnvironmentValues(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	composePath := filepath.Join(dir, "compose.yaml")
	contents := `services:
  api:
    image: example/api
    environment:
      TOKEN: explicit
  worker:
    extends:
      service: api
    image: example/worker
`
	if err := os.WriteFile(composePath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	args, cleanup, err := prepareComposeCommand(
		[]string{"docker", "compose", "--file", composePath, "up"},
		[]string{"TOKEN"},
		[]string{"TOKEN=from-infisical"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	generated, err := os.ReadFile(args[3])
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]interface{}
	if err := yaml.Unmarshal(generated, &document); err != nil {
		t.Fatal(err)
	}
	worker := document["services"].(map[string]interface{})["worker"].(map[string]interface{})
	environment, exists := worker["environment"].([]interface{})
	if !exists {
		return
	}
	for _, item := range environment {
		if item == "TOKEN" || strings.HasPrefix(item.(string), "TOKEN=") {
			t.Fatal("expected inherited TOKEN not to be added to the child service")
		}
	}
}

func TestPrepareComposeCommandDoesNotWriteSecretValues(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	composePath := filepath.Join(dir, "compose.yaml")
	if err := os.WriteFile(composePath, []byte("services:\n  app:\n    image: example/app\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	args, cleanup, err := prepareComposeCommand(
		[]string{"docker", "compose", "--file", composePath, "up"},
		[]string{"SECRET"},
		[]string{"SECRET=pa$WORD"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	contents, err := os.ReadFile(args[3])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), "pa$WORD") {
		t.Fatal("temporary Compose file contains a secret value")
	}
}
