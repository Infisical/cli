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

	if args[4] != "--file" || args[5] == composePath {
		t.Fatalf("expected Compose file argument to be replaced, got %v", args)
	}
	if _, err := os.Stat(args[5]); err != nil {
		t.Fatalf("temporary Compose file does not exist: %v", err)
	}

	contents, err := os.ReadFile(args[5])
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]interface{}
	if err := yaml.Unmarshal(contents, &document); err != nil {
		t.Fatal(err)
	}

	services := document["services"].(map[string]interface{})
	apiEnvironment := services["api"].(map[string]interface{})["environment"].(map[string]interface{})
	if secret, exists := apiEnvironment["SECRET"]; !exists || secret != nil {
		t.Fatalf("expected SECRET to be present as an unset Compose variable, got %v", secret)
	}
	if _, exists := apiEnvironment["EXISTING"]; exists {
		t.Fatal("expected explicit EXISTING value to stay out of the override")
	}
	if _, exists := apiEnvironment["TOKEN"]; exists {
		t.Fatal("expected explicit TOKEN value to stay out of the override")
	}
	workerEnvironment := services["worker"].(map[string]interface{})["environment"].(map[string]interface{})
	if secret, exists := workerEnvironment["SECRET"]; !exists || secret != nil {
		t.Fatalf("expected SECRET to be present as an unset Compose variable, got %v", secret)
	}
	if token, exists := workerEnvironment["TOKEN"]; !exists || token != nil {
		t.Fatalf("expected TOKEN to be injected into worker, got %v", token)
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

	if args[3] != filepath.Join(dir, "base.yaml") || args[5] != filepath.Join(dir, "local.yaml") {
		t.Fatalf("expected source Compose files to remain unchanged, got %v", args)
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

	if !strings.HasPrefix(args[4], "--file=") || !strings.HasSuffix(args[4], composePath) {
		t.Fatalf("expected attached Compose file option to remain unchanged, got %v", args)
	}
	if len(args) != 10 {
		t.Fatalf("expected generated Compose override to be added, got %v", args)
	}
	overridePath := args[8]
	if args[7] != "--file" || overridePath == composePath {
		t.Fatalf("expected generated override file to be appended, got %v", args)
	}
	override, err := os.ReadFile(overridePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(override), "SECRET: null") {
		t.Fatalf("expected generated override to request SECRET, got %s", override)
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

func TestPrepareComposeCommandFindsComposeAfterDockerOptions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	composePath := filepath.Join(dir, "compose.yaml")
	if err := os.WriteFile(composePath, []byte("services:\n  app:\n    image: example/app\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	args, cleanup, err := prepareComposeCommand(
		[]string{"docker", "--context", "prod", "compose", "--project-name", "example", "--file", composePath, "up"},
		[]string{"SECRET"},
		[]string{"SECRET=value"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	if !slices.Contains(args, "--file") {
		t.Fatalf("expected generated Compose override, got %v", args)
	}
}

func TestPrepareComposeCommandDoesNotRewriteComposeArgumentValues(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	composePath := filepath.Join(dir, "compose.yaml")
	if err := os.WriteFile(composePath, []byte("services:\n  app:\n    image: example/app\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	args, cleanup, err := prepareComposeCommand(
		[]string{"docker", "compose", "--project-name", "up", "--file", composePath, "up"},
		[]string{"SECRET"},
		[]string{"SECRET=value"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	if !slices.Contains(args, "--file") || args[2] != "--project-name" || args[3] != "up" {
		t.Fatalf("expected Compose option values to remain intact, got %v", args)
	}
	if len(args) != 9 || args[6] != "--file" || args[7] == composePath {
		t.Fatalf("expected generated override file to be inserted before up, got %v", args)
	}
	override, err := os.ReadFile(args[7])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(override), "SECRET: null") {
		t.Fatalf("expected generated override to request SECRET, got %s", override)
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

	if len(args) != 7 {
		t.Fatalf("expected source Compose files to remain unchanged, got %v", args)
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

	if len(args) != 5 {
		t.Fatalf("expected no override file for inherited TOKEN, got %v", args)
	}
}

func TestPrepareComposeCommandPreservesExternalInheritedEnvironmentValues(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	commonPath := filepath.Join(dir, "common.yaml")
	composePath := filepath.Join(dir, "compose.yaml")
	if err := os.WriteFile(commonPath, []byte(`services:
  base:
    environment:
      TOKEN: explicit
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(composePath, []byte(`services:
  worker:
    extends:
      file: common.yaml
      service: base
    image: example/worker
`), 0o600); err != nil {
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

	if len(args) != 5 {
		t.Fatalf("expected no override file for external inherited TOKEN, got %v", args)
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

	contents, err := os.ReadFile(args[5])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), "pa$WORD") {
		t.Fatal("temporary Compose file contains a secret value")
	}
}

func TestPrepareComposeCommandCleansUpOverrideFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	composePath := filepath.Join(dir, "compose.yaml")
	if err := os.WriteFile(composePath, []byte("services:\n  app:\n    image: example/app\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	args, cleanup, err := prepareComposeCommand(
		[]string{"docker", "compose", "--file", composePath, "up"},
		[]string{"SECRET"},
		[]string{"SECRET=value"},
	)
	if err != nil {
		t.Fatal(err)
	}
	tempPath := args[5]
	if _, err := os.Stat(tempPath); err != nil {
		t.Fatal(err)
	}
	cleanup()
	if _, err := os.Stat(tempPath); !os.IsNotExist(err) {
		t.Fatalf("expected temporary override to be removed, got %v", err)
	}
}
