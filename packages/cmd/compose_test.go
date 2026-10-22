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
		[]string{"SECRET", "EXISTING"},
		[]string{"SECRET=from-infisical", "EXISTING=from-infisical"},
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
	if apiEnvironment["SECRET"] != nil {
		t.Fatalf("expected SECRET in api environment, got %v", apiEnvironment["SECRET"])
	}
	if apiEnvironment["EXISTING"] != "explicit" {
		t.Fatalf("expected explicit api value to win, got %v", apiEnvironment["EXISTING"])
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
