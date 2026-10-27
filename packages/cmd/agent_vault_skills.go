package cmd

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var agentVaultSkillsCmd = &cobra.Command{
	Use:   "skills",
	Short: "Manage the skills Agent Vault delivers to agents",
}

var agentVaultSkillsPushCmd = &cobra.Command{
	Use:   "push <folder>",
	Short: "Create a skill from a folder, or publish the folder as its next version",
	Long: `Create a skill from a folder, or publish the folder as its next version.

The folder holds one skill, with SKILL.md at its root. The name in the SKILL.md header picks the skill: a new
name creates it, and an existing one gets a new version unless nothing changed.`,
	Example:               "  infisical agent-vault skills push ./skills/code-review",
	DisableFlagsInUseLine: true,
	Args:                  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		files, name, err := readAgentVaultSkillFolder(args[0])
		if err != nil {
			util.HandleError(err)
		}

		identity := resolveAgentVaultIdentityToken(cmd)
		httpClient, err := util.GetRestyClientWithCustomHeaders()
		if err != nil {
			util.HandleError(err, "Failed to build the API client")
		}
		httpClient.SetAuthToken(identity)

		result, err := pushAgentVaultSkill(httpClient, name, api.AgentVaultSkillFilesRequest{Files: files, Source: "cli"})
		if err != nil {
			util.HandleError(err)
		}
		fmt.Println(result)
	},
}

// pushAgentVaultSkill publishes a version of the skill with this name, or creates it. A create that loses a
// race with another push of the same name gets 409, and publishes to the skill the other push made.
func pushAgentVaultSkill(httpClient *resty.Client, name string, request api.AgentVaultSkillFilesRequest) (string, error) {
	publish := func(skillID string) (string, error) {
		published, err := api.CallPublishAgentVaultSkillVersion(httpClient, skillID, request)
		if err != nil {
			return "", fmt.Errorf("unable to publish a new version of %q: %w", name, err)
		}
		if published.Unchanged {
			return fmt.Sprintf("%s: unchanged (v%d)", name, published.Version.Version), nil
		}
		return fmt.Sprintf("%s: v%d", name, published.Version.Version), nil
	}
	find := func() (string, error) {
		listed, err := api.CallListAgentVaultSkillsByName(httpClient, name)
		if err != nil {
			return "", fmt.Errorf("unable to look up the skill %q: %w", name, err)
		}
		for _, skill := range listed.Skills {
			if skill.Name == name {
				return skill.ID, nil
			}
		}
		return "", nil
	}

	skillID, err := find()
	if err != nil {
		return "", err
	}
	if skillID != "" {
		return publish(skillID)
	}

	created, err := api.CallCreateAgentVaultSkill(httpClient, request)
	var apiErr *api.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusConflict {
		if existing, findErr := find(); findErr == nil && existing != "" {
			return publish(existing)
		}
	}
	if err != nil {
		return "", fmt.Errorf("unable to create the skill %q: %w", name, err)
	}
	return fmt.Sprintf("%s: created v%d", created.Skill.Name, created.Version.Version), nil
}

// readAgentVaultSkillFolder reads every regular file under dir. Limits are left to Infisical, which owns them.
func readAgentVaultSkillFolder(dir string) ([]api.AgentVaultSkillFile, string, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, "", fmt.Errorf("unable to read the skill folder: %w", err)
	}
	if !info.IsDir() {
		return nil, "", fmt.Errorf("%s is not a folder; pass the folder that holds SKILL.md", dir)
	}

	// WalkDir does not follow a symlinked root, so a folder reached through a link would read as one file.
	// Links inside the folder are still refused below.
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, "", fmt.Errorf("unable to read the skill folder: %w", err)
	}

	var files []api.AgentVaultSkillFile
	var skillMd []byte
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path != root && strings.HasPrefix(entry.Name(), ".") {
			// Hidden entries are tooling (.git, .DS_Store), never part of the skill.
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !entry.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file; a skill holds only files and folders", rel)
		}
		fileInfo, err := entry.Info()
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		mode := "0644"
		if fileInfo.Mode().Perm()&0o111 != 0 {
			mode = "0755"
		}
		if rel == "SKILL.md" {
			skillMd = content
		}
		files = append(files, api.AgentVaultSkillFile{Path: rel, Mode: mode, ContentBase64: base64.StdEncoding.EncodeToString(content)})
		return nil
	})
	if err != nil {
		return nil, "", fmt.Errorf("unable to read the skill folder: %w", err)
	}
	if skillMd == nil {
		return nil, "", fmt.Errorf("%s has no SKILL.md at its root", dir)
	}
	name, err := agentVaultSkillName(skillMd)
	if err != nil {
		return nil, "", err
	}
	return files, name, nil
}

// Only the name is read here, to find the skill. Infisical parses and validates the whole header.
func agentVaultSkillName(skillMd []byte) (string, error) {
	lines := strings.Split(string(bytes.TrimPrefix(skillMd, []byte("\ufeff"))), "\n")
	isDelimiter := func(line string) bool { return strings.TrimRight(line, " \t\r") == "---" }
	end := slices.IndexFunc(lines[1:], isDelimiter)
	if !isDelimiter(lines[0]) || end < 0 {
		return "", errors.New("SKILL.md must start with a header between '---' lines that sets name")
	}
	var header map[string]any
	if err := yaml.Unmarshal([]byte(strings.Join(lines[1:end+1], "\n")), &header); err != nil {
		return "", fmt.Errorf("the SKILL.md header is not valid YAML: %w", err)
	}
	name, _ := header["name"].(string)
	if strings.TrimSpace(name) == "" {
		return "", errors.New("the SKILL.md header does not set name")
	}
	return name, nil
}

func init() {
	agentVaultSkillsPushCmd.Flags().String("client-id", "", "universal auth client id of the machine identity to push as (falls back to INFISICAL_UNIVERSAL_AUTH_CLIENT_ID)")
	agentVaultSkillsPushCmd.Flags().String("client-secret", "", "universal auth client secret of that machine identity (falls back to INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET)")

	agentVaultSkillsCmd.AddCommand(agentVaultSkillsPushCmd)
	agentVaultCmd.AddCommand(agentVaultSkillsCmd)
}
