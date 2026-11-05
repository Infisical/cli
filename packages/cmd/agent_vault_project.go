package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

const agentVaultProjectIDEnv = "INFISICAL_AGENT_VAULT_PROJECT_ID"

type agentVaultProject struct {
	ID string
	// The flag or the variable the ID came from, as messages name it.
	Source   string
	FromFlag bool
}

// resolveAgentVaultProject picks the Agent Vault project from --project-id, then INFISICAL_AGENT_VAULT_PROJECT_ID,
// then INFISICAL_PROJECT_ID. The last is shared with Secrets Management, so it comes after the variable that can
// only name an Agent Vault project.
func resolveAgentVaultProject(cmd *cobra.Command) (agentVaultProject, error) {
	if cmd.Flags().Changed("project-id") {
		value, err := cmd.Flags().GetString("project-id")
		if err != nil {
			return agentVaultProject{}, fmt.Errorf("unable to read --project-id: %w", err)
		}
		// Same reasoning as the empty --session-token: "$PROJECT" with the variable unset should not fall
		// through to a project the operator did not name.
		if strings.TrimSpace(value) == "" {
			return agentVaultProject{}, fmt.Errorf("--project-id was given but is empty; pass the Agent Vault project's ID, or drop the flag and set %s", agentVaultProjectIDEnv)
		}
		project, err := agentVaultProjectFrom(value, "--project-id")
		project.FromFlag = true
		return project, err
	}

	project, found, err := resolveAgentVaultProjectFromEnvironment()
	if err != nil {
		return agentVaultProject{}, err
	}
	if !found {
		return agentVaultProject{}, fmt.Errorf(
			"no Agent Vault project is set. Pass --project-id, or set %s or %s",
			agentVaultProjectIDEnv, util.INFISICAL_PROJECT_ID_NAME)
	}
	return project, nil
}

// resolveAgentVaultProjectFromEnvironment is every source but the flag, for commands that have none.
func resolveAgentVaultProjectFromEnvironment() (project agentVaultProject, found bool, err error) {
	if value := strings.TrimSpace(os.Getenv(agentVaultProjectIDEnv)); value != "" {
		project, err = agentVaultProjectFrom(value, agentVaultProjectIDEnv)
		return project, true, err
	}

	if value := strings.TrimSpace(os.Getenv(util.INFISICAL_PROJECT_ID_NAME)); value != "" {
		project, err = agentVaultProjectFrom(value, util.INFISICAL_PROJECT_ID_NAME)
		return project, true, err
	}
	return agentVaultProject{}, false, nil
}

func agentVaultProjectFrom(value, source string) (agentVaultProject, error) {
	value = strings.TrimSpace(value)
	// uuid.Parse also takes the braced and urn: spellings, which the server would refuse.
	if _, err := uuid.Parse(value); err != nil || len(value) != 36 {
		return agentVaultProject{}, fmt.Errorf("%q from %s is not a project ID; copy the ID from the Agent Vault project's settings in Infisical", value, source)
	}
	return agentVaultProject{ID: strings.ToLower(value), Source: source}, nil
}

// A flag was typed for this run; anything else is ambient, so the command says which project it picked up.
func echoAgentVaultProject(project agentVaultProject) {
	if !project.FromFlag {
		util.PrintlnStderr(fmt.Sprintf("Agent Vault project %s from %s", project.ID, project.Source))
	}
}

// INFISICAL_PROJECT_ID is often already set for Secrets Management, and the server answers 404 for a project
// that is not an Agent Vault one.
func agentVaultProjectHints(err error, project agentVaultProject) []string {
	var apiErr *api.APIError
	if project.Source != util.INFISICAL_PROJECT_ID_NAME || !errors.As(err, &apiErr) ||
		apiErr.StatusCode != http.StatusNotFound || apiErr.DocumentationURL != "" {
		return nil
	}
	return []string{fmt.Sprintf(
		"The project came from %s, which may name a Secrets Management project. Set %s or pass --project-id with the Agent Vault project's ID.",
		util.INFISICAL_PROJECT_ID_NAME, agentVaultProjectIDEnv)}
}

func agentVaultProjectSourceKind(project agentVaultProject) string {
	switch project.Source {
	case "--project-id":
		return "flag"
	case agentVaultProjectIDEnv:
		return "agent-vault-env"
	case util.INFISICAL_PROJECT_ID_NAME:
		return "project-env"
	default:
		return "unknown"
	}
}

func printAgentVaultProjectForProfile() {
	project, found, err := resolveAgentVaultProjectFromEnvironment()
	switch {
	case err != nil:
		util.PrintlnStdout("Agent Vault project:", err.Error())
	case found:
		util.PrintlnStdout("Agent Vault project:", project.ID)
		util.PrintlnStdout("Agent Vault project via:", project.Source)
	}
}
