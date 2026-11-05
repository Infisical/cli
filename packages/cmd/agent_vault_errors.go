package cmd

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
)

const (
	errCodeAccessBundleRequired = "access_bundle_required"
	errCodeInvalidAccessBundle  = "invalid_access_bundle"
	errCodeInvalidProjectID     = "invalid_project_id"
)

func errAgentVaultInvalidOutput(format string) *util.CLIError {
	return &util.CLIError{Code: errCodeInvalidFlagValue,
		Message: fmt.Sprintf("--output must be json or yaml, not %s: leave it out to print only the token.", quoted(format, "format"))}
}

func errAgentVaultAccessBundleRequired() *util.CLIError {
	return &util.CLIError{Code: errCodeAccessBundleRequired,
		Message: fmt.Sprintf("An access bundle is required: pass --access-bundle <name> or set %s.", agentVaultAccessBundleEnv)}
}

func errAgentVaultEmptyAccessBundle() *util.CLIError {
	return &util.CLIError{Code: errCodeInvalidFlagValue,
		Message: `--access-bundle was given but names no bundle: pass a name like "coding-agent".`}
}

func errAgentVaultOneAccessBundle() *util.CLIError {
	return &util.CLIError{Code: errCodeInvalidFlagValue,
		Message: "A session carries one access bundle: pass --access-bundle once."}
}

func errAgentVaultInvalidAccessBundle(name string, source agentVaultSource) *util.CLIError {
	return &util.CLIError{Code: errCodeInvalidAccessBundle,
		Message: fmt.Sprintf(`%s from %s is not an access bundle name: names are lowercase letters, numbers and hyphens, for example "coding-agent".`,
			quoted(name, "access bundle"), agentVaultSourceName(source, "--access-bundle", agentVaultAccessBundleEnv))}
}

// An empty --project-id is usually "$PROJECT" with the variable unset, so it never falls through to a
// project the operator did not name.
func errAgentVaultEmptyProjectID() *util.CLIError {
	return &util.CLIError{Code: errCodeInvalidFlagValue,
		Message: fmt.Sprintf("--project-id was given but is empty: pass the Agent Vault project's ID, or drop the flag and set %s.", agentVaultProjectIDEnv)}
}

func errAgentVaultProjectRequired() *util.CLIError {
	return &util.CLIError{Code: errCodeProjectRequired,
		Message: fmt.Sprintf("No Agent Vault project is set: pass --project-id, or set %s or %s.", agentVaultProjectIDEnv, util.INFISICAL_PROJECT_ID_NAME)}
}

func errAgentVaultInvalidProjectID(value, source string) *util.CLIError {
	return &util.CLIError{Code: errCodeInvalidProjectID,
		Message: fmt.Sprintf("%s from %s is not a project ID: copy the ID from the Agent Vault project's settings in Infisical.", quoted(value, "project ID"), source)}
}

// INFISICAL_PROJECT_ID is often already set for Secrets Management, and the server answers 404 for a project
// that is not an Agent Vault one, so a project from there gets the hint to use the Agent Vault variable.
func errAgentVaultProjectNotFound(project agentVaultProject, cause error) *util.CLIError {
	message := fmt.Sprintf("Agent Vault project %s from %s doesn't exist, or you don't have access to it.", quoted(project.ID, "project ID"), project.Source)
	if project.Source == util.INFISICAL_PROJECT_ID_NAME {
		message += fmt.Sprintf(" %s may name a Secrets Management project: set %s or pass --project-id with the Agent Vault project's ID.",
			util.INFISICAL_PROJECT_ID_NAME, agentVaultProjectIDEnv)
	} else {
		message += " Copy the ID from the Agent Vault project's settings in Infisical."
	}
	return &util.CLIError{Code: errCodeProjectNotFound, Cause: cause, Message: message}
}

// A non-member is told the same as for a project that doesn't exist, without the ID, so the error can't be used to
// confirm one.
func errAgentVaultProjectNotAMember(project agentVaultProject, cause error) *util.CLIError {
	return &util.CLIError{
		Code:    errCodeProjectNotFound,
		Cause:   cause,
		Message: fmt.Sprintf("The Agent Vault project from %s doesn't exist, or you don't have access to it.", project.Source),
	}
}

// classifyAgentVaultAPIError is classifyAPIError for a request scoped to one Agent Vault project. A 404 from a
// route the backend doesn't have yet is left alone, so an older Infisical still prints its own answer.
func classifyAgentVaultAPIError(err error, project agentVaultProject) error {
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) {
		return err
	}
	if apiErr.StatusCode == http.StatusForbidden && apiErr.Name == "ProjectMembershipNotFound" {
		return errAgentVaultProjectNotAMember(project, err)
	}
	var notFound func(cause error) *util.CLIError
	// The route-missing answer is named "Not Found" and the app's own 404s "NotFound", so the name tells them apart
	// without reading the message.
	if !(apiErr.StatusCode == http.StatusNotFound && apiErr.Name == infisicalRouteMissingName) {
		notFound = func(cause error) *util.CLIError { return errAgentVaultProjectNotFound(project, cause) }
	}
	return classifyAPIError(err, errorScope{ProjectID: project.ID}, notFound)
}
