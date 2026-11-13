package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Infisical/infisical-merge/packages/agentvault"
	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
)

const (
	errCodeAccessBundleRequired   = "access_bundle_required"
	errCodeAccessBundleNotGranted = "access_bundle_not_granted"
	errCodeInvalidAccessBundle    = "invalid_access_bundle"
	errCodeInvalidProjectID       = "invalid_project_id"

	errCodeSessionTokenRequired = "session_token_required"
	errCodeProxyRequired        = "proxy_required"
	errCodeProxyUnreachable     = "proxy_unreachable"
	errCodeProxyUntrusted       = "proxy_untrusted"
	errCodeProxyNotSupported    = "proxy_not_supported"
	errCodeServiceNotFound      = "service_not_found"
	errCodeNoServices           = "no_services"
	errCodeServiceRefused       = "service_refused"
	errCodeSessionInvalid       = "session_invalid"
	errCodeLocalPortUnavailable = "local_port_unavailable"
)

func errAgentVaultInvalidOutput(format string) *util.CLIError {
	return &util.CLIError{Code: errCodeInvalidFlagValue,
		Message: fmt.Sprintf("--output must be json or yaml, not %s: leave it out to print only the token.", quoted(format, "format"))}
}

func errAgentVaultAccessBundleRequired() *util.CLIError {
	return &util.CLIError{Code: errCodeAccessBundleRequired,
		Message: fmt.Sprintf("An access bundle is required: pass --access-bundle <name> or set %s.", agentVaultAccessBundleEnv)}
}

func errAgentVaultAccessBundleNotGranted(bundle string, cause error) *util.CLIError {
	return &util.CLIError{Code: errCodeAccessBundleNotGranted, Cause: cause,
		Message: fmt.Sprintf("Access bundle %s isn't granted to you in this Agent Vault project, or doesn't exist. Check the name, or ask an Agent Vault admin to grant it.", quoted(bundle, "access bundle"))}
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
// route the backend doesn't have yet is left alone, so an older Infisical still prints its own answer. accessBundle
// is the bundle the request named, or empty when it named none.
func classifyAgentVaultAPIError(err error, project agentVaultProject, accessBundle string) error {
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) {
		return err
	}
	if apiErr.StatusCode == http.StatusForbidden && apiErr.Name == "ProjectMembershipNotFound" {
		return errAgentVaultProjectNotAMember(project, err)
	}
	if apiErr.StatusCode == http.StatusBadRequest && apiErr.Name == "AccessBundleNotGranted" && accessBundle != "" {
		return errAgentVaultAccessBundleNotGranted(accessBundle, err)
	}
	var notFound func(cause error) *util.CLIError
	// The route-missing answer is named "Not Found" and the app's own 404s "NotFound", so the name tells them apart
	// without reading the message.
	if !(apiErr.StatusCode == http.StatusNotFound && apiErr.Name == infisicalRouteMissingName) {
		notFound = func(cause error) *util.CLIError { return errAgentVaultProjectNotFound(project, cause) }
	}
	return classifyAPIError(err, errorScope{ProjectID: project.ID}, notFound)
}

func errAgentVaultConnectEmptyFlag(flag, env string) *util.CLIError {
	message := fmt.Sprintf("%s was given but is empty: pass a value", flag)
	if env != "" {
		message += fmt.Sprintf(", or drop the flag and set %s", env)
	}
	return &util.CLIError{Code: errCodeInvalidFlagValue, Message: message + "."}
}

func errAgentVaultConnectSessionTokenRequired() *util.CLIError {
	return &util.CLIError{Code: errCodeSessionTokenRequired,
		Message: fmt.Sprintf("A session token is required: pass --session-token or set %s. 'infisical agent-vault run' sets it for the agent.", agentVaultSessionTokenEnv)}
}

func errAgentVaultConnectProxyRequired() *util.CLIError {
	return &util.CLIError{Code: errCodeProxyRequired,
		Message: fmt.Sprintf("The proxy address is required: pass --proxy <host:port> or set %s. 'infisical agent-vault run' sets it for the agent.", agentVaultProxyAddressEnv)}
}

func errAgentVaultConnectProxyUnreachable(proxyAddr string, cause error) *util.CLIError {
	return &util.CLIError{Code: errCodeProxyUnreachable, Cause: cause,
		Message: fmt.Sprintf("Unable to reach the Agent Vault proxy at %s: check the address and that 'infisical agent-vault proxy' is running there.", proxyAddr)}
}

const agentVaultFingerprintLocation = "the Certificate Authority column on the Proxies page in Infisical"

func errAgentVaultConnectProxyUntrusted(proxyAddr string, cause error) *util.CLIError {
	return &util.CLIError{Code: errCodeProxyUntrusted, Cause: cause,
		Message: fmt.Sprintf("Unable to verify the Agent Vault proxy at %s, so the session token wasn't sent to the proxy: pass --ca-fingerprint SHA256:... with the fingerprint shown in %s.", proxyAddr, agentVaultFingerprintLocation)}
}

func errAgentVaultConnectFingerprintMismatch(proxyAddr, served string) *util.CLIError {
	return &util.CLIError{Code: errCodeProxyUntrusted,
		Message: fmt.Sprintf("The proxy at %s serves a certificate authority with fingerprint %s, not the one passed in --ca-fingerprint, so the session token wasn't sent to the proxy. Check the fingerprint in %s.", proxyAddr, served, agentVaultFingerprintLocation)}
}

func errAgentVaultConnectFingerprintsNotListed(proxyAddr string, cause error) *util.CLIError {
	return &util.CLIError{Code: errCodeProxyUntrusted, Cause: cause,
		Message: fmt.Sprintf("This Infisical doesn't list proxy fingerprints yet, so the proxy at %s couldn't be verified and the session token wasn't sent to it: pass --ca-fingerprint SHA256:... with the fingerprint shown in %s.", proxyAddr, agentVaultFingerprintLocation)}
}

func errAgentVaultConnectInfisicalUnreachable(proxyAddr, domain string, cause error) *util.CLIError {
	return &util.CLIError{Code: errCodeProxyUntrusted, Cause: cause,
		Message: fmt.Sprintf("Couldn't reach Infisical at %s to verify the proxy at %s, so the session token wasn't sent to the proxy: check --domain, or pass --ca-fingerprint SHA256:... with the fingerprint shown in %s.", domain, proxyAddr, agentVaultFingerprintLocation)}
}

func errAgentVaultConnectSessionUnknown(proxyAddr, domain string, cause error) *util.CLIError {
	return &util.CLIError{Code: errCodeProxyUntrusted, Cause: cause,
		Message: fmt.Sprintf("%s doesn't know this session token, so the proxy at %s couldn't be verified and the session token wasn't sent to it. If the session is on another Infisical instance, pass --domain, or pass --ca-fingerprint SHA256:... with the fingerprint shown in %s.", domain, proxyAddr, agentVaultFingerprintLocation)}
}

func errAgentVaultConnectSessionInvalid(cause error) *util.CLIError {
	return &util.CLIError{Code: errCodeSessionInvalid, Cause: cause,
		Message: "This session is no longer valid, or it belongs to a different Agent Vault project than the proxy: start a new session with 'infisical agent-vault sessions create', or run the agent again under 'infisical agent-vault run'."}
}

func errAgentVaultConnectPortNeedsOneService() *util.CLIError {
	return &util.CLIError{Code: errCodeInvalidFlagValue,
		Message: "--port works with one service: name one service, or leave --port out."}
}

func errAgentVaultConnectInvalidPort(port int) *util.CLIError {
	return &util.CLIError{Code: errCodeInvalidFlagValue,
		Message: fmt.Sprintf("--port must be between 1 and 65535, not %d: pass another port, or leave --port out to use a free one.", port)}
}

func errAgentVaultConnectLocalPort(service string, port int, cause error) *util.CLIError {
	if port != 0 {
		return &util.CLIError{Code: errCodeLocalPortUnavailable, Cause: cause,
			Message: fmt.Sprintf("Unable to open local port %d for %s: %s. Pass another --port, or leave it out to use a free one.", port, quoted(service, "service"), cause)}
	}
	return &util.CLIError{Code: errCodeLocalPortUnavailable, Cause: cause,
		Message: fmt.Sprintf("Unable to open a local port for %s: %s. Close programs you don't need, or raise the open file limit, and run the command again.", quoted(service, "service"), cause)}
}

func errAgentVaultConnectAllRefused() *util.CLIError {
	return &util.CLIError{Code: errCodeServiceRefused,
		Message: "The proxy refused every database and SSH service in this session, for the reasons printed above. Fix one of them, or ask an Agent Vault admin to."}
}

func errAgentVaultConnectNoServices() *util.CLIError {
	return &util.CLIError{Code: errCodeNoServices,
		Message: "This session has no database or SSH services: ask an Agent Vault admin to add one to the session's access bundle."}
}

func errAgentVaultConnectServiceNotFound(name string, available []agentvault.NativeServiceInfo) *util.CLIError {
	names := make([]string, len(available))
	for i, service := range available {
		names[i] = service.Name
	}
	return &util.CLIError{Code: errCodeServiceNotFound,
		Message: fmt.Sprintf("This session has no database or SSH service named %s: its services are %s. If you just added it, try again in a minute.", quoted(name, "service"), strings.Join(names, ", "))}
}

// The proxy's refusals are written for the person reading them, so they are passed on as they are.
func classifyAgentVaultConnectError(err error, proxyAddr string) error {
	var cliErr *util.CLIError
	if errors.As(err, &cliErr) {
		return err
	}
	if errors.Is(err, agentvault.ErrProxyTooOld) {
		return &util.CLIError{Code: errCodeProxyNotSupported, Cause: err,
			Message: fmt.Sprintf("The Agent Vault proxy at %s doesn't serve database and SSH services yet: update it to the latest Infisical CLI and restart it.", proxyAddr)}
	}
	var refused *agentvault.ProxyRefusedError
	if errors.As(err, &refused) && refused.SessionInvalid() {
		return errAgentVaultConnectSessionInvalid(err)
	}
	if errors.As(err, &refused) {
		message := strings.TrimSuffix(refused.Message, ".") + "."
		first, size := utf8.DecodeRuneInString(message)
		return &util.CLIError{Code: errCodeServiceRefused, Cause: err, Message: string(unicode.ToUpper(first)) + message[size:]}
	}
	return &util.CLIError{Code: errCodeProxyUnreachable, Cause: err,
		Message: fmt.Sprintf("The connection to the Agent Vault proxy at %s failed: %s.", proxyAddr, strings.TrimSuffix(err.Error(), "."))}
}
