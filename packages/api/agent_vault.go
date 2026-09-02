package api

import (
	"fmt"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/go-resty/resty/v2"
)

// The header carrying the session an agent is running with. A selector, not a second credential: the
// proxy's own bearer token is what authorizes the call.
const AgentVaultSessionHeader = "X-Infisical-Agent-Session"

type AgentVaultProxyConfig struct {
	UnmatchedHost string `json:"unmatchedHost"`
	BypassHosts   string `json:"bypassHosts"`
	PollInterval  int    `json:"pollInterval"`
}

type EnrollAgentVaultProxyRequest struct {
	EnrollmentToken   string `json:"enrollmentToken"`
	RootCaCertificate string `json:"rootCaCertificate"`
}

type EnrollAgentVaultProxyResponse struct {
	ProxyID     string                `json:"proxyId"`
	Name        string                `json:"name"`
	AccessToken string                `json:"accessToken"`
	Config      AgentVaultProxyConfig `json:"config"`
}

func CallEnrollAgentVaultProxy(httpClient *resty.Client, request EnrollAgentVaultProxyRequest) (EnrollAgentVaultProxyResponse, error) {
	var res EnrollAgentVaultProxyResponse
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/agent-vault/proxy/enroll", config.INFISICAL_URL))

	if err != nil {
		return EnrollAgentVaultProxyResponse{}, NewGenericRequestError("CallEnrollAgentVaultProxy", err)
	}
	if response.IsError() {
		return EnrollAgentVaultProxyResponse{}, NewAPIErrorWithResponse("CallEnrollAgentVaultProxy", response, nil)
	}
	return res, nil
}

type AgentVaultHeartbeatRequest struct {
	Version string `json:"version,omitempty"`
}

type AgentVaultHeartbeatResponse struct {
	Config AgentVaultProxyConfig `json:"config"`
}

func CallAgentVaultHeartbeat(httpClient *resty.Client, request AgentVaultHeartbeatRequest) (AgentVaultHeartbeatResponse, error) {
	var res AgentVaultHeartbeatResponse
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/agent-vault/proxy/heartbeat", config.INFISICAL_URL))

	if err != nil {
		return AgentVaultHeartbeatResponse{}, NewGenericRequestError("CallAgentVaultHeartbeat", err)
	}
	if response.IsError() {
		return AgentVaultHeartbeatResponse{}, NewAPIErrorWithResponse("CallAgentVaultHeartbeat", response, nil)
	}
	return res, nil
}

type AgentVaultCredential struct {
	Type         string `json:"type"`
	HeaderName   string `json:"headerName,omitempty"`
	HeaderPrefix string `json:"headerPrefix,omitempty"`
	Value        string `json:"value,omitempty"`
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
}

type AgentVaultConnection struct {
	ID               string               `json:"id"`
	Name             string               `json:"name"`
	AccessBundleName string               `json:"accessBundleName"`
	HostPattern      string               `json:"hostPattern"`
	Credential       AgentVaultCredential `json:"credential"`
}

type ResolveAgentVaultSessionResponse struct {
	SessionID string `json:"sessionId"`
	ExpiresAt string `json:"expiresAt"`
	// Ordered by bundle position, then connection name. An empty list is a valid session whose actor has
	// lost every access bundle, not an error.
	Connections []AgentVaultConnection `json:"connections"`
}

func CallResolveAgentVaultSession(httpClient *resty.Client, sessionToken string) (ResolveAgentVaultSessionResponse, error) {
	var res ResolveAgentVaultSessionResponse
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		SetHeader(AgentVaultSessionHeader, sessionToken).
		Post(fmt.Sprintf("%v/v1/agent-vault/proxy/resolve", config.INFISICAL_URL))

	if err != nil {
		return ResolveAgentVaultSessionResponse{}, NewGenericRequestError("CallResolveAgentVaultSession", err)
	}
	if response.IsError() {
		return ResolveAgentVaultSessionResponse{}, NewAPIErrorWithResponse("CallResolveAgentVaultSession", response, nil)
	}
	return res, nil
}
