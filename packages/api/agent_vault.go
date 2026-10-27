package api

import (
	"context"
	"fmt"
	"net/url"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/go-resty/resty/v2"
)

// A selector, not a second credential: the proxy's own bearer token is what authorizes the call.
const AgentVaultSessionHeader = "X-Infisical-Agent-Session"

type AgentVaultProxyConfig struct {
	TrafficPolicy string `json:"trafficPolicy"`
	AllowedHosts  string `json:"allowedHosts"`
	PollInterval  int    `json:"pollInterval"`
}

type AgentVaultProxyRootCa struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"privateKey"`
}

type AgentVaultProxyBootstrapRequest struct {
	ServedCaCertificate string `json:"servedCaCertificate,omitempty"`
}

type AgentVaultProxyBootstrapResponse struct {
	ProxyID string                 `json:"proxyId"`
	Name    string                 `json:"name"`
	Config  AgentVaultProxyConfig  `json:"config"`
	RootCa  *AgentVaultProxyRootCa `json:"rootCa"`
}

func CallAgentVaultProxyBootstrap(httpClient *resty.Client, request AgentVaultProxyBootstrapRequest) (AgentVaultProxyBootstrapResponse, error) {
	var res AgentVaultProxyBootstrapResponse
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/agent-vault/proxy/bootstrap", config.INFISICAL_URL))

	if err != nil {
		return AgentVaultProxyBootstrapResponse{}, NewGenericRequestError("CallAgentVaultProxyBootstrap", err)
	}
	if response.IsError() {
		return AgentVaultProxyBootstrapResponse{}, NewAPIErrorWithResponse("CallAgentVaultProxyBootstrap", response, nil)
	}
	return res, nil
}

type AgentVaultHeartbeatResponse struct {
	Config AgentVaultProxyConfig `json:"config"`
}

func CallAgentVaultHeartbeat(httpClient *resty.Client) (AgentVaultHeartbeatResponse, error) {
	var res AgentVaultHeartbeatResponse
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
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
	// "oauth" marks a token Infisical can refresh; every other credential leaves it empty.
	Source string `json:"source,omitempty"`
}

type AgentVaultCustomHeader struct {
	Name   string `json:"name"`
	Prefix string `json:"prefix,omitempty"`
	Value  string `json:"value"`
}

type AgentVaultSubstitution struct {
	Placeholder string   `json:"placeholder"`
	Surfaces    []string `json:"surfaces"`
	Value       string   `json:"value"`
}

type AgentVaultService struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Type             string `json:"type"`
	AccessBundleName string `json:"accessBundleName"`
	HostPattern      string `json:"hostPattern"`
	// A nil slice means unrestricted, which is what JSON null decodes to.
	AllowedMethods      []string                 `json:"allowedMethods"`
	AllowedPathPrefixes []string                 `json:"allowedPathPrefixes"`
	Credential          AgentVaultCredential     `json:"credential"`
	CustomHeaders       []AgentVaultCustomHeader `json:"customHeaders"`
	Substitutions       []AgentVaultSubstitution `json:"substitutions"`
	// The service takes part of its credential from each member and the session's owner has not set their personal values.
	// Older servers never send it, which decodes to false.
	PersonalValuesMissing bool `json:"personalValuesMissing"`
}

type AgentVaultSessionLogGrant struct {
	Enabled    bool   `json:"enabled"`
	SessionKey string `json:"sessionKey"`
}

type ResolveAgentVaultSessionRequest struct {
	HasSessionLogKey bool `json:"hasSessionLogKey"`
}

type ResolveAgentVaultSessionResponse struct {
	SessionID   string                    `json:"sessionId"`
	ExpiresAt   string                    `json:"expiresAt"`
	Services    []AgentVaultService       `json:"services"`
	SessionLogs AgentVaultSessionLogGrant `json:"sessionLogs"`
}

func CallResolveAgentVaultSession(httpClient *resty.Client, sessionToken string, request ResolveAgentVaultSessionRequest) (ResolveAgentVaultSessionResponse, error) {
	var res ResolveAgentVaultSessionResponse
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		SetHeader(AgentVaultSessionHeader, sessionToken).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/agent-vault/proxy/resolve", config.INFISICAL_URL))

	if err != nil {
		return ResolveAgentVaultSessionResponse{}, NewGenericRequestError("CallResolveAgentVaultSession", err)
	}
	if response.IsError() {
		return ResolveAgentVaultSessionResponse{}, NewAPIErrorWithResponse("CallResolveAgentVaultSession", response, nil)
	}
	return res, nil
}

// The proxy calls these while an agent's request waits, and keeps a failed refresh's error for a few seconds,
// so neither may buffer an unbounded body. A credential answer is a few kilobytes at most.
const agentVaultCredentialResponseLimit = 64 << 10

type RefreshAgentVaultServiceCredentialRequest struct {
	HostPattern       string `json:"hostPattern"`
	RejectedTokenHash string `json:"rejectedTokenHash"`
}

type RefreshAgentVaultServiceCredentialResponse struct {
	Credential AgentVaultCredential `json:"credential"`
	Status     string               `json:"status"`
}

func CallRefreshAgentVaultServiceCredential(httpClient *resty.Client, sessionToken, serviceID string, request RefreshAgentVaultServiceCredentialRequest) (RefreshAgentVaultServiceCredentialResponse, error) {
	var res RefreshAgentVaultServiceCredentialResponse
	response, err := httpClient.
		R().
		SetResponseBodyLimit(agentVaultCredentialResponseLimit).
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		SetHeader(AgentVaultSessionHeader, sessionToken).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/agent-vault/proxy/services/%s/credential-refresh", config.INFISICAL_URL, url.PathEscape(serviceID)))

	if err != nil {
		return RefreshAgentVaultServiceCredentialResponse{}, NewGenericRequestError("CallRefreshAgentVaultServiceCredential", err)
	}
	if response.IsError() {
		return RefreshAgentVaultServiceCredentialResponse{}, NewAPIErrorWithResponse("CallRefreshAgentVaultServiceCredential", response, nil)
	}
	return res, nil
}

type ReportAgentVaultServiceMissingScopesRequest struct {
	HostPattern       string   `json:"hostPattern"`
	RejectedTokenHash string   `json:"rejectedTokenHash"`
	RequiredScopes    []string `json:"requiredScopes"`
}

func CallReportAgentVaultServiceMissingScopes(httpClient *resty.Client, sessionToken, serviceID string, request ReportAgentVaultServiceMissingScopesRequest) error {
	response, err := httpClient.
		R().
		SetResponseBodyLimit(agentVaultCredentialResponseLimit).
		SetHeader("User-Agent", USER_AGENT).
		SetHeader(AgentVaultSessionHeader, sessionToken).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/agent-vault/proxy/services/%s/missing-scopes", config.INFISICAL_URL, url.PathEscape(serviceID)))

	if err != nil {
		return NewGenericRequestError("CallReportAgentVaultServiceMissingScopes", err)
	}
	if response.IsError() {
		return NewAPIErrorWithResponse("CallReportAgentVaultServiceMissingScopes", response, nil)
	}
	return nil
}

type CreateAgentVaultSessionLogChunkRequest struct {
	ChunkID          string `json:"chunkId"`
	EndedAt          string `json:"endedAt"`
	CiphertextBytes  int    `json:"ciphertextBytes"`
	CiphertextSha256 string `json:"ciphertextSha256"`
	RecordCount      int    `json:"recordCount"`
}

type CreateAgentVaultSessionLogChunkResponse struct {
	UploadURL        string `json:"uploadUrl"`
	ExpiresInSeconds int    `json:"expiresInSeconds"`
}

func CallCreateAgentVaultSessionLogChunk(ctx context.Context, httpClient *resty.Client, sessionID string, request CreateAgentVaultSessionLogChunkRequest) (CreateAgentVaultSessionLogChunkResponse, error) {
	var res CreateAgentVaultSessionLogChunkResponse
	response, err := httpClient.
		R().
		SetContext(ctx).
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/agent-vault/proxy/sessions/%s/logs/chunks", config.INFISICAL_URL, sessionID))

	if err != nil {
		return CreateAgentVaultSessionLogChunkResponse{}, NewGenericRequestError("CallCreateAgentVaultSessionLogChunk", err)
	}
	if response.IsError() {
		return CreateAgentVaultSessionLogChunkResponse{}, NewAPIErrorWithResponse("CallCreateAgentVaultSessionLogChunk", response, nil)
	}
	return res, nil
}

type CreateAgentVaultSessionRequest struct {
	AccessBundles []string `json:"accessBundles"`
	TTL           string   `json:"ttl"`
	Label         string   `json:"label,omitempty"`
}

type AgentVaultSession struct {
	ID        string  `json:"id"`
	Token     string  `json:"token"`
	ExpiresAt *string `json:"expiresAt"`
}

type CreateAgentVaultSessionResponse struct {
	Session AgentVaultSession `json:"session"`
}

func CallCreateAgentVaultSession(httpClient *resty.Client, request CreateAgentVaultSessionRequest) (CreateAgentVaultSessionResponse, error) {
	var res CreateAgentVaultSessionResponse
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/agent-vault/sessions", config.INFISICAL_URL))

	if err != nil {
		return CreateAgentVaultSessionResponse{}, NewGenericRequestError("CallCreateAgentVaultSession", err)
	}
	if response.IsError() {
		return CreateAgentVaultSessionResponse{}, NewAPIErrorWithResponse("CallCreateAgentVaultSession", response, nil)
	}
	return res, nil
}

func CallRevokeAgentVaultSession(httpClient *resty.Client, sessionID string) error {
	response, err := httpClient.
		R().
		SetHeader("User-Agent", USER_AGENT).
		Post(fmt.Sprintf("%v/v1/agent-vault/sessions/%s/revoke", config.INFISICAL_URL, sessionID))

	if err != nil {
		return NewGenericRequestError("CallRevokeAgentVaultSession", err)
	}
	if response.IsError() {
		return NewAPIErrorWithResponse("CallRevokeAgentVaultSession", response, nil)
	}
	return nil
}
