package api

import (
	"fmt"

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

type LoginAgentVaultProxyRequest struct {
	Method            string `json:"method"`
	Token             string `json:"token"`
	RootCaCertificate string `json:"rootCaCertificate"`
}

type LoginAgentVaultProxyResponse struct {
	ProxyID     string                `json:"proxyId"`
	Name        string                `json:"name"`
	AccessToken string                `json:"accessToken"`
	Config      AgentVaultProxyConfig `json:"config"`
}

func CallLoginAgentVaultProxy(httpClient *resty.Client, request LoginAgentVaultProxyRequest) (LoginAgentVaultProxyResponse, error) {
	var res LoginAgentVaultProxyResponse
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/agent-vault/proxy/login", config.INFISICAL_URL))

	if err != nil {
		return LoginAgentVaultProxyResponse{}, NewGenericRequestError("CallLoginAgentVaultProxy", err)
	}
	if response.IsError() {
		return LoginAgentVaultProxyResponse{}, NewAPIErrorWithResponse("CallLoginAgentVaultProxy", response, nil)
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
	AccessBundleName string `json:"accessBundleName"`
	HostPattern      string `json:"hostPattern"`
	// A nil slice means unrestricted, which is what JSON null decodes to.
	AllowedMethods      []string                 `json:"allowedMethods"`
	AllowedPathPrefixes []string                 `json:"allowedPathPrefixes"`
	Credential          AgentVaultCredential     `json:"credential"`
	CustomHeaders       []AgentVaultCustomHeader `json:"customHeaders"`
	Substitutions       []AgentVaultSubstitution `json:"substitutions"`
}

// AgentVaultActivityGrant is what a session needs in order to have its activity recorded. SessionKey is
// sent exactly once per session: the proxy reports that it already holds one and Infisical skips the
// unwrap, which is a KMS round trip, on every poll after the first.
type AgentVaultActivityGrant struct {
	Enabled    bool   `json:"enabled"`
	SessionKey string `json:"sessionKey"`
	ProjectID  string `json:"projectId"`
}

type ResolveAgentVaultSessionRequest struct {
	HasActivityKey bool `json:"hasActivityKey"`
}

type ResolveAgentVaultSessionResponse struct {
	SessionID string                  `json:"sessionId"`
	ExpiresAt string                  `json:"expiresAt"`
	Services  []AgentVaultService     `json:"services"`
	Activity  AgentVaultActivityGrant `json:"activity"`
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

// CreateAgentVaultActivityChunkRequest is the metadata for one sealed chunk. The ciphertext itself never
// passes through Infisical: the response carries a presigned URL to PUT it straight to the customer's
// bucket. Re-sending the same ChunkID is idempotent, which is what makes a failed upload safe to retry.
type CreateAgentVaultActivityChunkRequest struct {
	ChunkID         string `json:"chunkId"`
	StartedAt       string `json:"startedAt"`
	EndedAt         string `json:"endedAt"`
	FirstSeq        uint64 `json:"firstSeq"`
	LastSeq         uint64 `json:"lastSeq"`
	RecordCount     int    `json:"recordCount"`
	DroppedCount    uint64 `json:"droppedCount"`
	CiphertextBytes int    `json:"ciphertextBytes"`
	IV              string `json:"iv"`
}

type CreateAgentVaultActivityChunkResponse struct {
	ChunkID          string `json:"chunkId"`
	UploadURL        string `json:"uploadUrl"`
	ExpiresInSeconds int    `json:"expiresInSeconds"`
}

func CallCreateAgentVaultActivityChunk(httpClient *resty.Client, sessionID string, request CreateAgentVaultActivityChunkRequest) (CreateAgentVaultActivityChunkResponse, error) {
	var res CreateAgentVaultActivityChunkResponse
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/agent-vault/proxy/sessions/%s/activity/chunks", config.INFISICAL_URL, sessionID))

	if err != nil {
		return CreateAgentVaultActivityChunkResponse{}, NewGenericRequestError("CallCreateAgentVaultActivityChunk", err)
	}
	if response.IsError() {
		return CreateAgentVaultActivityChunkResponse{}, NewAPIErrorWithResponse("CallCreateAgentVaultActivityChunk", response, nil)
	}
	return res, nil
}

type CreateAgentVaultSessionRequest struct {
	AccessBundles []string `json:"accessBundles"`
	TTL           string   `json:"ttl"`
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
