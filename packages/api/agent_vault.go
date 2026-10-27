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

func CallRevokeAgentVaultSession(ctx context.Context, httpClient *resty.Client, sessionID string) error {
	response, err := httpClient.
		R().
		SetContext(ctx).
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

type AgentVaultSkillFile struct {
	Path          string `json:"path"`
	Mode          string `json:"mode"`
	ContentBase64 string `json:"contentBase64"`
}

type AgentVaultProxySkill struct {
	ID      string                `json:"id"`
	Name    string                `json:"name"`
	Version int                   `json:"version"`
	Sha256  string                `json:"sha256"`
	Files   []AgentVaultSkillFile `json:"files"`
}

type AgentVaultProxySkillsResponse struct {
	Skills []AgentVaultProxySkill `json:"skills"`
}

func CallListAgentVaultProxySkills(httpClient *resty.Client, sessionToken string) (AgentVaultProxySkillsResponse, error) {
	var res AgentVaultProxySkillsResponse
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		SetHeader(AgentVaultSessionHeader, sessionToken).
		Get(fmt.Sprintf("%v/v1/agent-vault/proxy/skills", config.INFISICAL_URL))

	if err != nil {
		return AgentVaultProxySkillsResponse{}, NewGenericRequestError("CallListAgentVaultProxySkills", err)
	}
	if response.IsError() {
		return AgentVaultProxySkillsResponse{}, NewAPIErrorWithResponse("CallListAgentVaultProxySkills", response, nil)
	}
	return res, nil
}

type AgentVaultSkill struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	LatestVersion int    `json:"latestVersion"`
	CreatedAt     string `json:"createdAt"`
	UpdatedAt     string `json:"updatedAt"`
}

type AgentVaultSkillVersion struct {
	ID        string `json:"id"`
	Version   int    `json:"version"`
	Sha256    string `json:"sha256"`
	SizeBytes int    `json:"sizeBytes"`
	FileCount int    `json:"fileCount"`
	CreatedAt string `json:"createdAt"`
}

type ListAgentVaultSkillsResponse struct {
	Skills     []AgentVaultSkill `json:"skills"`
	TotalCount int               `json:"totalCount"`
}

func CallListAgentVaultSkillsByName(httpClient *resty.Client, name string) (ListAgentVaultSkillsResponse, error) {
	var res ListAgentVaultSkillsResponse
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		SetQueryParam("name", name).
		Get(fmt.Sprintf("%v/v1/agent-vault/skills", config.INFISICAL_URL))

	if err != nil {
		return ListAgentVaultSkillsResponse{}, NewGenericRequestError("CallListAgentVaultSkillsByName", err)
	}
	if response.IsError() {
		return ListAgentVaultSkillsResponse{}, NewAPIErrorWithResponse("CallListAgentVaultSkillsByName", response, nil)
	}
	return res, nil
}

type AgentVaultSkillFilesRequest struct {
	Files  []AgentVaultSkillFile `json:"files"`
	Source string                `json:"source,omitempty"`
}

type CreateAgentVaultSkillResponse struct {
	Skill   AgentVaultSkill        `json:"skill"`
	Version AgentVaultSkillVersion `json:"version"`
}

func CallCreateAgentVaultSkill(httpClient *resty.Client, request AgentVaultSkillFilesRequest) (CreateAgentVaultSkillResponse, error) {
	var res CreateAgentVaultSkillResponse
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/agent-vault/skills", config.INFISICAL_URL))

	if err != nil {
		return CreateAgentVaultSkillResponse{}, NewGenericRequestError("CallCreateAgentVaultSkill", err)
	}
	if response.IsError() {
		return CreateAgentVaultSkillResponse{}, NewAPIErrorWithResponse("CallCreateAgentVaultSkill", response, nil)
	}
	return res, nil
}

type PublishAgentVaultSkillVersionResponse struct {
	Version   AgentVaultSkillVersion `json:"version"`
	Unchanged bool                   `json:"unchanged"`
}

func CallPublishAgentVaultSkillVersion(httpClient *resty.Client, skillID string, request AgentVaultSkillFilesRequest) (PublishAgentVaultSkillVersionResponse, error) {
	var res PublishAgentVaultSkillVersionResponse
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/agent-vault/skills/%s/versions", config.INFISICAL_URL, url.PathEscape(skillID)))

	if err != nil {
		return PublishAgentVaultSkillVersionResponse{}, NewGenericRequestError("CallPublishAgentVaultSkillVersion", err)
	}
	if response.IsError() {
		return PublishAgentVaultSkillVersionResponse{}, NewAPIErrorWithResponse("CallPublishAgentVaultSkillVersion", response, nil)
	}
	return res, nil
}
