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

type AgentVaultAccessBundle struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	HostPatterns []string `json:"hostPatterns"`
}

type ListAgentVaultAccessBundlesResponse struct {
	AccessBundles []AgentVaultAccessBundle `json:"accessBundles"`
}

func CallListAgentVaultAccessBundles(httpClient *resty.Client) (ListAgentVaultAccessBundlesResponse, error) {
	var res ListAgentVaultAccessBundlesResponse
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		Get(fmt.Sprintf("%v/v1/agent-vault/access-bundles", config.INFISICAL_URL))

	if err != nil {
		return ListAgentVaultAccessBundlesResponse{}, NewGenericRequestError("CallListAgentVaultAccessBundles", err)
	}
	if response.IsError() {
		return ListAgentVaultAccessBundlesResponse{}, NewAPIErrorWithResponse("CallListAgentVaultAccessBundles", response, nil)
	}
	return res, nil
}

type CreateAgentVaultSessionRequest struct {
	AccessBundleIDs []string `json:"accessBundleIds"`
	TTL             string   `json:"ttl"`
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

// Served by the proxy itself, not by Infisical, over plain HTTP on the proxy's own address. Unauthenticated:
// a public certificate is public, and this is how an agent comes to trust the proxy.
type AgentVaultProxyCaResponse struct {
	ProxyID     string `json:"proxyId"`
	Name        string `json:"name"`
	Certificate string `json:"certificate"`
	Fingerprint string `json:"fingerprint"`
}

func CallGetAgentVaultProxyCa(httpClient *resty.Client, proxyAddr string) (AgentVaultProxyCaResponse, error) {
	var res AgentVaultProxyCaResponse
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		Get(fmt.Sprintf("http://%s/_agent-vault/ca", proxyAddr))

	if err != nil {
		return AgentVaultProxyCaResponse{}, NewGenericRequestError("CallGetAgentVaultProxyCa", err)
	}
	if response.IsError() {
		return AgentVaultProxyCaResponse{}, NewAPIErrorWithResponse("CallGetAgentVaultProxyCa", response, nil)
	}
	return res, nil
}

type AgentVaultReachable struct {
	Connection   string   `json:"connection"`
	AccessBundle string   `json:"accessBundle"`
	Hosts        []string `json:"hosts"`
	Credential   string   `json:"credentialType"`
}

type AgentVaultWhoamiResponse struct {
	ProxyID       string                `json:"proxyId"`
	Name          string                `json:"name"`
	UnmatchedHost string                `json:"unmatchedHost"`
	Reachable     []AgentVaultReachable `json:"reachable"`
}

func CallAgentVaultWhoami(httpClient *resty.Client, proxyAddr, sessionToken string) (AgentVaultWhoamiResponse, error) {
	var res AgentVaultWhoamiResponse
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		SetHeader(AgentVaultSessionHeader, sessionToken).
		Get(fmt.Sprintf("http://%s/_agent-vault/whoami", proxyAddr))

	if err != nil {
		return AgentVaultWhoamiResponse{}, NewGenericRequestError("CallAgentVaultWhoami", err)
	}
	if response.IsError() {
		return AgentVaultWhoamiResponse{}, NewAPIErrorWithResponse("CallAgentVaultWhoami", response, nil)
	}
	return res, nil
}
