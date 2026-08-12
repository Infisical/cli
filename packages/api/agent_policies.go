package api

import (
	"fmt"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/go-resty/resty/v2"
)

type AgentProxyLoginRequest struct {
	Method string `json:"method"`
	Token  string `json:"token"`
}

type AgentProxyLoginResponse struct {
	AccessToken  string `json:"accessToken"`
	AgentProxyID string `json:"agentProxyId"`
	TokenType    string `json:"tokenType"`
}

// CallAgentProxyLogin trades a one-time enrollment token for the proxy's long-lived access token.
func CallAgentProxyLogin(httpClient *resty.Client, enrollmentToken string) (AgentProxyLoginResponse, error) {
	var res AgentProxyLoginResponse
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(AgentProxyLoginRequest{Method: "token", Token: enrollmentToken}).
		Post(fmt.Sprintf("%v/v1/agent-proxies/login", config.INFISICAL_URL))

	if err != nil {
		return AgentProxyLoginResponse{}, NewGenericRequestError("CallAgentProxyLogin", err)
	}
	if response.IsError() {
		return AgentProxyLoginResponse{}, NewAPIErrorWithResponse("CallAgentProxyLogin", response, nil)
	}
	return res, nil
}

func CallAgentProxyHeartbeat(httpClient *resty.Client) error {
	response, err := httpClient.
		R().
		SetHeader("User-Agent", USER_AGENT).
		Post(fmt.Sprintf("%v/v1/agent-proxies/heartbeat", config.INFISICAL_URL))

	if err != nil {
		return NewGenericRequestError("CallAgentProxyHeartbeat", err)
	}
	if response.IsError() {
		return NewAPIErrorWithResponse("CallAgentProxyHeartbeat", response, nil)
	}
	return nil
}

type AgentPolicyRule struct {
	HostPattern string   `json:"hostPattern"`
	Methods     []string `json:"methods"`
}

type AgentPolicyCredential struct {
	Role                 string   `json:"role"`
	HeaderName           string   `json:"headerName"`
	HeaderPrefix         string   `json:"headerPrefix"`
	HeaderPurpose        string   `json:"headerPurpose"`
	PlaceholderValue     string   `json:"placeholderValue"`
	SubstitutionSurfaces []string `json:"substitutionSurfaces"`
	Value                string   `json:"value"`
}

type ResolvedAgentPolicy struct {
	ID          string                  `json:"id"`
	Name        string                  `json:"name"`
	Target      string                  `json:"target"`
	Rules       []AgentPolicyRule       `json:"rules"`
	Credentials []AgentPolicyCredential `json:"credentials"`
}

type ResolvedUserPolicy struct {
	ID     string            `json:"id"`
	Name   string            `json:"name"`
	Target string            `json:"target"`
	Rules  []AgentPolicyRule `json:"rules"`
}

type ResolvedAgentSessionInfo struct {
	ID         string `json:"id"`
	IdentityID string `json:"identityId"`
	AgentName  string `json:"agentName"`
	UserID     string `json:"userId"`
	ProjectID  string `json:"projectId"`
}

type ResolveAgentSessionResponse struct {
	Session       ResolvedAgentSessionInfo `json:"session"`
	AllowedHosts  []string                 `json:"allowedHosts"`
	AgentPolicies []ResolvedAgentPolicy    `json:"agentPolicies"`
	UserPolicies  []ResolvedUserPolicy     `json:"userPolicies"`
}

type resolveAgentSessionRequest struct {
	Token string `json:"token"`
}

// CallResolveAgentSession exchanges a session token for the policies on both sides of the intersection,
// plus the credential values for the agent's policies. Called by the proxy, never by the agent.
func CallResolveAgentSession(httpClient *resty.Client, sessionToken string) (ResolveAgentSessionResponse, error) {
	var res ResolveAgentSessionResponse
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(resolveAgentSessionRequest{Token: sessionToken}).
		Post(fmt.Sprintf("%v/v1/agent-sessions/resolve", config.INFISICAL_URL))

	if err != nil {
		return ResolveAgentSessionResponse{}, NewGenericRequestError("CallResolveAgentSession", err)
	}
	if response.IsError() {
		return ResolveAgentSessionResponse{}, NewAPIErrorWithResponse("CallResolveAgentSession", response, nil)
	}
	return res, nil
}

type AgentSessionActivityEvent struct {
	Decision   string `json:"decision"`
	Method     string `json:"method"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Path       string `json:"path"`
	StatusCode int    `json:"statusCode,omitempty"`
	PolicyName string `json:"policyName,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type recordAgentSessionActivityRequest struct {
	Token  string                      `json:"token"`
	Events []AgentSessionActivityEvent `json:"events"`
}

func CallRecordAgentSessionActivity(httpClient *resty.Client, sessionToken string, events []AgentSessionActivityEvent) error {
	response, err := httpClient.
		R().
		SetHeader("User-Agent", USER_AGENT).
		SetBody(recordAgentSessionActivityRequest{Token: sessionToken, Events: events}).
		Post(fmt.Sprintf("%v/v1/agent-sessions/activity", config.INFISICAL_URL))

	if err != nil {
		return NewGenericRequestError("CallRecordAgentSessionActivity", err)
	}
	if response.IsError() {
		return NewAPIErrorWithResponse("CallRecordAgentSessionActivity", response, nil)
	}
	return nil
}

type CreateAgentSessionRequest struct {
	ProjectID string `json:"projectId"`
	UserEmail string `json:"userEmail"`
}

type AgentSessionPlaceholder struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type CreateAgentSessionResponse struct {
	Token string `json:"token"`
	User  struct {
		ID       string `json:"id"`
		Email    string `json:"email"`
		Username string `json:"username"`
	} `json:"user"`
	Placeholders       []AgentSessionPlaceholder `json:"placeholders"`
	ProxyCaCertificate string                    `json:"proxyCaCertificate"`
}

// CallCreateAgentSession is the agent's side of the flow: it authenticates as its own machine identity
// and asks for a session on a user's behalf.
func CallCreateAgentSession(httpClient *resty.Client, request CreateAgentSessionRequest) (CreateAgentSessionResponse, error) {
	var res CreateAgentSessionResponse
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/agent-sessions", config.INFISICAL_URL))

	if err != nil {
		return CreateAgentSessionResponse{}, NewGenericRequestError("CallCreateAgentSession", err)
	}
	if response.IsError() {
		return CreateAgentSessionResponse{}, NewAPIErrorWithResponse("CallCreateAgentSession", response, nil)
	}
	return res, nil
}
