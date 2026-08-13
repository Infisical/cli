package api

import (
	"fmt"
	"time"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/go-resty/resty/v2"
)

type AgentGatewaySessionMode string

const (
	AgentGatewaySessionModeRemote AgentGatewaySessionMode = "remote"
	AgentGatewaySessionModeLocal  AgentGatewaySessionMode = "local"
)

// A resolved credential is only ever "unavailable" with a reason, never silently absent, so the broker can
// say which credential it could not apply and why instead of failing a request with no explanation.
type AgentGatewayBundleCredential struct {
	ID                   string   `json:"id"`
	Role                 string   `json:"role"`
	HeaderName           string   `json:"headerName,omitempty"`
	HeaderPrefix         string   `json:"headerPrefix,omitempty"`
	HeaderPurpose        string   `json:"headerPurpose,omitempty"`
	PlaceholderKey       string   `json:"placeholderKey,omitempty"`
	PlaceholderValue     string   `json:"placeholderValue,omitempty"`
	SubstitutionSurfaces []string `json:"substitutionSurfaces,omitempty"`
	Kind                 string   `json:"kind"`
	// Names only, for the activity log. The value is separate and never logged.
	SecretKey          string     `json:"secretKey,omitempty"`
	DynamicSecretName  string     `json:"dynamicSecretName,omitempty"`
	DynamicSecretField string     `json:"dynamicSecretField,omitempty"`
	Value              string     `json:"value,omitempty"`
	LeaseID            string     `json:"leaseId,omitempty"`
	LeaseExpiresAt     *time.Time `json:"leaseExpiresAt,omitempty"`
	Unavailable        bool       `json:"unavailable,omitempty"`
	UnavailableReason  string     `json:"unavailableReason,omitempty"`
}

// Priority is the tie-break the matcher applies when two services match the same host, so the order the
// backend sends is significant and must not be re-sorted.
type AgentGatewayBundleService struct {
	ID          string                         `json:"id"`
	Name        string                         `json:"name"`
	HostPattern string                         `json:"hostPattern"`
	IsEnabled   bool                           `json:"isEnabled"`
	Priority    int                            `json:"priority"`
	Credentials []AgentGatewayBundleCredential `json:"credentials"`
}

type AgentGatewayBrokerBundleResponse struct {
	SessionID           string                      `json:"sessionId"`
	AgentGatewayID      string                      `json:"agentGatewayId"`
	Services            []AgentGatewayBundleService `json:"services"`
	RefreshAfterSeconds int                         `json:"refreshAfterSeconds"`
	ExpiresAt           time.Time                   `json:"expiresAt"`
}

type CreateAgentGatewaySessionRequest struct {
	Mode AgentGatewaySessionMode `json:"mode"`
}

type CreateAgentGatewaySessionResponse struct {
	Session struct {
		ID                  string                  `json:"id"`
		AgentGatewayID      string                  `json:"agentGatewayId"`
		AgentGatewayName    string                  `json:"agentGatewayName"`
		Mode                AgentGatewaySessionMode `json:"mode"`
		ProjectID           string                  `json:"projectId"`
		ProjectSlug         string                  `json:"projectSlug"`
		ExpiresAt           time.Time               `json:"expiresAt"`
		RenewAfterSeconds   int                     `json:"renewAfterSeconds"`
		RefreshAfterSeconds int                     `json:"refreshAfterSeconds"`
		UnmatchedHostPolicy string                  `json:"unmatchedHostPolicy"`
	} `json:"session"`
}

// AgentGatewayPlaceholder is the dummy value an agent receives in place of a real credential.
type AgentGatewayPlaceholder struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type AgentGatewayTransportResponse struct {
	RelayHost string `json:"relayHost"`
	Gateway   struct {
		ClientCertificate      string `json:"clientCertificate"`
		ClientPrivateKey       string `json:"clientPrivateKey"`
		ServerCertificateChain string `json:"serverCertificateChain"`
	} `json:"gateway"`
	Relay struct {
		ClientCertificate      string `json:"clientCertificate"`
		ClientPrivateKey       string `json:"clientPrivateKey"`
		ServerCertificateChain string `json:"serverCertificateChain"`
	} `json:"relay"`
	CaCertificate        string                    `json:"caCertificate"`
	Placeholders         []AgentGatewayPlaceholder `json:"placeholders"`
	HostPatterns         []string                  `json:"hostPatterns"`
	ExpiresAt            time.Time                 `json:"expiresAt"`
	CertificateExpiresAt time.Time                 `json:"certificateExpiresAt"`
}

type AgentGatewaySummary struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	IsLocalModeEnabled bool   `json:"isLocalModeEnabled"`
	Gateway            *struct {
		ID                 string `json:"id"`
		Name               string `json:"name"`
		IsHealthy          bool   `json:"isHealthy"`
		SupportsAgentProxy bool   `json:"supportsAgentProxy"`
	} `json:"gateway"`
	ProxiedServiceCount int `json:"proxiedServiceCount"`
}

type ListAgentGatewaysResponse struct {
	AgentGateways []AgentGatewaySummary `json:"agentGateways"`
	TotalCount    int                   `json:"totalCount"`
}

type GetAgentGatewayByNameResponse struct {
	AgentGateway struct {
		ID                 string `json:"id"`
		Name               string `json:"name"`
		ProjectID          string `json:"projectId"`
		IsLocalModeEnabled bool   `json:"isLocalModeEnabled"`
		Gateway            *struct {
			ID                 string `json:"id"`
			Name               string `json:"name"`
			IsHealthy          bool   `json:"isHealthy"`
			SupportsAgentProxy bool   `json:"supportsAgentProxy"`
		} `json:"gateway"`
		ProxiedServices []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			HostPattern string `json:"hostPattern"`
			IsEnabled   bool   `json:"isEnabled"`
			Priority    int    `json:"priority"`
		} `json:"proxiedServices"`
	} `json:"agentGateway"`
}

func CallListAgentGateways(httpClient *resty.Client, projectId string) (ListAgentGatewaysResponse, error) {
	var res ListAgentGatewaysResponse
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		SetQueryParam("projectId", projectId).
		Get(fmt.Sprintf("%v/v1/agent-gateways", config.INFISICAL_URL))

	if err != nil {
		return ListAgentGatewaysResponse{}, NewGenericRequestError("CallListAgentGateways", err)
	}
	if response.IsError() {
		return ListAgentGatewaysResponse{}, NewAPIErrorWithResponse("CallListAgentGateways", response, nil)
	}
	return res, nil
}

func CallGetAgentGatewayByName(httpClient *resty.Client, projectId string, name string) (GetAgentGatewayByNameResponse, error) {
	var res GetAgentGatewayByNameResponse
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		SetQueryParam("projectId", projectId).
		Get(fmt.Sprintf("%v/v1/agent-gateways/by-name/%s", config.INFISICAL_URL, name))

	if err != nil {
		return GetAgentGatewayByNameResponse{}, NewGenericRequestError("CallGetAgentGatewayByName", err)
	}
	if response.IsError() {
		return GetAgentGatewayByNameResponse{}, NewAPIErrorWithResponse("CallGetAgentGatewayByName", response, nil)
	}
	return res, nil
}

func CallCreateAgentGatewaySession(httpClient *resty.Client, agentGatewayId string, request CreateAgentGatewaySessionRequest) (CreateAgentGatewaySessionResponse, error) {
	var res CreateAgentGatewaySessionResponse
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/agent-gateways/%s/sessions", config.INFISICAL_URL, agentGatewayId))

	if err != nil {
		return CreateAgentGatewaySessionResponse{}, NewGenericRequestError("CallCreateAgentGatewaySession", err)
	}
	if response.IsError() {
		return CreateAgentGatewaySessionResponse{}, NewAPIErrorWithResponse("CallCreateAgentGatewaySession", response, nil)
	}
	return res, nil
}

func CallGetAgentGatewayTransport(httpClient *resty.Client, sessionId string) (AgentGatewayTransportResponse, error) {
	var res AgentGatewayTransportResponse
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		Get(fmt.Sprintf("%v/v1/agent-gateways/sessions/%s/transport", config.INFISICAL_URL, sessionId))

	if err != nil {
		return AgentGatewayTransportResponse{}, NewGenericRequestError("CallGetAgentGatewayTransport", err)
	}
	if response.IsError() {
		return AgentGatewayTransportResponse{}, NewAPIErrorWithResponse("CallGetAgentGatewayTransport", response, nil)
	}
	return res, nil
}

// notModified is true when the caller's ETag still matches, in which case the previous bundle stays valid
// and no plaintext crossed the wire.
func CallGetAgentGatewayBrokerBundle(httpClient *resty.Client, sessionId string, ifNoneMatch string) (bundle AgentGatewayBrokerBundleResponse, etag string, notModified bool, err error) {
	request := httpClient.
		R().
		SetResult(&bundle).
		SetHeader("User-Agent", USER_AGENT)

	if ifNoneMatch != "" {
		request = request.SetHeader("If-None-Match", ifNoneMatch)
	}

	response, err := request.Get(fmt.Sprintf("%v/v1/agent-gateways/sessions/%s/broker-bundle", config.INFISICAL_URL, sessionId))
	if err != nil {
		return AgentGatewayBrokerBundleResponse{}, "", false, NewGenericRequestError("CallGetAgentGatewayBrokerBundle", err)
	}
	if response.StatusCode() == 304 {
		return AgentGatewayBrokerBundleResponse{}, ifNoneMatch, true, nil
	}
	if response.IsError() {
		return AgentGatewayBrokerBundleResponse{}, "", false, NewAPIErrorWithResponse("CallGetAgentGatewayBrokerBundle", response, nil)
	}

	return bundle, response.Header().Get("ETag"), false, nil
}

func CallRenewAgentGatewaySession(httpClient *resty.Client, sessionId string) (expiresAt time.Time, renewAfterSeconds int, err error) {
	var res struct {
		ExpiresAt         time.Time `json:"expiresAt"`
		RenewAfterSeconds int       `json:"renewAfterSeconds"`
	}
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		Post(fmt.Sprintf("%v/v1/agent-gateways/sessions/%s/renew", config.INFISICAL_URL, sessionId))

	if err != nil {
		return time.Time{}, 0, NewGenericRequestError("CallRenewAgentGatewaySession", err)
	}
	if response.IsError() {
		return time.Time{}, 0, NewAPIErrorWithResponse("CallRenewAgentGatewaySession", response, nil)
	}
	return res.ExpiresAt, res.RenewAfterSeconds, nil
}

// Best effort by design: a SIGKILLed CLI or a crashed gateway never gets here, which is why the backend's
// expiry sweep is the authoritative revoker.
func CallEndAgentGatewaySession(httpClient *resty.Client, sessionId string) error {
	response, err := httpClient.
		R().
		SetHeader("User-Agent", USER_AGENT).
		Delete(fmt.Sprintf("%v/v1/agent-gateways/sessions/%s", config.INFISICAL_URL, sessionId))

	if err != nil {
		return NewGenericRequestError("CallEndAgentGatewaySession", err)
	}
	if response.IsError() {
		return NewAPIErrorWithResponse("CallEndAgentGatewaySession", response, nil)
	}
	return nil
}

// Reported by the broker rather than the agent: an agent runs in an untrusted environment, so letting it
// report would let a compromised one forge usage.
func CallReportAgentGatewayUsage(httpClient *resty.Client, sessionId string, serviceIds []string) error {
	if len(serviceIds) == 0 {
		return nil
	}

	response, err := httpClient.
		R().
		SetHeader("User-Agent", USER_AGENT).
		SetBody(map[string]any{"serviceIds": serviceIds}).
		Post(fmt.Sprintf("%v/v1/agent-gateways/sessions/%s/report-usage", config.INFISICAL_URL, sessionId))

	if err != nil {
		return NewGenericRequestError("CallReportAgentGatewayUsage", err)
	}
	if response.IsError() {
		return NewAPIErrorWithResponse("CallReportAgentGatewayUsage", response, nil)
	}
	return nil
}

// CallGetAgentGatewayPlaceholders resolves the bundle once to learn which placeholder variables the agent
// expects. Local mode only: in remote mode the values never reach this host, so the transport call carries
// the placeholders instead.
func CallGetAgentGatewayPlaceholders(httpClient *resty.Client, sessionId string) ([]AgentGatewayPlaceholder, error) {
	bundle, _, _, err := CallGetAgentGatewayBrokerBundle(httpClient, sessionId, "")
	if err != nil {
		return nil, err
	}

	var placeholders []AgentGatewayPlaceholder
	for _, service := range bundle.Services {
		if !service.IsEnabled {
			continue
		}
		for _, credential := range service.Credentials {
			if credential.Unavailable || credential.PlaceholderKey == "" || credential.PlaceholderValue == "" {
				continue
			}
			placeholders = append(placeholders, AgentGatewayPlaceholder{
				Key:   credential.PlaceholderKey,
				Value: credential.PlaceholderValue,
			})
		}
	}
	return placeholders, nil
}

// AgentGatewaySessionRequest is one recorded request. Names only: no header values, no bodies, and a path as
// the agent sent it, so a substituted path carries the placeholder rather than the credential.
type AgentGatewaySessionRequest struct {
	OccurredAt   time.Time                              `json:"occurredAt"`
	Method       string                                 `json:"method"`
	Host         string                                 `json:"host"`
	Port         int                                    `json:"port,omitempty"`
	Path         string                                 `json:"path,omitempty"`
	Decision     string                                 `json:"decision"`
	StatusCode   int                                    `json:"statusCode,omitempty"`
	ServiceID    string                                 `json:"serviceId,omitempty"`
	ServiceName  string                                 `json:"serviceName,omitempty"`
	Credentials  []AgentGatewaySessionRequestCredential `json:"credentials,omitempty"`
	ErrorMessage string                                 `json:"errorMessage,omitempty"`
}

type AgentGatewaySessionRequestCredential struct {
	Key                string   `json:"key,omitempty"`
	DynamicSecretName  string   `json:"dynamicSecretName,omitempty"`
	DynamicSecretField string   `json:"dynamicSecretField,omitempty"`
	Role               string   `json:"role,omitempty"`
	Header             string   `json:"header,omitempty"`
	Surfaces           []string `json:"surfaces,omitempty"`
}

// Best effort by design: a recording is worth having, but never worth failing a brokered request over.
func CallRecordAgentGatewaySessionRequests(httpClient *resty.Client, sessionId string, requests []AgentGatewaySessionRequest) error {
	if len(requests) == 0 {
		return nil
	}

	response, err := httpClient.
		R().
		SetHeader("User-Agent", USER_AGENT).
		SetBody(map[string]any{"requests": requests}).
		Post(fmt.Sprintf("%v/v1/agent-gateways/sessions/%s/requests", config.INFISICAL_URL, sessionId))

	if err != nil {
		return NewGenericRequestError("CallRecordAgentGatewaySessionRequests", err)
	}
	if response.IsError() {
		return NewAPIErrorWithResponse("CallRecordAgentGatewaySessionRequests", response, nil)
	}
	return nil
}
