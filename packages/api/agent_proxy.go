package api

import (
	"fmt"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/go-resty/resty/v2"
)

type GetAgentProxyCaResponse struct {
	Certificate  string `json:"certificate"`
	KeyAlgorithm string `json:"keyAlgorithm"`
	IssuedAt     string `json:"issuedAt"`
	Expiration   string `json:"expiration"`
	SerialNumber string `json:"serialNumber"`
}

func CallGetAgentProxyCa(httpClient *resty.Client) (GetAgentProxyCaResponse, error) {
	var res GetAgentProxyCaResponse
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		Get(fmt.Sprintf("%v/v1/organization/agent-proxy-ca", config.INFISICAL_URL))

	if err != nil {
		return GetAgentProxyCaResponse{}, NewGenericRequestError("CallGetAgentProxyCa", err)
	}
	if response.IsError() {
		return GetAgentProxyCaResponse{}, NewAPIErrorWithResponse("CallGetAgentProxyCa", response, nil)
	}
	return res, nil
}

type SignAgentProxyIntermediateCaRequest struct {
	PublicKey string `json:"publicKey"`
}

type SignAgentProxyIntermediateCaResponse struct {
	Certificate  string `json:"certificate"`
	IssuedAt     string `json:"issuedAt"`
	Expiration   string `json:"expiration"`
	SerialNumber string `json:"serialNumber"`
}

func CallSignAgentProxyIntermediateCa(httpClient *resty.Client, request SignAgentProxyIntermediateCaRequest) (SignAgentProxyIntermediateCaResponse, error) {
	var res SignAgentProxyIntermediateCaResponse
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/organization/agent-proxy-ca/sign", config.INFISICAL_URL))

	if err != nil {
		return SignAgentProxyIntermediateCaResponse{}, NewGenericRequestError("CallSignAgentProxyIntermediateCa", err)
	}
	if response.IsError() {
		return SignAgentProxyIntermediateCaResponse{}, NewAPIErrorWithResponse("CallSignAgentProxyIntermediateCa", response, nil)
	}
	return res, nil
}

type ProxiedServiceCredential struct {
	ID                   string   `json:"id"`
	SecretKey            string   `json:"secretKey,omitempty"`
	Role                 string   `json:"role"`
	HeaderName           string   `json:"headerName,omitempty"`
	HeaderPrefix         string   `json:"headerPrefix,omitempty"`
	HeaderPurpose        string   `json:"headerPurpose,omitempty"`
	PlaceholderKey       string   `json:"placeholderKey,omitempty"`
	PlaceholderValue     string   `json:"placeholderValue,omitempty"`
	SubstitutionSurfaces []string `json:"substitutionSurfaces,omitempty"`
	// dynamic-secret-backed credential: the proxy mints a lease and injects DynamicSecretField from its output
	DynamicSecretName   string                 `json:"dynamicSecretName,omitempty"`
	DynamicSecretField  string                 `json:"dynamicSecretField,omitempty"`
	DynamicSecretConfig map[string]interface{} `json:"dynamicSecretConfig,omitempty"`
	// true when the calling identity could itself mint this dynamic secret's lease (connect-wrapper guardrail)
	CallerCanLease bool `json:"callerCanLease,omitempty"`
}

type ProxiedService struct {
	ID          string                     `json:"id"`
	Name        string                     `json:"name"`
	HostPattern string                     `json:"hostPattern"`
	IsEnabled   bool                       `json:"isEnabled"`
	CanProxy    bool                       `json:"canProxy"`
	Credentials []ProxiedServiceCredential `json:"credentials"`
}

type ListProxiedServicesResponse struct {
	// the project's slug, resolved server-side; the proxy needs it to call the projectSlug-based lease API
	ProjectSlug string           `json:"projectSlug"`
	Services    []ProxiedService `json:"services"`
}

type ListProxiedServicesRequest struct {
	ProjectID   string
	Environment string
	SecretPath  string
}

func CallListProxiedServices(httpClient *resty.Client, request ListProxiedServicesRequest) (ListProxiedServicesResponse, error) {
	var res ListProxiedServicesResponse
	response, err := httpClient.
		R().
		SetResult(&res).
		SetHeader("User-Agent", USER_AGENT).
		SetQueryParam("projectId", request.ProjectID).
		SetQueryParam("environment", request.Environment).
		SetQueryParam("secretPath", request.SecretPath).
		Get(fmt.Sprintf("%v/v1/proxied-services", config.INFISICAL_URL))

	if err != nil {
		return ListProxiedServicesResponse{}, NewGenericRequestError("CallListProxiedServices", err)
	}
	if response.IsError() {
		return ListProxiedServicesResponse{}, NewAPIErrorWithResponse("CallListProxiedServices", response, nil)
	}
	return res, nil
}
