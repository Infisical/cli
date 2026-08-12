package api

import (
	"fmt"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/go-resty/resty/v2"
)

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
