package api

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/go-resty/resty/v2"
)

type AgentSecretMetadata struct {
	ID   string `json:"id"`
	Key  string `json:"secretKey"`
	Type string `json:"type"`
}

type AgentSecret struct {
	AgentSecretMetadata
	Value  *string `json:"secretValue"`
	Hidden bool    `json:"secretValueHidden"`
}

type AgentSecretScope struct {
	ProjectID   string `json:"projectId"`
	Environment string `json:"environment"`
	Path        string `json:"secretPath"`
}

func agentSecretRequest(client *resty.Client, scope AgentSecretScope) *resty.Request {
	return client.R().SetHeader("User-Agent", USER_AGENT).SetQueryParams(map[string]string{
		"projectId": scope.ProjectID, "environment": scope.Environment, "secretPath": scope.Path,
		"includeImports": "false", "expandSecretReferences": "false", "includePersonalOverrides": "false",
		"type": "shared",
	})
}

func agentSecretRequestError(response *resty.Response, err error) error {
	if err != nil {
		return errors.New("could not complete the secret request; check your connection and Infisical domain")
	}
	if response.IsSuccess() {
		return nil
	}
	switch response.StatusCode() {
	case 401:
		return errors.New("authentication failed; run infisical login or provide a valid machine identity access token")
	case 403:
		return errors.New("your identity does not have permission for this secret operation")
	case 404:
		return errors.New("the secret or its location was not found")
	case 409:
		return errors.New("a secret already exists at this location; it was not overwritten")
	default:
		return fmt.Errorf("Infisical rejected the secret request (HTTP %d); response content withheld", response.StatusCode())
	}
}

func FindAgentSecrets(client *resty.Client, scope AgentSecretScope) ([]AgentSecretMetadata, error) {
	var result struct {
		Secrets []AgentSecretMetadata `json:"secrets"`
	}
	response, err := agentSecretRequest(client, scope).
		SetQueryParam("viewSecretValue", "false").SetResult(&result).
		Get(config.INFISICAL_URL + "/v4/secrets")
	if err := agentSecretRequestError(response, err); err != nil {
		return nil, err
	}
	return result.Secrets, nil
}

func ReadAgentSecret(client *resty.Client, scope AgentSecretScope, key string, expand bool) (AgentSecret, error) {
	var result struct {
		Secret AgentSecret `json:"secret"`
	}
	response, err := agentSecretRequest(client, scope).
		SetQueryParam("viewSecretValue", "true").
		SetQueryParam("expandSecretReferences", fmt.Sprint(expand)).SetResult(&result).
		Get(config.INFISICAL_URL + "/v4/secrets/" + url.PathEscape(key))
	if err := agentSecretRequestError(response, err); err != nil {
		return AgentSecret{}, err
	}
	if result.Secret.Hidden || result.Secret.Value == nil || result.Secret.ID == "" || result.Secret.Type != "shared" {
		return AgentSecret{}, errors.New("the shared secret value is not available to this identity")
	}
	return result.Secret, nil
}

func CreateAgentSecret(client *resty.Client, scope AgentSecretScope, key, value string) (AgentSecretMetadata, error) {
	var result struct {
		Secret   AgentSecretMetadata `json:"secret"`
		Approval *struct{}           `json:"approval"`
	}
	response, err := client.R().SetHeader("User-Agent", USER_AGENT).
		SetBody(struct {
			AgentSecretScope
			Value                 string `json:"secretValue"`
			Type                  string `json:"type"`
			SkipMultilineEncoding bool   `json:"skipMultilineEncoding"`
		}{scope, value, "shared", true}).SetResult(&result).
		Post(config.INFISICAL_URL + "/v4/secrets/" + url.PathEscape(key))
	if err := agentSecretRequestError(response, err); err != nil {
		return AgentSecretMetadata{}, fmt.Errorf("%w; do not retry automatically, use find to check whether the write occurred", err)
	}
	if result.Approval != nil {
		return AgentSecretMetadata{}, errors.New("the write requires approval and is not verified; approve it in Infisical, then use find; do not retry the write")
	}
	if result.Secret.ID == "" {
		return AgentSecretMetadata{}, errors.New("the write returned no secret identifier and is not verified; use find before attempting another write")
	}
	return result.Secret, nil
}
