package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/broker"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog/log"
)

func buildBrokerFetchFn(token *models.TokenDetails, projectId, environmentName string) broker.FetchFunc {
	return func() ([]broker.SecretWithProxyConfig, error) {
		log.Debug().
			Str("env", environmentName).
			Str("projectId", projectId).
			Msg("Fetching proxy configs from Infisical")

		var accessToken string
		if token != nil && token.Token != "" {
			accessToken = token.Token
		} else {
			loggedInDetails, err := util.GetCurrentLoggedInUserDetails(true)
			if err != nil || !loggedInDetails.IsUserLoggedIn {
				return nil, fmt.Errorf("not authenticated -- use --token or infisical login")
			}
			accessToken = loggedInDetails.UserCredentials.JTWToken
		}

		httpClient, err := util.GetRestyClientWithCustomHeaders()
		if err != nil {
			return nil, fmt.Errorf("creating HTTP client: %w", err)
		}
		httpClient.SetAuthToken(accessToken).SetHeader("Accept", "application/json")

		rawSecrets, err := api.CallGetRawSecretsV3(httpClient, api.GetRawSecretsV3Request{
			WorkspaceId:   projectId,
			Environment:   environmentName,
			SecretPath:    "/",
			IncludeImport: true,
		})
		if err != nil {
			return nil, fmt.Errorf("fetching secrets: %w", err)
		}

		type proxyConfigResp struct {
			ProxyConfigs []struct {
				SecretId    string          `json:"secretId"`
				Placeholder string          `json:"placeholder"`
				Rules       json.RawMessage `json:"rules"`
			} `json:"proxyConfigs"`
		}
		var pcResp proxyConfigResp
		pcResponse, err := httpClient.R().
			SetResult(&pcResp).
			SetQueryParam("environment", environmentName).
			SetQueryParam("secretPath", "/").
			Get(fmt.Sprintf("%v/v1/projects/%v/secrets/http-proxy-configs", config.INFISICAL_URL, projectId))
		if err != nil || pcResponse.IsError() {
			log.Warn().Err(err).Msg("Failed to fetch proxy configs, continuing with empty rules")
			return []broker.SecretWithProxyConfig{}, nil
		}

		type pcEntry struct {
			placeholder string
			rules       json.RawMessage
		}
		pcMap := make(map[string]pcEntry)
		for _, pc := range pcResp.ProxyConfigs {
			pcMap[pc.SecretId] = pcEntry{placeholder: pc.Placeholder, rules: pc.Rules}
		}

		var result []broker.SecretWithProxyConfig
		for _, secret := range rawSecrets.Secrets {
			pc, ok := pcMap[secret.ID]
			if !ok {
				continue
			}
			var rules []broker.ProxyRule
			json.Unmarshal(pc.rules, &rules)
			result = append(result, broker.SecretWithProxyConfig{
				SecretKey:   secret.SecretKey,
				SecretValue: secret.SecretValue,
				ProxyConfig: broker.ProxyConfig{
					Placeholder: pc.placeholder,
					Rules:       rules,
				},
			})
		}

		return result, nil
	}
}

func buildProposalFunc(token *models.TokenDetails, projectId, environmentName string) broker.ProposalFunc {
	return func(proposal broker.ProposalRequest) (*broker.ProposalResponse, error) {
		var accessToken string
		if token != nil && token.Token != "" {
			accessToken = token.Token
		} else {
			loggedInDetails, loginErr := util.GetCurrentLoggedInUserDetails(true)
			if loginErr != nil || !loggedInDetails.IsUserLoggedIn {
				return nil, fmt.Errorf("not authenticated for proposals")
			}
			accessToken = loggedInDetails.UserCredentials.JTWToken
		}

		httpClient, clientErr := util.GetRestyClientWithCustomHeaders()
		if clientErr != nil {
			return nil, fmt.Errorf("creating HTTP client: %w", clientErr)
		}
		httpClient.SetAuthToken(accessToken).SetHeader("Accept", "application/json")

		body := map[string]interface{}{
			"workspaceId":   projectId,
			"environment":   environmentName,
			"secretPath":    "/",
			"secretValue":   "",
			"secretComment": proposal.Comment,
			"type":          "shared",
		}
		resp, apiErr := httpClient.R().
			SetBody(body).
			Post(fmt.Sprintf("%v/v3/secrets/raw/%v", config.INFISICAL_URL, proposal.SecretKey))

		if apiErr != nil {
			return nil, fmt.Errorf("creating secret: %w", apiErr)
		}
		if resp.IsError() {
			return &broker.ProposalResponse{
				Status:  "error",
				Message: fmt.Sprintf("API error: %s", resp.String()),
			}, nil
		}

		return &broker.ProposalResponse{
			Status:  "pending",
			Message: fmt.Sprintf("Secret %s created. Add proxy config in the dashboard.", proposal.SecretKey),
		}, nil
	}
}

func createBrokerRunDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home dir: %w", err)
	}

	infisicalDir := filepath.Join(home, ".infisical")
	os.MkdirAll(infisicalDir, 0700)

	runDir, err := os.MkdirTemp(infisicalDir, "run-")
	if err != nil {
		return "", fmt.Errorf("creating run dir: %w", err)
	}

	certsDir := filepath.Join(runDir, "certs")
	if err := os.MkdirAll(certsDir, 0700); err != nil {
		os.RemoveAll(runDir)
		return "", fmt.Errorf("creating certs dir: %w", err)
	}

	return runDir, nil
}

func writeBrokerCACerts(runDir string, caPEM []byte) (caCertPath, combinedCAPath string) {
	certsDir := filepath.Join(runDir, "certs")
	caCertPath = filepath.Join(certsDir, "mitm-ca.pem")
	combinedCAPath = filepath.Join(certsDir, "combined-ca.pem")

	os.WriteFile(caCertPath, caPEM, 0644)

	systemCAPath := "/etc/ssl/cert.pem"
	if systemCA, err := os.ReadFile(systemCAPath); err == nil {
		combined := append(systemCA, '\n')
		combined = append(combined, caPEM...)
		os.WriteFile(combinedCAPath, combined, 0644)
	} else {
		combinedCAPath = caCertPath
	}

	return caCertPath, combinedCAPath
}

func writeSRTConfig(runDir string, proxyPort int) string {
	certsDir := filepath.Join(runDir, "certs")
	srtConfigPath := filepath.Join(runDir, "srt-config.json")

	srtConfig := map[string]interface{}{
		"network": map[string]interface{}{
			"allowedDomains": []string{},
			"deniedDomains":  []string{},
			"httpProxyPort":  proxyPort,
		},
		"filesystem": map[string]interface{}{
			"denyRead":   []string{"~/.infisical", "~/.ssh", "~/.aws", "~/.config/gcloud"},
			"allowRead":  []string{certsDir},
			"allowWrite": []string{".", "~", "/tmp", "/private/tmp"},
			"denyWrite":  []string{},
		},
		"allowPty": true,
	}

	srtJSON, _ := json.MarshalIndent(srtConfig, "", "  ")
	os.WriteFile(srtConfigPath, srtJSON, 0644)

	return srtConfigPath
}
