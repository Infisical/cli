package gatewayv2

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/go-resty/resty/v2"
)

// LoginGatewayWithKubernetes exchanges the pod's projected service account token for a
// GATEWAY_ACCESS_TOKEN. tokenPath defaults to the standard projected-token mount when empty.
func LoginGatewayWithKubernetes(httpClient *resty.Client, gatewayID string, tokenPath string) (string, error) {
	if gatewayID == "" {
		return "", errors.New("--gateway-id is required when --enroll-method=kubernetes")
	}

	if tokenPath == "" {
		tokenPath = KUBERNETES_SERVICE_ACCOUNT_TOKEN_PATH
	}

	tokenBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("no Kubernetes service account token found at %s. --enroll-method=kubernetes requires the gateway to run inside a Kubernetes pod, or --service-account-token-path pointing at a projected token", tokenPath)
		}
		return "", fmt.Errorf("unable to read Kubernetes service account token at %s: %w", tokenPath, err)
	}

	jwt := strings.TrimSpace(string(tokenBytes))
	if jwt == "" {
		return "", fmt.Errorf("the Kubernetes service account token at %s is empty", tokenPath)
	}

	resp, err := api.CallKubernetesAuthLoginGateway(httpClient, api.KubernetesAuthLoginGatewayRequest{
		Method:    EnrollMethodKubernetes,
		GatewayID: gatewayID,
		JWT:       jwt,
	})
	if err != nil {
		return "", err
	}

	return resp.AccessToken, nil
}
