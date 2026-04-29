package gatewayv2

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/go-resty/resty/v2"
	infisicalSdkUtil "github.com/infisical/go-sdk/packages/util"
)

const (
	INFISICAL_GATEWAY_ID_KEY = "INFISICAL_GATEWAY_ID"
)

// LoginGatewayWithAws builds a SigV4-signed sts:GetCallerIdentity request using the local AWS
// credentials chain (instance metadata, env vars, profile, etc.) and exchanges it for a
// GATEWAY_ACCESS_TOKEN. The credentials themselves never leave the host — only the signature
// over a single STS API call.
func LoginGatewayWithAws(httpClient *resty.Client, gatewayID string) (string, error) {
	if gatewayID == "" {
		return "", errors.New("--gateway-id is required when --enroll-method=aws")
	}

	awsCredentials, awsRegion, err := infisicalSdkUtil.RetrieveAwsCredentials()
	if err != nil {
		return "", fmt.Errorf("unable to retrieve AWS credentials (no instance role / no AWS env vars / no profile): %w", err)
	}

	iamRequestURL := fmt.Sprintf("https://sts.%s.amazonaws.com/", awsRegion)
	iamRequestBody := "Action=GetCallerIdentity&Version=2011-06-15"

	req, err := http.NewRequest(http.MethodPost, iamRequestURL, strings.NewReader(iamRequestBody))
	if err != nil {
		return "", fmt.Errorf("error building STS request: %w", err)
	}

	req.Header.Add("X-Amz-Date", time.Now().UTC().Format("20060102T150405Z"))

	hash := sha256.New()
	hash.Write([]byte(iamRequestBody))
	payloadHash := fmt.Sprintf("%x", hash.Sum(nil))

	signer := v4.NewSigner()
	if err := signer.SignHTTP(context.TODO(), awsCredentials, req, payloadHash, "sts", awsRegion, time.Now()); err != nil {
		return "", fmt.Errorf("error signing STS request: %w", err)
	}

	headers := make(map[string]string)
	for name, values := range req.Header {
		if strings.ToLower(name) == "content-length" {
			continue
		}
		headers[name] = values[0]
	}
	headers["Host"] = fmt.Sprintf("sts.%s.amazonaws.com", awsRegion)
	headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"
	headers["Content-Length"] = fmt.Sprintf("%d", len(iamRequestBody))

	headersJSON, err := json.Marshal(headers)
	if err != nil {
		return "", fmt.Errorf("error marshalling headers: %w", err)
	}

	resp, err := api.CallAwsAuthLoginGateway(httpClient, api.AwsAuthLoginGatewayRequest{
		Method:            EnrollMethodAws,
		GatewayID:         gatewayID,
		HTTPRequestMethod: req.Method,
		IamRequestBody:    base64.StdEncoding.EncodeToString([]byte(iamRequestBody)),
		IamRequestHeaders: base64.StdEncoding.EncodeToString(headersJSON),
	})
	if err != nil {
		return "", err
	}

	return resp.AccessToken, nil
}

// LoadStoredGatewayID returns the persisted gateway id for a named gateway (set after first
// AWS-auth login so subsequent restarts don't need --gateway-id).
func LoadStoredGatewayID(name string) (string, error) {
	return loadConfKey(name, INFISICAL_GATEWAY_ID_KEY)
}

// SaveGatewayID persists the gateway id used during AWS-auth login.
func SaveGatewayID(name, gatewayID string) error {
	return saveConfKey(name, INFISICAL_GATEWAY_ID_KEY, gatewayID)
}
