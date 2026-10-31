package kmip

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

func LoginKmipServerWithAws(ctx context.Context, httpClient *resty.Client, kmipServerID string) (string, error) {
	if kmipServerID == "" {
		return "", errors.New("--kmip-server-id is required when --enroll-method=aws")
	}

	awsCredentials, awsRegion, err := infisicalSdkUtil.RetrieveAwsCredentials()
	if err != nil {
		return "", fmt.Errorf("unable to retrieve AWS credentials: %w", err)
	}

	iamRequestURL := fmt.Sprintf("https://sts.%s.amazonaws.com/", awsRegion)
	iamRequestBody := "Action=GetCallerIdentity&Version=2011-06-15"

	req, err := http.NewRequest(http.MethodPost, iamRequestURL, strings.NewReader(iamRequestBody))
	if err != nil {
		return "", fmt.Errorf("error building STS request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	hash := sha256.New()
	hash.Write([]byte(iamRequestBody))
	payloadHash := fmt.Sprintf("%x", hash.Sum(nil))

	signer := v4.NewSigner()
	if err := signer.SignHTTP(ctx, awsCredentials, req, payloadHash, "sts", awsRegion, time.Now()); err != nil {
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

	headersJSON, err := json.Marshal(headers)
	if err != nil {
		return "", fmt.Errorf("error marshalling headers: %w", err)
	}

	resp, err := api.CallKmipServerLogin(httpClient, api.KmipServerLoginRequest{
		Method:            EnrollMethodAws,
		KmipServerID:      kmipServerID,
		HTTPRequestMethod: req.Method,
		IamRequestBody:    base64.StdEncoding.EncodeToString([]byte(iamRequestBody)),
		IamRequestHeaders: base64.StdEncoding.EncodeToString(headersJSON),
	})
	if err != nil {
		return "", err
	}

	return resp.AccessToken, nil
}
