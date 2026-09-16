package gatewayv2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	credentials "cloud.google.com/go/iam/credentials/apiv1"
	"cloud.google.com/go/iam/credentials/apiv1/credentialspb"
	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/go-resty/resty/v2"
	"google.golang.org/api/option"
)

const (
	gcpMetadataIdentityURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"
	gcpMetadataEmailURL    = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
	gcpMetadataTimeout     = 10 * time.Second
	gcpIamTokenLifetime    = 5 * time.Minute
)

// LoginGatewayWithGcp exchanges a GCP identity proof for a GATEWAY_ACCESS_TOKEN. Both token types
// carry the gateway ID as their audience.
func LoginGatewayWithGcp(ctx context.Context, httpClient *resty.Client, gatewayID string, authType string, serviceAccountKeyPath string) (string, error) {
	if gatewayID == "" {
		return "", errors.New("--gateway-id is required when --enroll-method=gcp")
	}

	var jwt string
	var err error
	switch authType {
	case GcpAuthTypeGce:
		if serviceAccountKeyPath != "" {
			return "", errors.New("--service-account-key-file-path only applies to --gcp-auth-type=iam. The gce type reads its token from the instance metadata server")
		}
		jwt, err = fetchGcpIdentityToken(ctx, gatewayID)
	case GcpAuthTypeIam:
		jwt, err = signGcpServiceAccountJwt(ctx, gatewayID, serviceAccountKeyPath)
	default:
		return "", fmt.Errorf("invalid --gcp-auth-type: %s. Valid values are '%s' and '%s'", authType, GcpAuthTypeGce, GcpAuthTypeIam)
	}
	if err != nil {
		return "", err
	}

	resp, err := api.CallGcpAuthLoginGateway(httpClient, api.GcpAuthLoginGatewayRequest{
		Method:    EnrollMethodGcp,
		GatewayID: gatewayID,
		JWT:       jwt,
	})
	if err != nil {
		return "", err
	}

	return resp.AccessToken, nil
}

func fetchGcpIdentityToken(ctx context.Context, audience string) (string, error) {
	res, err := resty.New().
		SetTimeout(gcpMetadataTimeout).
		R().
		SetContext(ctx).
		SetHeader("Metadata-Flavor", "Google").
		SetQueryParam("audience", audience).
		SetQueryParam("format", "full").
		Get(gcpMetadataIdentityURL)

	if err != nil {
		return "", fmt.Errorf("unable to reach the GCP metadata server. --gcp-auth-type=gce requires the gateway to run on a Compute Engine instance or a GKE pod with workload identity: %w", err)
	}

	if res.IsError() {
		return "", fmt.Errorf("the GCP metadata server rejected the identity token request [status-code=%d]: %s", res.StatusCode(), res.String())
	}

	token := strings.TrimSpace(res.String())
	if token == "" {
		return "", errors.New("the GCP metadata server returned an empty identity token")
	}

	return token, nil
}

func signGcpServiceAccountJwt(ctx context.Context, audience string, serviceAccountKeyPath string) (string, error) {
	clientEmail, err := resolveGcpServiceAccountEmail(ctx, serviceAccountKeyPath)
	if err != nil {
		return "", err
	}

	// Without an expiry the proof is replayable forever; the backend refuses one.
	now := time.Now()
	payload, err := json.Marshal(map[string]any{
		"sub": clientEmail,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(gcpIamTokenLifetime).Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("unable to build the GCP JWT payload: %w", err)
	}

	var opts []option.ClientOption
	if serviceAccountKeyPath != "" {
		opts = append(opts, option.WithCredentialsFile(serviceAccountKeyPath))
	}

	client, err := credentials.NewIamCredentialsClient(ctx, opts...) //nolint:staticcheck // deprecated but no drop-in replacement available yet
	if err != nil {
		return "", fmt.Errorf("unable to create the GCP IAM credentials client: %w", err)
	}
	defer client.Close() //nolint:errcheck

	resp, err := client.SignJwt(ctx, &credentialspb.SignJwtRequest{
		Name:    fmt.Sprintf("projects/-/serviceAccounts/%s", clientEmail),
		Payload: string(payload),
	})
	if err != nil {
		return "", fmt.Errorf("unable to sign the GCP JWT as %s. Ensure the IAM Service Account Credentials API is enabled and the caller holds roles/iam.serviceAccountTokenCreator on that service account: %w", clientEmail, err)
	}

	if resp.SignedJwt == "" {
		return "", errors.New("GCP returned an empty signed JWT")
	}

	return resp.SignedJwt, nil
}

func resolveGcpServiceAccountEmail(ctx context.Context, serviceAccountKeyPath string) (string, error) {
	if serviceAccountKeyPath != "" {
		keyBytes, err := os.ReadFile(serviceAccountKeyPath)
		if err != nil {
			return "", fmt.Errorf("unable to read the GCP service account key at %s: %w", serviceAccountKeyPath, err)
		}

		var key struct {
			ClientEmail string `json:"client_email"`
		}
		if err := json.Unmarshal(keyBytes, &key); err != nil {
			return "", fmt.Errorf("unable to parse the GCP service account key at %s: %w", serviceAccountKeyPath, err)
		}
		if key.ClientEmail == "" {
			return "", fmt.Errorf("the GCP service account key at %s has no client_email", serviceAccountKeyPath)
		}
		return key.ClientEmail, nil
	}

	res, err := resty.New().
		SetTimeout(gcpMetadataTimeout).
		R().
		SetContext(ctx).
		SetHeader("Metadata-Flavor", "Google").
		Get(gcpMetadataEmailURL)

	if err != nil {
		return "", fmt.Errorf("unable to determine which GCP service account to sign as. Provide --service-account-key-file-path, or run the gateway where the metadata server is reachable: %w", err)
	}

	if res.IsError() {
		return "", fmt.Errorf("the GCP metadata server rejected the service account email request [status-code=%d]: %s", res.StatusCode(), res.String())
	}

	email := strings.TrimSpace(res.String())
	if email == "" {
		return "", errors.New("the GCP metadata server returned an empty service account email")
	}

	return email, nil
}
