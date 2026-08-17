package pam

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// AwsIamAuthMethod is the credential auth method the server sends when the gateway, rather than
// Infisical, produces the login token. Any other value means the credential carries its own secret.
const AwsIamAuthMethod = "aws-iam"

const rdsAuthTokenTimeout = 15 * time.Second

// Reused across connections: resolving it fetches the gateway's own credentials from pod identity or
// instance metadata, which is a network round trip we should not repeat on every dial. Bounded by the
// number of regions an org's accounts live in.
var regionConfigs sync.Map

func loadRegionConfig(ctx context.Context, region string) (aws.Config, error) {
	if cached, ok := regionConfigs.Load(region); ok {
		return cached.(aws.Config), nil
	}

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return aws.Config{}, err
	}

	regionConfigs.Store(region, cfg)
	return cfg, nil
}

type RdsAuthTokenParams struct {
	Host        string
	Port        int
	Region      string
	DBUser      string
	RoleArn     string
	SessionName string
}

// BuildRdsAuthToken mints an RDS/Aurora IAM authentication token for a single connection. The token is
// a SigV4 signature over the exact endpoint being dialled, so it is never reusable elsewhere, and it
// is never cached or written to disk.
//
// The gateway assumes the account's role using credentials from its own environment (pod identity,
// instance role, env vars, profile), which keeps the authority to reach a database inside the
// customer's account and scoped to one PAM account. A missing role is an error rather than a fall back
// to the gateway's own identity, which would quietly widen that scope.
func BuildRdsAuthToken(ctx context.Context, params RdsAuthTokenParams) (string, error) {
	if params.Region == "" {
		return "", fmt.Errorf("no AWS region configured for this account")
	}
	if params.RoleArn == "" {
		return "", fmt.Errorf("no IAM role configured for this account")
	}

	ctx, cancel := context.WithTimeout(ctx, rdsAuthTokenTimeout)
	defer cancel()

	cfg, err := loadRegionConfig(ctx, params.Region)
	if err != nil {
		return "", fmt.Errorf("unable to load AWS credentials on the gateway (no pod identity, instance role, or AWS environment variables): %w", err)
	}

	credentials := aws.NewCredentialsCache(
		stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), params.RoleArn, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = params.SessionName
		}),
	)

	endpoint := fmt.Sprintf("%s:%d", params.Host, params.Port)
	token, err := auth.BuildAuthToken(ctx, endpoint, params.Region, params.DBUser, credentials)
	if err != nil {
		return "", fmt.Errorf("failed to generate an AWS IAM authentication token as %s: %w", params.RoleArn, err)
	}

	return token, nil
}
