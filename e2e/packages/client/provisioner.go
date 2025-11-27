package client

import (
	"context"
	"fmt"
	"github.com/go-faker/faker/v4"
	"github.com/oapi-codegen/oapi-codegen/v2/pkg/securityprovider"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"log/slog"
)

type Provisioner struct {
	Client *ClientWithResponses
}

type ProvisionerOption func(*Provisioner)

func NewProvisioner(opts ...ProvisionerOption) *Provisioner {
	p := &Provisioner{}
	for _, opt := range opts {
		opt(p)
	}
	if p.Client == nil {
		panic("Client is required")
	}
	return p
}

func WithClient(client *ClientWithResponses) ProvisionerOption {
	return func(p *Provisioner) {
		p.Client = client
	}
}

func (p *Provisioner) Bootstrap(ctx context.Context) (*string, error) {
	slog.Info("Signing up Admin account ...")
	res, err := p.Client.PostApiV1AdminSignupWithResponse(ctx, PostApiV1AdminSignupJSONRequestBody{
		Email:     openapi_types.Email(faker.Email()),
		FirstName: faker.FirstName(),
		Password:  faker.Password(),
	})
	if err != nil {
		return nil, err
	}
	if res.StatusCode() != 201 {
		return nil, fmt.Errorf("expected status code 201, got %v", res.StatusCode())
	}
	slog.Info("Signed up Admin account successfully, id=%s", res.JSON200.User.Id)

	slog.Info("Selecting organization with id=%s", res.JSON200.Organization.Id)
	bearerAuth, err := securityprovider.NewSecurityProviderBearerToken(res.JSON200.Token)
	if err != nil {
		return nil, err
	}
	selectOrgRes, err := p.Client.PostApiV3AuthSelectOrganizationWithResponse(
		ctx,
		PostApiV3AuthSelectOrganizationJSONRequestBody{
			OrganizationId: res.JSON200.Organization.Id.String(),
		},
		bearerAuth.Intercept,
	)
	if err != nil {
		return nil, err
	}
	if selectOrgRes.StatusCode() != 200 {
		return nil, fmt.Errorf("expected status code 200, got %v", res.StatusCode())
	}
	slog.Info("Selected organization with id=%s", res.JSON200.Organization.Id)

	slog.Info("Creating Auth token ...")
	authTokenRes, err := p.Client.PostApiV1AuthTokenWithResponse(ctx, bearerAuth.Intercept)
	if err != nil {
		return nil, err
	}
	if authTokenRes.StatusCode() != 200 {
		return nil, fmt.Errorf("expected status code 200, got %v", res.StatusCode())
	}
	return &authTokenRes.JSON200.Token, nil
}
