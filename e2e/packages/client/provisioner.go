package client

import (
	"context"
	"fmt"
	"github.com/go-faker/faker/v4"
	"github.com/oapi-codegen/oapi-codegen/v2/pkg/securityprovider"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"log/slog"
	"net/http"
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
	if res.StatusCode() != 200 {
		return nil, fmt.Errorf("expected status code 200, got %v", res.StatusCode())
	}
	slog.Info("Signed up Admin account successfully, id=%s", res.JSON200.User.Id)
	cookies := res.HTTPResponse.Cookies()

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
	orgBearerAuth, err := securityprovider.NewSecurityProviderBearerToken(selectOrgRes.JSON200.Token)
	if err != nil {
		return nil, err
	}
	authTokenRes, err := p.Client.PostApiV1AuthTokenWithResponse(
		ctx,
		orgBearerAuth.Intercept,
		// Notice: we need to pass in cookies from sign-up for the token creation to work
		// ref: https://github.com/Infisical/infisical/blob/c39673e25a5914ad914b08da68ac621fb7c1a0f8/backend/src/server/routes/v1/auth-router.ts#L89
		func(ctx context.Context, req *http.Request) error {
			for _, cookie := range cookies {
				req.AddCookie(cookie)
			}
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	if authTokenRes.StatusCode() != 200 {
		return nil, fmt.Errorf("expected status code 200, got %v", authTokenRes.StatusCode())
	}
	slog.Info("Token successfully created")
	return &authTokenRes.JSON200.Token, nil
}
