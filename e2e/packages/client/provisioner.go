package client

import (
	"context"
	"fmt"
	"github.com/go-faker/faker/v4"
	"github.com/oapi-codegen/oapi-codegen/v2/pkg/securityprovider"
	"github.com/oapi-codegen/runtime/types"
	"log/slog"
	"net/http"
)

type Provisioner struct {
	Client *ClientWithResponses
}

type ProvisionResult struct {
	UserId string
	OrgId  string
	Token  string
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

func WithCookies(cookies ...*http.Cookie) RequestEditorFn {
	return func(ctx context.Context, req *http.Request) error {
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		return nil
	}
}

func (p *Provisioner) Bootstrap(ctx context.Context) (*ProvisionResult, error) {
	slog.Info("Signing up Admin account ...")
	signUpResp, err := p.Client.PostApiV1AdminSignupWithResponse(ctx, PostApiV1AdminSignupJSONRequestBody{
		Email:     types.Email(faker.Email()),
		FirstName: faker.FirstName(),
		Password:  faker.Password(),
	})
	if err != nil {
		return nil, err
	}
	if signUpResp.StatusCode() != 200 {
		return nil, fmt.Errorf("expected status code 200, got %v", signUpResp.StatusCode())
	}
	slog.Info("Signed up Admin account successfully", "userId", signUpResp.JSON200.User.Id)

	slog.Info("Selecting organization with", "id", signUpResp.JSON200.Organization.Id)
	bearerAuth, err := securityprovider.NewSecurityProviderBearerToken(signUpResp.JSON200.Token)
	if err != nil {
		return nil, err
	}
	selectOrgResp, err := p.Client.PostApiV3AuthSelectOrganizationWithResponse(
		ctx,
		PostApiV3AuthSelectOrganizationJSONRequestBody{
			OrganizationId: signUpResp.JSON200.Organization.Id.String(),
		},
		bearerAuth.Intercept,
		WithCookies(signUpResp.HTTPResponse.Cookies()...),
	)
	if err != nil {
		return nil, err
	}
	if selectOrgResp.StatusCode() != 200 {
		return nil, fmt.Errorf("expected status code 200, got %v", signUpResp.StatusCode())
	}
	slog.Info("Selected organization", "orgId", signUpResp.JSON200.Organization.Id)

	slog.Info("Creating Auth token ...")
	orgBearerAuth, err := securityprovider.NewSecurityProviderBearerToken(selectOrgResp.JSON200.Token)
	if err != nil {
		return nil, err
	}
	authTokenResp, err := p.Client.PostApiV1AuthTokenWithResponse(
		ctx,
		orgBearerAuth.Intercept,
		// Notice: we need to pass in cookies from sign-up for the token creation to work
		// ref: https://github.com/Infisical/infisical/blob/c39673e25a5914ad914b08da68ac621fb7c1a0f8/backend/src/server/routes/v1/auth-router.ts#L89
		WithCookies(selectOrgResp.HTTPResponse.Cookies()...),
	)
	if err != nil {
		return nil, err
	}
	if authTokenResp.StatusCode() != 200 {
		return nil, fmt.Errorf("expected status code 200, got %v", authTokenResp.StatusCode())
	}
	slog.Info("Token successfully created")
	return &ProvisionResult{
		UserId: signUpResp.JSON200.User.Id.String(),
		OrgId:  signUpResp.JSON200.Organization.Id.String(),
		Token:  authTokenResp.JSON200.Token,
	}, nil
}
