package api

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

const USER_AGENT = "cli"

const (
	operationCallGetRawSecretsV3                   = "CallGetRawSecretsV3"
	operationCallGetEncryptedWorkspaceKey          = "CallGetEncryptedWorkspaceKey"
	operationCallGetServiceTokenDetails            = "CallGetServiceTokenDetails"
	operationCallLogin1V3                          = "CallLogin1V3"
	operationCallVerifyMfaToken                    = "CallVerifyMfaToken"
	operationCallLogin2V3                          = "CallLogin2V3"
	operationCallLoginV3                           = "CallLoginV3"
	operationCallGetAllOrganizations               = "CallGetAllOrganizations"
	operationCallSelectOrganization                = "CallSelectOrganization"
	operationCallGetAllWorkSpacesUserBelongsTo     = "CallGetAllWorkSpacesUserBelongsTo"
	operationCallGetProjectById                    = "CallGetProjectById"
	operationCallIsAuthenticated                   = "CallIsAuthenticated"
	operationCallGetNewAccessTokenWithRefreshToken = "CallGetNewAccessTokenWithRefreshToken"
	operationCallGetFoldersV1                      = "CallGetFoldersV1"
	operationCallCreateFolderV1                    = "CallCreateFolderV1"
	operationCallDeleteFolderV1                    = "CallDeleteFolderV1"
	operationCallDeleteSecretsV3                   = "CallDeleteSecretsV3"
	operationCallCreateServiceToken                = "CallCreateServiceToken"
	operationCallUniversalAuthLogin                = "CallUniversalAuthLogin"
	operationCallMachineIdentityRefreshAccessToken = "CallMachineIdentityRefreshAccessToken"
	operationCallFetchSingleSecretByName           = "CallFetchSingleSecretByName"
	operationCallCreateRawSecretsV3                = "CallCreateRawSecretsV3"
	operationCallUpdateRawSecretsV3                = "CallUpdateRawSecretsV3"
	operationCallRegisterGatewayIdentityV1         = "CallRegisterGatewayIdentityV1"
	operationCallExchangeRelayCertV1               = "CallExchangeRelayCertV1"
	operationCallGatewayHeartBeatV1                = "CallGatewayHeartBeatV1"
	operationCallGatewayHeartBeatV2                = "CallGatewayHeartBeatV2"
	operationCallBootstrapInstance                 = "CallBootstrapInstance"
	operationCallRegisterInstanceRelay             = "CallRegisterInstanceRelay"
	operationCallRegisterOrgRelay                  = "CallRegisterOrgRelay"
	operationCallGetOrgRelays                      = "CallGetOrgRelays"
	operationCallRegisterGateway                   = "CallRegisterGateway"
	operationCallPAMAccess                         = "CallPAMAccess"
	operationCallPAMSessionCredentials             = "CallPAMSessionCredentials"
	operationCallGetPamSessionKey                  = "CallGetPamSessionKey"
	operationCallUploadPamSessionLog               = "CallUploadPamSessionLog"
	operationCallPAMSessionTermination             = "CallPAMSessionTermination"
	operationCallOrgRelayHeartBeat                 = "CallOrgRelayHeartBeat"
	operationCallInstanceRelayHeartBeat            = "CallInstanceRelayHeartBeat"
	operationCallIssueCertificate                  = "CallIssueCertificate"
	operationCallRetrieveCertificate               = "CallRetrieveCertificate"
	operationCallRenewCertificate                  = "CallRenewCertificate"
	operationCallGetCertificateRequest             = "CallGetCertificateRequest"
)

var ErrNotFound = errors.New("resource not found")

func CallGetEncryptedWorkspaceKey(httpClient *resty.Client, request GetEncryptedWorkspaceKeyRequest) (GetEncryptedWorkspaceKeyResponse, error) {
	endpoint := fmt.Sprintf("%v/v2/workspace/%v/encrypted-key", config.INFISICAL_URL, request.WorkspaceId)
	var result GetEncryptedWorkspaceKeyResponse
	response, err := httpClient.
		R().
		SetResult(&result).
		SetHeader("User-Agent", USER_AGENT).
		Get(endpoint)

	if err != nil {
		return GetEncryptedWorkspaceKeyResponse{}, NewGenericRequestError(operationCallGetEncryptedWorkspaceKey, err)
	}

	if response.IsError() {
		return GetEncryptedWorkspaceKeyResponse{}, NewAPIErrorWithResponse(operationCallGetEncryptedWorkspaceKey, response, nil)
	}

	return result, nil
}

func CallGetServiceTokenDetailsV2(httpClient *resty.Client) (GetServiceTokenDetailsResponse, error) {
	var tokenDetailsResponse GetServiceTokenDetailsResponse
	response, err := httpClient.
		R().
		SetResult(&tokenDetailsResponse).
		SetHeader("User-Agent", USER_AGENT).
		Get(fmt.Sprintf("%v/v2/service-token", config.INFISICAL_URL))

	if err != nil {
		return GetServiceTokenDetailsResponse{}, NewGenericRequestError(operationCallGetServiceTokenDetails, err)
	}

	if response.IsError() {
		return GetServiceTokenDetailsResponse{}, NewAPIErrorWithResponse(operationCallGetServiceTokenDetails, response, nil)
	}

	return tokenDetailsResponse, nil
}

func CallLogin1V2(httpClient *resty.Client, request GetLoginOneV2Request) (GetLoginOneV2Response, error) {
	var loginOneV2Response GetLoginOneV2Response
	response, err := httpClient.
		R().
		SetResult(&loginOneV2Response).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v3/auth/login1", config.INFISICAL_URL))

	if err != nil {
		return GetLoginOneV2Response{}, NewGenericRequestError(operationCallLogin1V3, err)
	}

	if response.IsError() {
		return GetLoginOneV2Response{}, NewAPIErrorWithResponse(operationCallLogin1V3, response, nil)
	}

	return loginOneV2Response, nil
}

func CallLoginV3(httpClient *resty.Client, request GetLoginV3Request) (GetLoginV3Response, error) {
	var loginV3Response GetLoginV3Response
	response, err := httpClient.
		R().
		SetResult(&loginV3Response).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v3/auth/login", config.INFISICAL_URL))

	if err != nil {
		return GetLoginV3Response{}, NewGenericRequestError(operationCallLoginV3, err)
	}

	if response.IsError() {
		return GetLoginV3Response{}, NewAPIErrorWithResponse(operationCallLoginV3, response, nil)
	}

	return loginV3Response, nil
}

func CallVerifyMfaToken(httpClient *resty.Client, request VerifyMfaTokenRequest) (*VerifyMfaTokenResponse, *VerifyMfaTokenErrorResponse, error) {
	var verifyMfaTokenResponse VerifyMfaTokenResponse
	var responseError VerifyMfaTokenErrorResponse
	response, err := httpClient.
		R().
		SetResult(&verifyMfaTokenResponse).
		SetHeader("User-Agent", USER_AGENT).
		SetError(&responseError).
		SetBody(request).
		Post(fmt.Sprintf("%v/v2/auth/mfa/verify", config.INFISICAL_URL))

	cookies := response.Cookies()
	// Find a cookie by name
	cookieName := "jid"
	var refreshToken *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == cookieName {
			refreshToken = cookie
			break
		}
	}

	// When MFA is enabled
	if refreshToken != nil {
		verifyMfaTokenResponse.RefreshToken = refreshToken.Value
	}

	if err != nil {
		return nil, nil, NewGenericRequestError(operationCallVerifyMfaToken, err)
	}

	if response.IsError() {
		return nil, &responseError, nil
	}

	return &verifyMfaTokenResponse, nil, nil
}

func CallLogin2V2(httpClient *resty.Client, request GetLoginTwoV2Request) (GetLoginTwoV2Response, error) {
	var loginTwoV2Response GetLoginTwoV2Response
	response, err := httpClient.
		R().
		SetResult(&loginTwoV2Response).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v3/auth/login2", config.INFISICAL_URL))

	cookies := response.Cookies()
	// Find a cookie by name
	cookieName := "jid"
	var refreshToken *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == cookieName {
			refreshToken = cookie
			break
		}
	}

	// When MFA is enabled
	if refreshToken != nil {
		loginTwoV2Response.RefreshToken = refreshToken.Value
	}

	if err != nil {
		return GetLoginTwoV2Response{}, NewGenericRequestError(operationCallLogin2V3, err)
	}

	if response.IsError() {
		return GetLoginTwoV2Response{}, NewAPIErrorWithResponse(operationCallLogin2V3, response, nil)
	}

	return loginTwoV2Response, nil
}

func CallGetAllOrganizations(httpClient *resty.Client) (GetOrganizationsResponse, error) {
	var orgResponse GetOrganizationsResponse
	response, err := httpClient.
		R().
		SetResult(&orgResponse).
		SetHeader("User-Agent", USER_AGENT).
		Get(fmt.Sprintf("%v/v1/organization", config.INFISICAL_URL))

	if err != nil {
		return GetOrganizationsResponse{}, NewGenericRequestError(operationCallGetAllOrganizations, err)
	}

	if response.IsError() {
		return GetOrganizationsResponse{}, NewAPIErrorWithResponse(operationCallGetAllOrganizations, response, nil)
	}

	return orgResponse, nil
}

func CallSelectOrganization(httpClient *resty.Client, request SelectOrganizationRequest) (SelectOrganizationResponse, error) {
	var selectOrgResponse SelectOrganizationResponse

	response, err := httpClient.
		R().
		SetBody(request).
		SetResult(&selectOrgResponse).
		SetHeader("User-Agent", USER_AGENT).
		Post(fmt.Sprintf("%v/v3/auth/select-organization", config.INFISICAL_URL))

	if err != nil {
		return SelectOrganizationResponse{}, NewGenericRequestError(operationCallSelectOrganization, err)
	}

	if response.IsError() {
		return SelectOrganizationResponse{}, NewAPIErrorWithResponse(operationCallSelectOrganization, response, nil)
	}

	return selectOrgResponse, nil

}

func CallGetAllWorkSpacesUserBelongsTo(httpClient *resty.Client) (GetWorkSpacesResponse, error) {
	var workSpacesResponse GetWorkSpacesResponse
	response, err := httpClient.
		R().
		SetResult(&workSpacesResponse).
		SetHeader("User-Agent", USER_AGENT).
		Get(fmt.Sprintf("%v/v1/workspace", config.INFISICAL_URL))

	if err != nil {
		return GetWorkSpacesResponse{}, err
	}

	if response.IsError() {
		return GetWorkSpacesResponse{}, fmt.Errorf("CallGetAllWorkSpacesUserBelongsTo: Unsuccessful response:  [response=%v]", response)
	}

	return workSpacesResponse, nil
}

func CallGetProjectById(httpClient *resty.Client, id string) (Project, error) {
	var projectResponse GetProjectByIdResponse
	response, err := httpClient.
		R().
		SetResult(&projectResponse).
		SetHeader("User-Agent", USER_AGENT).
		Get(fmt.Sprintf("%v/v1/workspace/%s", config.INFISICAL_URL, id))

	if err != nil {
		return Project{}, NewGenericRequestError(operationCallGetProjectById, err)
	}

	if response.IsError() {
		return Project{}, NewAPIErrorWithResponse(operationCallGetProjectById, response, nil)
	}

	return projectResponse.Project, nil
}

func CallIsAuthenticated(httpClient *resty.Client) bool {
	var workSpacesResponse GetWorkSpacesResponse
	response, err := httpClient.
		R().
		SetResult(&workSpacesResponse).
		SetHeader("User-Agent", USER_AGENT).
		Post(fmt.Sprintf("%v/v1/auth/checkAuth", config.INFISICAL_URL))

	if err != nil {
		return false
	}

	if response.IsError() {
		log.Debug().Msgf("%s: Unsuccessful response: [response=%v]", operationCallIsAuthenticated, response)
		return false
	}

	return true
}

func CallGetNewAccessTokenWithRefreshToken(httpClient *resty.Client, refreshToken string) (GetNewAccessTokenWithRefreshTokenResponse, error) {
	var newAccessToken GetNewAccessTokenWithRefreshTokenResponse
	response, err := httpClient.
		R().
		SetResult(&newAccessToken).
		SetHeader("User-Agent", USER_AGENT).
		SetCookie(&http.Cookie{
			Name:  "jid",
			Value: refreshToken,
		}).
		Post(fmt.Sprintf("%v/v1/auth/token", config.INFISICAL_URL))

	if err != nil {
		return GetNewAccessTokenWithRefreshTokenResponse{}, NewGenericRequestError(operationCallGetNewAccessTokenWithRefreshToken, err)
	}

	if response.IsError() {
		return GetNewAccessTokenWithRefreshTokenResponse{}, NewAPIErrorWithResponse(operationCallGetNewAccessTokenWithRefreshToken, response, nil)
	}

	return newAccessToken, nil
}

func CallGetFoldersV1(httpClient *resty.Client, request GetFoldersV1Request) (GetFoldersV1Response, error) {
	var foldersResponse GetFoldersV1Response
	httpRequest := httpClient.
		R().
		SetResult(&foldersResponse).
		SetHeader("User-Agent", USER_AGENT).
		SetQueryParam("environment", request.Environment).
		SetQueryParam("workspaceId", request.WorkspaceId).
		SetQueryParam("directory", request.FoldersPath)

	response, err := httpRequest.Get(fmt.Sprintf("%v/v1/folders", config.INFISICAL_URL))

	if err != nil {
		return GetFoldersV1Response{}, NewGenericRequestError(operationCallGetFoldersV1, err)
	}

	if response.IsError() {
		return GetFoldersV1Response{}, NewAPIErrorWithResponse(operationCallGetFoldersV1, response, nil)
	}

	return foldersResponse, nil
}

func CallCreateFolderV1(httpClient *resty.Client, request CreateFolderV1Request) (CreateFolderV1Response, error) {
	var folderResponse CreateFolderV1Response
	httpRequest := httpClient.
		R().
		SetResult(&folderResponse).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request)

	response, err := httpRequest.Post(fmt.Sprintf("%v/v1/folders", config.INFISICAL_URL))
	if err != nil {
		return CreateFolderV1Response{}, NewGenericRequestError(operationCallCreateFolderV1, err)
	}

	if response.IsError() {
		return CreateFolderV1Response{}, NewAPIErrorWithResponse(operationCallCreateFolderV1, response, nil)
	}

	return folderResponse, nil
}

func CallDeleteFolderV1(httpClient *resty.Client, request DeleteFolderV1Request) (DeleteFolderV1Response, error) {
	var folderResponse DeleteFolderV1Response

	httpRequest := httpClient.
		R().
		SetResult(&folderResponse).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request)

	response, err := httpRequest.Delete(fmt.Sprintf("%v/v1/folders/%v", config.INFISICAL_URL, request.FolderName))
	if err != nil {
		return DeleteFolderV1Response{}, NewGenericRequestError(operationCallDeleteFolderV1, err)
	}

	if response.IsError() {
		return DeleteFolderV1Response{}, NewAPIErrorWithResponse(operationCallDeleteFolderV1, response, nil)
	}

	return folderResponse, nil
}

func CallDeleteSecretsRawV3(httpClient *resty.Client, request DeleteSecretV3Request) error {

	var secretsResponse GetEncryptedSecretsV3Response
	response, err := httpClient.
		R().
		SetResult(&secretsResponse).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Delete(fmt.Sprintf("%v/v3/secrets/raw/%s", config.INFISICAL_URL, request.SecretName))

	if err != nil {
		return NewGenericRequestError(operationCallDeleteSecretsV3, err)
	}

	if response.IsError() {
		additionalContext := "Please make sure your secret path, workspace and environment name are all correct."
		return NewAPIErrorWithResponse(operationCallDeleteSecretsV3, response, &additionalContext)
	}

	return nil
}

func CallCreateServiceToken(httpClient *resty.Client, request CreateServiceTokenRequest) (CreateServiceTokenResponse, error) {
	var createServiceTokenResponse CreateServiceTokenResponse
	response, err := httpClient.
		R().
		SetResult(&createServiceTokenResponse).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v2/service-token/", config.INFISICAL_URL))

	if err != nil {
		return CreateServiceTokenResponse{}, NewGenericRequestError(operationCallCreateServiceToken, err)
	}

	if response.IsError() {
		return CreateServiceTokenResponse{}, NewAPIErrorWithResponse(operationCallCreateServiceToken, response, nil)
	}

	return createServiceTokenResponse, nil
}

func CallUniversalAuthLogin(httpClient *resty.Client, request UniversalAuthLoginRequest) (UniversalAuthLoginResponse, error) {
	var universalAuthLoginResponse UniversalAuthLoginResponse
	response, err := httpClient.
		R().
		SetResult(&universalAuthLoginResponse).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/auth/universal-auth/login/", config.INFISICAL_URL))

	if err != nil {
		return UniversalAuthLoginResponse{}, NewGenericRequestError(operationCallUniversalAuthLogin, err)
	}

	if response.IsError() {
		return UniversalAuthLoginResponse{}, NewAPIErrorWithResponse(operationCallUniversalAuthLogin, response, nil)
	}

	return universalAuthLoginResponse, nil
}

func CallMachineIdentityRefreshAccessToken(httpClient *resty.Client, request UniversalAuthRefreshRequest) (UniversalAuthRefreshResponse, error) {
	var universalAuthRefreshResponse UniversalAuthRefreshResponse
	response, err := httpClient.
		R().
		SetResult(&universalAuthRefreshResponse).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/auth/token/renew", config.INFISICAL_URL))

	if err != nil {
		return UniversalAuthRefreshResponse{}, NewGenericRequestError(operationCallMachineIdentityRefreshAccessToken, err)
	}

	if response.IsError() {
		return UniversalAuthRefreshResponse{}, NewAPIErrorWithResponse(operationCallMachineIdentityRefreshAccessToken, response, nil)
	}

	return universalAuthRefreshResponse, nil
}

func CallGetRawSecretsV3(httpClient *resty.Client, request GetRawSecretsV3Request) (GetRawSecretsV3Response, error) {
	var getRawSecretsV3Response GetRawSecretsV3Response
	req := httpClient.
		R().
		SetResult(&getRawSecretsV3Response).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		SetQueryParam("workspaceId", request.WorkspaceId).
		SetQueryParam("environment", request.Environment).
		SetQueryParam("secretPath", request.SecretPath)

	if request.TagSlugs != "" {
		req.SetQueryParam("tagSlugs", request.TagSlugs)
	}

	if request.IncludeImport {
		req.SetQueryParam("include_imports", "true")
	}
	if request.Recursive {
		req.SetQueryParam("recursive", "true")
	}

	if request.ExpandSecretReferences {
		req.SetQueryParam("expandSecretReferences", "true")
	}

	response, err := req.Get(fmt.Sprintf("%v/v3/secrets/raw", config.INFISICAL_URL))

	if err != nil {
		return GetRawSecretsV3Response{}, NewGenericRequestError(operationCallGetRawSecretsV3, err)
	}

	if response.IsError() &&
		(strings.Contains(response.String(), "bot_not_found_error") ||
			strings.Contains(strings.ToLower(response.String()), "failed to find bot key") ||
			strings.Contains(strings.ToLower(response.String()), "bot is not active")) {
		additionalContext := fmt.Sprintf(`Project with id %s is incompatible with your current CLI version. Upgrade your project by visiting the project settings page. If you're self-hosting and project upgrade option isn't yet available, contact your administrator to upgrade your Infisical instance to the latest release.`, request.WorkspaceId)
		return GetRawSecretsV3Response{}, NewAPIErrorWithResponse(operationCallGetRawSecretsV3, response, &additionalContext)
	}

	if response.IsError() {
		return GetRawSecretsV3Response{}, NewAPIErrorWithResponse(operationCallGetRawSecretsV3, response, nil)
	}

	getRawSecretsV3Response.ETag = response.Header().Get(("etag"))

	return getRawSecretsV3Response, nil
}

func CallFetchSingleSecretByName(httpClient *resty.Client, request GetRawSecretV3ByNameRequest) (GetRawSecretV3ByNameResponse, error) {
	var getRawSecretV3ByNameResponse GetRawSecretV3ByNameResponse
	response, err := httpClient.
		R().
		SetHeader("User-Agent", USER_AGENT).
		SetResult(&getRawSecretV3ByNameResponse).
		SetBody(request).
		SetQueryParam("expandSecretReferences", "true").
		SetQueryParam("include_imports", "true").
		SetQueryParam("environment", request.Environment).
		SetQueryParam("secretPath", request.SecretPath).
		SetQueryParam("workspaceId", request.WorkspaceID).
		SetQueryParam("type", "shared").
		Get(fmt.Sprintf("%v/v3/secrets/raw/%s", config.INFISICAL_URL, request.SecretName))

	if err != nil {
		return GetRawSecretV3ByNameResponse{}, NewGenericRequestError(operationCallFetchSingleSecretByName, err)
	}

	if response.IsError() {
		return GetRawSecretV3ByNameResponse{}, NewAPIErrorWithResponse(operationCallFetchSingleSecretByName, response, nil)
	}

	getRawSecretV3ByNameResponse.ETag = response.Header().Get(("etag"))

	return getRawSecretV3ByNameResponse, nil
}

func CallCreateDynamicSecretLeaseV1(httpClient *resty.Client, request CreateDynamicSecretLeaseV1Request) (CreateDynamicSecretLeaseV1Response, error) {
	var createDynamicSecretLeaseResponse CreateDynamicSecretLeaseV1Response
	response, err := httpClient.
		R().
		SetResult(&createDynamicSecretLeaseResponse).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/dynamic-secrets/leases", config.INFISICAL_URL))

	if err != nil {
		return CreateDynamicSecretLeaseV1Response{}, fmt.Errorf("CreateDynamicSecretLeaseV1: Unable to complete api request [err=%w]", err)
	}

	if response.IsError() {
		return CreateDynamicSecretLeaseV1Response{}, fmt.Errorf("CreateDynamicSecretLeaseV1: Unsuccessful response [%v %v] [status-code=%v] [response=%v]", response.Request.Method, response.Request.URL, response.StatusCode(), response.String())
	}

	return createDynamicSecretLeaseResponse, nil
}

func CallGetDynamicSecretLeaseV1(httpClient *resty.Client, request GetDynamicSecretLeaseV1Request) (GetDynamicSecretLeaseV1Response, error) {
	var getDynamicSecretLeaseResponse GetDynamicSecretLeaseV1Response
	response, err := httpClient.
		R().
		SetResult(&getDynamicSecretLeaseResponse).
		SetHeader("User-Agent", USER_AGENT).
		SetQueryParam("environmentSlug", request.Environment).
		SetQueryParam("projectSlug", request.ProjectSlug).
		SetQueryParam("secretPath", request.SecretPath).
		Get(fmt.Sprintf("%v/v1/dynamic-secrets/leases/%s", config.INFISICAL_URL, request.LeaseID))

	if err != nil {
		return GetDynamicSecretLeaseV1Response{}, fmt.Errorf("CallGetDynamicSecretLeaseV1: Unable to complete api request [err=%w]", err)
	}

	if response.IsError() {
		if response.StatusCode() == http.StatusNotFound {
			return GetDynamicSecretLeaseV1Response{}, ErrNotFound
		}
		return GetDynamicSecretLeaseV1Response{}, fmt.Errorf("CallGetDynamicSecretLeaseV1: Unsuccessful response [status-code=%v] [response=%v]", response.StatusCode(), response.String())
	}

	return getDynamicSecretLeaseResponse, nil
}

func CallCreateRawSecretsV3(httpClient *resty.Client, request CreateRawSecretV3Request) error {
	response, err := httpClient.
		R().
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v3/secrets/raw/%s", config.INFISICAL_URL, request.SecretName))

	if err != nil {
		return NewGenericRequestError(operationCallCreateRawSecretsV3, err)
	}

	if response.IsError() {
		return NewAPIErrorWithResponse(operationCallCreateRawSecretsV3, response, nil)
	}

	return nil
}

func CallUpdateRawSecretsV3(httpClient *resty.Client, request UpdateRawSecretByNameV3Request) error {
	response, err := httpClient.
		R().
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Patch(fmt.Sprintf("%v/v3/secrets/raw/%s", config.INFISICAL_URL, request.SecretName))

	if err != nil {
		return NewGenericRequestError(operationCallUpdateRawSecretsV3, err)
	}

	if response.IsError() {
		return NewAPIErrorWithResponse(operationCallUpdateRawSecretsV3, response, nil)
	}

	return nil
}

func CallRegisterGatewayIdentityV1(httpClient *resty.Client) (*GetRelayCredentialsResponseV1, error) {
	var resBody GetRelayCredentialsResponseV1
	response, err := httpClient.
		R().
		SetResult(&resBody).
		SetHeader("User-Agent", USER_AGENT).
		Post(fmt.Sprintf("%v/v1/gateways/register-identity", config.INFISICAL_URL))

	if err != nil {
		return nil, NewGenericRequestError(operationCallRegisterGatewayIdentityV1, err)
	}

	if response.IsError() {
		return nil, NewAPIErrorWithResponse(operationCallRegisterGatewayIdentityV1, response, nil)
	}

	return &resBody, nil
}

func CallExchangeRelayCertV1(httpClient *resty.Client, request ExchangeRelayCertRequestV1) (*ExchangeRelayCertResponseV1, error) {
	var resBody ExchangeRelayCertResponseV1
	response, err := httpClient.
		R().
		SetResult(&resBody).
		SetBody(request).
		SetHeader("User-Agent", USER_AGENT).
		Post(fmt.Sprintf("%v/v1/gateways/exchange-cert", config.INFISICAL_URL))

	if err != nil {
		return nil, NewGenericRequestError(operationCallExchangeRelayCertV1, err)
	}

	if response.IsError() {
		return nil, NewAPIErrorWithResponse(operationCallExchangeRelayCertV1, response, nil)
	}

	return &resBody, nil
}

func CallGatewayHeartBeatV1(httpClient *resty.Client) error {
	response, err := httpClient.
		R().
		SetHeader("User-Agent", USER_AGENT).
		Post(fmt.Sprintf("%v/v1/gateways/heartbeat", config.INFISICAL_URL))

	if err != nil {
		return NewGenericRequestError(operationCallGatewayHeartBeatV1, err)
	}

	if response.IsError() {
		return NewAPIErrorWithResponse(operationCallGatewayHeartBeatV1, response, nil)
	}

	return nil
}

func CallGatewayHeartBeatV2(httpClient *resty.Client) error {
	response, err := httpClient.
		R().
		SetHeader("User-Agent", USER_AGENT).
		Post(fmt.Sprintf("%v/v2/gateways/heartbeat", config.INFISICAL_URL))

	if err != nil {
		return NewGenericRequestError(operationCallGatewayHeartBeatV2, err)
	}

	if response.IsError() {
		return NewAPIErrorWithResponse(operationCallGatewayHeartBeatV2, response, nil)
	}

	return nil
}

func CallOrgRelayHeartBeat(httpClient *resty.Client, request RelayHeartbeatRequest) error {
	response, err := httpClient.
		R().
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/relays/heartbeat-org-relay", config.INFISICAL_URL))

	if err != nil {
		return NewGenericRequestError(operationCallOrgRelayHeartBeat, err)
	}

	if response.IsError() {
		return NewAPIErrorWithResponse(operationCallOrgRelayHeartBeat, response, nil)
	}

	return nil
}

func CallInstanceRelayHeartBeat(httpClient *resty.Client, request RelayHeartbeatRequest) error {
	response, err := httpClient.
		R().
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/relays/heartbeat-instance-relay", config.INFISICAL_URL))

	if err != nil {
		return NewGenericRequestError(operationCallInstanceRelayHeartBeat, err)
	}

	if response.IsError() {
		return NewAPIErrorWithResponse(operationCallInstanceRelayHeartBeat, response, nil)
	}

	return nil
}

func CallBootstrapInstance(httpClient *resty.Client, request BootstrapInstanceRequest) (BootstrapInstanceResponse, error) {
	var resBody BootstrapInstanceResponse
	response, err := httpClient.
		R().
		SetResult(&resBody).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/admin/bootstrap", request.Domain))

	if err != nil {
		return BootstrapInstanceResponse{}, NewGenericRequestError(operationCallBootstrapInstance, err)
	}

	if response.IsError() {
		return BootstrapInstanceResponse{}, NewAPIErrorWithResponse(operationCallBootstrapInstance, response, nil)
	}

	return resBody, nil
}

func CallRegisterInstanceRelay(httpClient *resty.Client, request RegisterRelayRequest) (RegisterRelayResponse, error) {
	var resBody RegisterRelayResponse
	response, err := httpClient.
		R().
		SetResult(&resBody).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/relays/register-instance-relay", config.INFISICAL_URL))

	if err != nil {
		return RegisterRelayResponse{}, NewGenericRequestError(operationCallRegisterInstanceRelay, err)
	}

	if response.IsError() {
		return RegisterRelayResponse{}, NewAPIErrorWithResponse(operationCallRegisterInstanceRelay, response, nil)
	}

	return resBody, nil
}

func CallRegisterRelay(httpClient *resty.Client, request RegisterRelayRequest) (RegisterRelayResponse, error) {
	var resBody RegisterRelayResponse
	response, err := httpClient.
		R().
		SetResult(&resBody).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/relays/register-org-relay", config.INFISICAL_URL))

	if err != nil {
		return RegisterRelayResponse{}, NewGenericRequestError(operationCallRegisterOrgRelay, err)
	}

	if response.IsError() {
		return RegisterRelayResponse{}, NewAPIErrorWithResponse(operationCallRegisterOrgRelay, response, nil)
	}

	return resBody, nil
}

func CallGetRelays(httpClient *resty.Client) (GetRelaysResponse, error) {
	var resBody GetRelaysResponse
	response, err := httpClient.
		R().
		SetResult(&resBody).
		SetHeader("User-Agent", USER_AGENT).
		Get(fmt.Sprintf("%v/v1/relays", config.INFISICAL_URL))

	if err != nil {
		return GetRelaysResponse{}, NewGenericRequestError(operationCallGetOrgRelays, err)
	}

	if response.IsError() {
		return GetRelaysResponse{}, NewAPIErrorWithResponse(operationCallGetOrgRelays, response, nil)
	}

	return resBody, nil
}

func CallRegisterGateway(httpClient *resty.Client, request RegisterGatewayRequest) (RegisterGatewayResponse, error) {
	var resBody RegisterGatewayResponse
	response, err := httpClient.
		R().
		SetResult(&resBody).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v2/gateways", config.INFISICAL_URL))

	if err != nil {
		return RegisterGatewayResponse{}, NewGenericRequestError(operationCallRegisterGateway, err)
	}

	if response.IsError() {
		return RegisterGatewayResponse{}, NewAPIErrorWithResponse(operationCallRegisterGateway, response, nil)
	}

	return resBody, nil
}

func CallPAMAccess(httpClient *resty.Client, request PAMAccessRequest) (PAMAccessResponse, error) {
	var pamAccessResponse PAMAccessResponse
	response, err := httpClient.
		R().
		SetResult(&pamAccessResponse).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/pam/accounts/access", config.INFISICAL_URL))

	if err != nil {
		return PAMAccessResponse{}, NewGenericRequestError(operationCallPAMAccess, err)
	}

	if response.IsError() {
		return PAMAccessResponse{}, NewAPIErrorWithResponse(operationCallPAMAccess, response, nil)
	}

	return pamAccessResponse, nil
}

func CallPAMSessionCredentials(httpClient *resty.Client, sessionId string) (PAMSessionCredentialsResponse, error) {
	var pamSessionCredentialsResponse PAMSessionCredentialsResponse
	response, err := httpClient.
		R().
		SetResult(&pamSessionCredentialsResponse).
		SetHeader("User-Agent", USER_AGENT).
		Get(fmt.Sprintf("%v/v1/pam/sessions/%s/credentials", config.INFISICAL_URL, sessionId))

	if err != nil {
		return PAMSessionCredentialsResponse{}, NewGenericRequestError(operationCallPAMSessionCredentials, err)
	}

	if response.IsError() {
		return PAMSessionCredentialsResponse{}, NewAPIErrorWithResponse(operationCallPAMSessionCredentials, response, nil)
	}

	return pamSessionCredentialsResponse, nil
}

func CallGetPamSessionKey(httpClient *resty.Client) (string, error) {
	response, err := httpClient.
		R().
		SetHeader("User-Agent", USER_AGENT).
		Get(fmt.Sprintf("%v/v2/gateways/pam-session-key", config.INFISICAL_URL))

	if err != nil {
		return "", NewGenericRequestError(operationCallGetPamSessionKey, err)
	}

	if response.IsError() {
		return "", NewAPIErrorWithResponse(operationCallGetPamSessionKey, response, nil)
	}

	return base64.StdEncoding.EncodeToString(response.Body()), nil
}

func CallUploadPamSessionLogs(httpClient *resty.Client, sessionId string, request UploadPAMSessionLogsRequest) error {
	response, err := httpClient.
		R().
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/pam/sessions/%s/logs", config.INFISICAL_URL, sessionId))

	if err != nil {
		return NewGenericRequestError(operationCallUploadPamSessionLog, err)
	}

	if response.IsError() {
		return NewAPIErrorWithResponse(operationCallUploadPamSessionLog, response, nil)
	}

	return nil
}

func CallPAMSessionTermination(httpClient *resty.Client, sessionId string) error {
	response, err := httpClient.
		R().
		SetHeader("User-Agent", USER_AGENT).
		Post(fmt.Sprintf("%v/v1/pam/sessions/%s/end", config.INFISICAL_URL, sessionId))

	if err != nil {
		return NewGenericRequestError(operationCallPAMSessionTermination, err)
	}

	if response.IsError() {
		return NewAPIErrorWithResponse(operationCallPAMSessionTermination, response, nil)
	}

	return nil
}

func CallIssueCertificate(httpClient *resty.Client, request IssueCertificateRequest) (*CertificateResponse, error) {
	var resBody CertificateResponse
	response, err := httpClient.
		R().
		SetResult(&resBody).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/cert-manager/certificates", config.INFISICAL_URL))

	if err != nil {
		return nil, NewGenericRequestError(operationCallIssueCertificate, err)
	}

	if response.IsError() {
		return nil, NewAPIErrorWithResponse(operationCallIssueCertificate, response, nil)
	}

	return &resBody, nil
}

func CallRetrieveCertificate(httpClient *resty.Client, certificateId string) (*RetrieveCertificateResponse, error) {
	var resBody RetrieveCertificateResponse
	response, err := httpClient.
		R().
		SetResult(&resBody).
		SetHeader("User-Agent", USER_AGENT).
		Get(fmt.Sprintf("%v/v1/cert-manager/certificates/%s", config.INFISICAL_URL, certificateId))

	if err != nil {
		return nil, NewGenericRequestError(operationCallRetrieveCertificate, err)
	}

	if response.IsError() {
		return nil, NewAPIErrorWithResponse(operationCallRetrieveCertificate, response, nil)
	}

	return &resBody, nil
}

func CallRenewCertificate(httpClient *resty.Client, certificateId string, request RenewCertificateRequest) (*RenewCertificateResponse, error) {
	var resBody RenewCertificateResponse
	response, err := httpClient.
		R().
		SetResult(&resBody).
		SetHeader("User-Agent", USER_AGENT).
		SetBody(request).
		Post(fmt.Sprintf("%v/v1/cert-manager/certificates/%s/renew", config.INFISICAL_URL, certificateId))

	if err != nil {
		return nil, NewGenericRequestError(operationCallRenewCertificate, err)
	}

	if response.IsError() {
		return nil, NewAPIErrorWithResponse(operationCallRenewCertificate, response, nil)
	}

	return &resBody, nil
}

func CallGetCertificateRequest(httpClient *resty.Client, certificateRequestId string) (*GetCertificateRequestResponse, error) {
	var resBody GetCertificateRequestResponse
	response, err := httpClient.
		R().
		SetResult(&resBody).
		SetHeader("User-Agent", USER_AGENT).
		Get(fmt.Sprintf("%v/v1/cert-manager/certificates/certificate-requests/%s", config.INFISICAL_URL, certificateRequestId))

	if err != nil {
		return nil, NewGenericRequestError(operationCallGetCertificateRequest, err)
	}

	if response.IsError() {
		return nil, NewAPIErrorWithResponse(operationCallGetCertificateRequest, response, nil)
	}

	return &resBody, nil
}
