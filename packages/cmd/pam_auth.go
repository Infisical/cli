package cmd

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	infisicalSdk "github.com/infisical/go-sdk"
	"github.com/spf13/cobra"
)

const pamAuthMethods = "universal-auth, kubernetes, azure, gcp-id-token, gcp-iam, aws-iam, oidc-auth, jwt-auth, ldap-auth"

// addPAMAuthFlags declares every input the machine identity handlers read: GetCmdFlagOrEnv fails on
// an undeclared flag, which would make the environment variable fallbacks unreachable.
func addPAMAuthFlags(cmd *cobra.Command) {
	cmd.Flags().String("token", "", "Authenticate as a machine identity using its access token")
	cmd.Flags().String("auth-method", "", "Authenticate as a machine identity with its own credentials instead of a ready-made --token ["+pamAuthMethods+"]")
	cmd.Flags().String("client-id", "", "Client id for universal auth")
	cmd.Flags().String("client-secret", "", "Client secret for universal auth")
	cmd.Flags().String("machine-identity-id", "", "Machine identity id for the kubernetes, azure, gcp-id-token, gcp-iam, aws-iam, oidc-auth, jwt-auth and ldap-auth methods")
	cmd.Flags().String("service-account-token-path", "", "Service account token path for kubernetes auth")
	cmd.Flags().String("service-account-key-file-path", "", "Service account key file path for gcp-iam auth")
	cmd.Flags().String("jwt", "", "JWT for the jwt-based methods [oidc-auth, jwt-auth]")
	cmd.Flags().String("ldap-username", "", "Username for ldap-auth")
	cmd.Flags().String("ldap-password", "", "Password for ldap-auth")
	cmd.Flags().String("organization-slug", "", "Scope the session to this sub-organization the machine identity can reach. Defaults to the organization the identity was created in")
}

// A machine identity wins over the stored user login; without a terminal nothing interactive starts.
func resolvePAMAccessToken(cmd *cobra.Command) (accessToken func() string, stop func(), machineIdentity bool) {
	token, err := util.GetInfisicalToken(cmd)
	if err != nil {
		util.HandleError(err, "Unable to parse token")
	}

	// A service token exported for other commands mustn't hijack PAM; only an explicit one is an error.
	if token != nil && token.Type == util.SERVICE_TOKEN_IDENTIFIER && !cmd.Flags().Changed("token") {
		token = nil
	}

	if token != nil {
		if token.Type == util.SERVICE_TOKEN_IDENTIFIER {
			exitWithError(cmd, errPAMServiceToken())
		}
		if !cmd.Flags().Changed("token") && errorOutputFormat(cmd) == "" {
			printProjectsTip(cmd, fmt.Sprintf("Using the machine identity token from the %s.", token.Source))
		}
		if exp, ok := jwtExpiry(token.Token); ok && exp.Before(time.Now()) {
			exitWithError(cmd, errPAMTokenExpired(token.Source))
		}
		return func() string { return token.Token }, func() {}, true
	}

	if source, stopAuth := authenticateMachineIdentity(cmd); source != nil {
		return source, stopAuth, true
	}

	interactive := stdinIsTerminal()
	if !util.IsLoggedIn() {
		if !interactive {
			exitWithError(cmd, errPAMAuthRequired(nil))
		}
		util.RequireLogin()
	}

	loggedInUserDetails, err := util.GetCurrentLoggedInUserDetails(true)
	if errors.Is(err, util.ErrUserNotLoggedIn) && !interactive {
		exitWithError(cmd, errPAMAuthRequired(err))
	}
	if err != nil {
		util.HandleError(err, "Unable to get logged in user details")
	}

	if loggedInUserDetails.LoginExpired && util.ValidateInfisicalAPIConnection() {
		if !interactive {
			exitWithError(cmd, errPAMAuthRequired(nil))
		}
		loggedInUserDetails = util.EstablishUserLoginSession()
	}

	jwt := loggedInUserDetails.UserCredentials.JTWToken
	if exp, ok := jwtExpiry(jwt); ok && exp.Before(time.Now()) {
		exitWithError(cmd, errPAMAuthRequired(nil))
	}
	return func() string { return jwt }, func() {}, false
}

// newPAMHTTPClient reads the token per request, so a renewed machine identity token is picked up.
func newPAMHTTPClient(accessToken func() string) *resty.Client {
	httpClient, err := util.GetRestyClientWithCustomHeaders()
	if err != nil {
		util.HandleError(err, "Failed to build the API client")
	}
	httpClient.SetHeader("User-Agent", api.USER_AGENT)
	httpClient.OnBeforeRequest(func(_ *resty.Client, request *resty.Request) error {
		request.SetAuthToken(accessToken())
		return nil
	})
	return httpClient
}

// authenticateMachineIdentity logs in as a machine identity when --auth-method or
// INFISICAL_AUTH_METHOD names one. Both results are nil when none was asked for.
func authenticateMachineIdentity(cmd *cobra.Command) (accessToken func() string, stop func()) {
	authMethod, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "auth-method", []string{util.INFISICAL_AUTH_METHOD_NAME}, "")
	if err != nil {
		util.HandleError(err, "Unable to parse auth-method flag")
	}

	if authMethod == "" || authMethod == "user" {
		return nil, nil
	}

	valid, strategy := util.IsAuthMethodValid(authMethod, false)
	if !valid {
		util.PrintErrorMessageAndExit(fmt.Sprintf("Invalid auth method %s. Supported: %s.", quoted(authMethod, "auth method"), pamAuthMethods))
	}

	customHeaders, err := util.GetInfisicalCustomHeadersMap()
	if err != nil {
		util.HandleError(err, "Unable to get custom headers")
	}

	// AutoTokenRefresh stays on: a session can outlive the first token, and callers read the current
	// one per request.
	ctx, cancel := context.WithCancel(cmd.Context())
	client := infisicalSdk.NewInfisicalClient(ctx, infisicalSdk.Config{
		SiteUrl:       config.INFISICAL_URL,
		UserAgent:     api.USER_AGENT,
		CustomHeaders: customHeaders,
	})

	authenticator := util.NewSdkAuthenticator(client, cmd)
	strategies := map[util.AuthStrategyType]func() (infisicalSdk.MachineIdentityCredential, error){
		util.AuthStrategy.UNIVERSAL_AUTH:    authenticator.HandleUniversalAuthLogin,
		util.AuthStrategy.KUBERNETES_AUTH:   authenticator.HandleKubernetesAuthLogin,
		util.AuthStrategy.AZURE_AUTH:        authenticator.HandleAzureAuthLogin,
		util.AuthStrategy.GCP_ID_TOKEN_AUTH: authenticator.HandleGcpIdTokenAuthLogin,
		util.AuthStrategy.GCP_IAM_AUTH:      authenticator.HandleGcpIamAuthLogin,
		util.AuthStrategy.AWS_IAM_AUTH:      authenticator.HandleAwsIamAuthLogin,
		util.AuthStrategy.OIDC_AUTH:         authenticator.HandleOidcAuthLogin,
		util.AuthStrategy.JWT_AUTH:          authenticator.HandleJwtAuthLogin,
		util.AuthStrategy.LDAP_AUTH:         authenticator.HandleLdapAuthLogin,
	}

	// IsAuthMethodValid accepts strategies this table may lack, and a missing key is a nil func.
	login, supported := strategies[strategy]
	if !supported {
		cancel()
		util.PrintErrorMessageAndExit(fmt.Sprintf("Auth method %q is not supported here. Supported: %s.", authMethod, pamAuthMethods))
	}

	credential, err := login()
	if err != nil {
		cancel()
		util.HandleError(err, fmt.Sprintf("Unable to authenticate with %s", authMethod))
	}
	if credential.AccessToken == "" {
		cancel()
		util.PrintErrorMessageAndExit(fmt.Sprintf("Authenticating with %s returned no access token.", authMethod))
	}

	// The client's getter returns whatever the refresh goroutine last renewed to.
	return client.Auth().GetAccessToken, cancel
}
