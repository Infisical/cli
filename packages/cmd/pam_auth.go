package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	infisicalSdk "github.com/infisical/go-sdk"
	"github.com/spf13/cobra"
)

const pamAuthMethods = "universal-auth, kubernetes, azure, gcp-id-token, gcp-iam, aws-iam, oidc-auth, jwt-auth, ldap-auth"

const pamAuthAnnotation = "infisical.pamAuth"

// addPAMAuthFlags declares every input the machine identity handlers read: GetCmdFlagOrEnv fails on
// an undeclared flag, which would make the environment variable fallbacks unreachable.
func addPAMAuthFlags(cmd *cobra.Command) {
	if cmd.Annotations == nil {
		cmd.Annotations = map[string]string{}
	}
	cmd.Annotations[serviceTokenAnnotation] = serviceTokenUnsupported[serviceTokenAnnotation]
	cmd.Annotations[pamAuthAnnotation] = "true"
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

func usesPAMAuth(cmd *cobra.Command) bool {
	return cmd.Annotations[pamAuthAnnotation] != ""
}

// pamToken is GetInfisicalToken without the generic TOKEN variable, which belongs to the gateway Helm
// chart and would otherwise be sent to Infisical as a bearer token.
func pamToken(cmd *cobra.Command) *models.TokenDetails {
	candidates := []struct{ value, source string }{}
	if value, _ := cmd.Flags().GetString("token"); value != "" {
		candidates = append(candidates, struct{ value, source string }{value, "--token flag"})
	}
	for _, name := range []string{util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME, util.INFISICAL_TOKEN_NAME} {
		if value := os.Getenv(name); value != "" {
			candidates = append(candidates, struct{ value, source string }{value, name + " environment variable"})
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	first := candidates[0]
	tokenType := util.UNIVERSAL_AUTH_TOKEN_IDENTIFIER
	if strings.HasPrefix(first.value, "st.") {
		tokenType = util.SERVICE_TOKEN_IDENTIFIER
	}
	return &models.TokenDetails{Type: tokenType, Token: first.value, Source: first.source}
}

// pamTokenInUse is the token resolvePAMAccessToken will use, or nil when an explicit --auth-method
// takes precedence over a token from the environment.
func pamTokenInUse(cmd *cobra.Command) *models.TokenDetails {
	if !cmd.Flags().Changed("token") && cmd.Flags().Changed("auth-method") {
		return nil
	}
	return pamToken(cmd)
}

// Precedence: --token, then an explicit --auth-method, then a token from the environment, then
// INFISICAL_AUTH_METHOD, then the stored user login. Without a terminal nothing interactive starts.
func resolvePAMAccessToken(cmd *cobra.Command) (accessToken func() string, stop func(), machineIdentity bool) {
	token := pamToken(cmd)
	explicitToken := cmd.Flags().Changed("token")

	if !explicitToken && cmd.Flags().Changed("auth-method") {
		if source, stopAuth := authenticateMachineIdentity(cmd); source != nil {
			return source, stopAuth, true
		}
		// An explicit --auth-method user asks for the saved login over any token in the environment.
		token = nil
	}

	// A service token exported for other commands mustn't hijack PAM; only an explicit one is an error.
	if token != nil && token.Type == util.SERVICE_TOKEN_IDENTIFIER && !explicitToken {
		token = nil
	}

	if token != nil {
		if token.Type == util.SERVICE_TOKEN_IDENTIFIER {
			exitWithError(cmd, errPAMServiceToken())
		}
		if !explicitToken && errorOutputFormat(cmd) == "" {
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

	return pamUserAccessToken(cmd), func() {}, false
}

func pamUserAccessToken(cmd *cobra.Command) func() string {
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
		selectionError := errors.Is(err, util.ErrOrgSelection) || errors.Is(err, util.ErrProfileNotFound) || errors.Is(err, util.ErrProfileDomainMismatch)
		exitWithError(cmd, errPAMLoginUnreadable(err, selectionError))
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
	return func() string { return jwt }
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
		exitWithError(cmd, errPAMInvalidAuthMethod(""))
	}

	if authMethod == "" || authMethod == "user" {
		return nil, nil
	}

	valid, strategy := util.IsAuthMethodValid(authMethod, false)
	if !valid {
		exitWithError(cmd, errPAMInvalidAuthMethod(authMethod))
	}

	customHeaders, err := util.GetInfisicalCustomHeadersMap()
	if err != nil {
		exitWithError(cmd, errPAMMachineIdentityLogin(authMethod, err))
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
		exitWithError(cmd, errPAMInvalidAuthMethod(authMethod))
	}

	credential, err := login()
	if err != nil {
		cancel()
		exitWithError(cmd, errPAMMachineIdentityLogin(authMethod, err))
	}
	if credential.AccessToken == "" {
		cancel()
		exitWithError(cmd, errPAMMachineIdentityLogin(authMethod, errors.New("no access token was returned")))
	}

	// The client's getter returns whatever the refresh goroutine last renewed to.
	return client.Auth().GetAccessToken, cancel
}
