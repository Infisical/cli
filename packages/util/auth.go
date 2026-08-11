package util

import (
	"fmt"
	"os"
	"os/exec"

	infisicalSdk "github.com/infisical/go-sdk"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

type AuthStrategyType string

var AuthStrategy = struct {
	UNIVERSAL_AUTH    AuthStrategyType
	KUBERNETES_AUTH   AuthStrategyType
	AZURE_AUTH        AuthStrategyType
	GCP_ID_TOKEN_AUTH AuthStrategyType
	GCP_IAM_AUTH      AuthStrategyType
	AWS_IAM_AUTH      AuthStrategyType
	OIDC_AUTH         AuthStrategyType
	JWT_AUTH          AuthStrategyType
	LDAP_AUTH         AuthStrategyType
}{
	UNIVERSAL_AUTH:    "universal-auth",
	KUBERNETES_AUTH:   "kubernetes",
	AZURE_AUTH:        "azure",
	GCP_ID_TOKEN_AUTH: "gcp-id-token",
	GCP_IAM_AUTH:      "gcp-iam",
	AWS_IAM_AUTH:      "aws-iam",
	OIDC_AUTH:         "oidc-auth",
	JWT_AUTH:          "jwt-auth",
	LDAP_AUTH:         "ldap-auth",
}

var AVAILABLE_AUTH_STRATEGIES = []AuthStrategyType{
	AuthStrategy.UNIVERSAL_AUTH,
	AuthStrategy.KUBERNETES_AUTH,
	AuthStrategy.AZURE_AUTH,
	AuthStrategy.GCP_ID_TOKEN_AUTH,
	AuthStrategy.GCP_IAM_AUTH,
	AuthStrategy.AWS_IAM_AUTH,
	AuthStrategy.OIDC_AUTH,
	AuthStrategy.JWT_AUTH,
	AuthStrategy.LDAP_AUTH,
}

func IsAuthMethodValid(authMethod string, allowUserAuth bool) (isValid bool, strategy AuthStrategyType) {

	if authMethod == "user" && allowUserAuth {
		return true, ""
	}

	for _, strategy := range AVAILABLE_AUTH_STRATEGIES {
		if string(strategy) == authMethod {
			return true, strategy
		}
	}
	return false, ""
}

// EstablishUserLoginSession handles the login flow to either create a new session or restore an expired one.
// It returns fresh user details if login is successful.
func EstablishUserLoginSession() LoggedInUserDetails {
	log.Info().Msg("No valid login session found, triggering login flow")

	exePath, err := os.Executable()
	if err != nil {
		PrintErrorMessageAndExit(fmt.Sprintf("Failed to determine executable path: %v", err))
	}

	// Spawn infisical login command
	loginCmd := exec.Command(exePath, "login", "--silent")
	loginCmd.Stdin = os.Stdin
	loginCmd.Stdout = os.Stdout
	loginCmd.Stderr = os.Stderr

	err = loginCmd.Run()
	if err != nil {
		PrintErrorMessageAndExit(fmt.Sprintf("Failed to automatically trigger login flow. Please run [infisical login] manually to login."))
	}

	loggedInUserDetails, err := GetCurrentLoggedInUserDetails(true)
	if err != nil {
		PrintErrorMessageAndExit("You must be logged in to run this command. To login, run [infisical login]")
	}

	if loggedInUserDetails.LoginExpired {
		PrintErrorMessageAndExit("Your login session has expired. Please run [infisical login]")
	}

	return loggedInUserDetails
}

type SdkAuthenticator struct {
	infisicalClient infisicalSdk.InfisicalClientInterface
	cmd             *cobra.Command
}

func NewSdkAuthenticator(infisicalClient infisicalSdk.InfisicalClientInterface, cmd *cobra.Command) *SdkAuthenticator {
	return &SdkAuthenticator{
		infisicalClient: infisicalClient,
		cmd:             cmd,
	}
}
func (a *SdkAuthenticator) HandleUniversalAuthLogin() (credential infisicalSdk.MachineIdentityCredential, e error) {

	clientId, err := GetCmdFlagOrEnv(a.cmd, "client-id", []string{INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME})

	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, err
	}

	clientSecret, err := GetCmdFlagOrEnv(a.cmd, "client-secret", []string{INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET_NAME})
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, err
	}

	// We are not providing an environment variable because infisical go sdk will check for the environment variable when value is emtpy
	// Refer: https://github.com/Infisical/go-sdk/blob/main/packages/util/constants.go#L10
	organizationSlug, err := GetCmdFlagOrEnvWithDefaultValue(a.cmd, "organization-slug", []string{}, "")
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, err
	}

	return a.infisicalClient.Auth().WithOrganizationSlug(organizationSlug).UniversalAuthLogin(clientId, clientSecret)
}

func (a *SdkAuthenticator) HandleJwtAuthLogin() (credential infisicalSdk.MachineIdentityCredential, e error) {

	identityId, err := GetCmdFlagOrEnv(a.cmd, "machine-identity-id", []string{INFISICAL_MACHINE_IDENTITY_ID_NAME})
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, err
	}

	jwt, err := GetCmdFlagOrEnv(a.cmd, "jwt", []string{INFISICAL_JWT_NAME})
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, err
	}

	organizationSlug, err := GetCmdFlagOrEnvWithDefaultValue(a.cmd, "organization-slug", []string{}, "")
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, err
	}

	return a.infisicalClient.Auth().WithOrganizationSlug(organizationSlug).JwtAuthLogin(identityId, jwt)
}

func (a *SdkAuthenticator) HandleKubernetesAuthLogin() (credential infisicalSdk.MachineIdentityCredential, e error) {

	identityId, err := GetCmdFlagOrEnv(a.cmd, "machine-identity-id", []string{INFISICAL_MACHINE_IDENTITY_ID_NAME})
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, err
	}

	serviceAccountTokenPath, err := GetCmdFlagOrEnv(a.cmd, "service-account-token-path", []string{INFISICAL_KUBERNETES_SERVICE_ACCOUNT_TOKEN_NAME})
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, err
	}

	organizationSlug, err := GetCmdFlagOrEnvWithDefaultValue(a.cmd, "organization-slug", []string{}, "")
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, err
	}

	return a.infisicalClient.Auth().WithOrganizationSlug(organizationSlug).KubernetesAuthLogin(identityId, serviceAccountTokenPath)
}

func (a *SdkAuthenticator) HandleAzureAuthLogin() (credential infisicalSdk.MachineIdentityCredential, e error) {

	identityId, err := GetCmdFlagOrEnv(a.cmd, "machine-identity-id", []string{INFISICAL_MACHINE_IDENTITY_ID_NAME})
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, err
	}

	organizationSlug, err := GetCmdFlagOrEnvWithDefaultValue(a.cmd, "organization-slug", []string{}, "")
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, err
	}

	return a.infisicalClient.Auth().WithOrganizationSlug(organizationSlug).AzureAuthLogin(identityId, "")
}

func (a *SdkAuthenticator) HandleGcpIdTokenAuthLogin() (credential infisicalSdk.MachineIdentityCredential, e error) {

	identityId, err := GetCmdFlagOrEnv(a.cmd, "machine-identity-id", []string{INFISICAL_MACHINE_IDENTITY_ID_NAME})
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, err
	}

	organizationSlug, err := GetCmdFlagOrEnvWithDefaultValue(a.cmd, "organization-slug", []string{}, "")
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, err
	}

	return a.infisicalClient.Auth().WithOrganizationSlug(organizationSlug).GcpIdTokenAuthLogin(identityId)
}

func (a *SdkAuthenticator) HandleGcpIamAuthLogin() (credential infisicalSdk.MachineIdentityCredential, e error) {

	identityId, err := GetCmdFlagOrEnv(a.cmd, "machine-identity-id", []string{INFISICAL_MACHINE_IDENTITY_ID_NAME})
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, err
	}

	serviceAccountKeyFilePath, err := GetCmdFlagOrEnv(a.cmd, "service-account-key-file-path", []string{INFISICAL_GCP_IAM_SERVICE_ACCOUNT_KEY_FILE_PATH_NAME})
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, err
	}

	organizationSlug, err := GetCmdFlagOrEnvWithDefaultValue(a.cmd, "organization-slug", []string{}, "")
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, err
	}

	return a.infisicalClient.Auth().WithOrganizationSlug(organizationSlug).GcpIamAuthLogin(identityId, serviceAccountKeyFilePath)
}

func (a *SdkAuthenticator) HandleAwsIamAuthLogin() (credential infisicalSdk.MachineIdentityCredential, e error) {

	identityId, err := GetCmdFlagOrEnv(a.cmd, "machine-identity-id", []string{INFISICAL_MACHINE_IDENTITY_ID_NAME})
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, err
	}

	organizationSlug, err := GetCmdFlagOrEnvWithDefaultValue(a.cmd, "organization-slug", []string{}, "")
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, err
	}

	return a.infisicalClient.Auth().WithOrganizationSlug(organizationSlug).AwsIamAuthLogin(identityId)
}

func (a *SdkAuthenticator) HandleOidcAuthLogin() (credential infisicalSdk.MachineIdentityCredential, e error) {

	identityId, err := GetCmdFlagOrEnv(a.cmd, "machine-identity-id", []string{INFISICAL_MACHINE_IDENTITY_ID_NAME})
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, err
	}

	jwt, err := GetCmdFlagOrEnv(a.cmd, "jwt", []string{INFISICAL_JWT_NAME, INFISICAL_OIDC_AUTH_JWT_NAME})
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, err
	}

	organizationSlug, err := GetCmdFlagOrEnvWithDefaultValue(a.cmd, "organization-slug", []string{}, "")
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, err
	}

	return a.infisicalClient.Auth().WithOrganizationSlug(organizationSlug).OidcAuthLogin(identityId, jwt)
}

func (a *SdkAuthenticator) HandleLdapAuthLogin() (credential infisicalSdk.MachineIdentityCredential, e error) {
	identityId, err := GetCmdFlagOrEnv(a.cmd, "machine-identity-id", []string{INFISICAL_MACHINE_IDENTITY_ID_NAME})
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, err
	}

	ldapUsername, err := GetCmdFlagOrEnv(a.cmd, "ldap-username", []string{INFISICAL_LDAP_USERNAME})
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, err
	}

	ldapPassword, err := GetCmdFlagOrEnv(a.cmd, "ldap-password", []string{INFISICAL_LDAP_PASSWORD})
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, err
	}

	organizationSlug, err := GetCmdFlagOrEnvWithDefaultValue(a.cmd, "organization-slug", []string{}, "")
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, err
	}

	return a.infisicalClient.Auth().WithOrganizationSlug(organizationSlug).LdapAuthLogin(identityId, ldapUsername, ldapPassword)
}

const MachineIdentityAuthMethods = "universal-auth, kubernetes, azure, gcp-id-token, gcp-iam, aws-iam, oidc-auth, jwt-auth, ldap-auth"

// GetCmdFlagOrEnv looks a flag up before the environment and errors on a name the command never
// declared, so any command offering --auth-method must register all of these.
var MachineIdentityAuthFlags = []string{
	"auth-method",
	"client-id",
	"client-secret",
	"machine-identity-id",
	"service-account-token-path",
	"service-account-key-file-path",
	"jwt",
	"ldap-username",
	"ldap-password",
	"organization-slug",
}

var MachineIdentityAuthEnvVars = []string{
	INFISICAL_AUTH_METHOD_NAME,
	INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME,
	INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET_NAME,
	INFISICAL_MACHINE_IDENTITY_ID_NAME,
	INFISICAL_KUBERNETES_SERVICE_ACCOUNT_TOKEN_NAME,
	INFISICAL_GCP_IAM_SERVICE_ACCOUNT_KEY_FILE_PATH_NAME,
	INFISICAL_JWT_NAME,
	INFISICAL_OIDC_AUTH_JWT_NAME,
	INFISICAL_LDAP_USERNAME,
	INFISICAL_LDAP_PASSWORD,
}

func RegisterMachineIdentityAuthFlags(cmd *cobra.Command, identity string) {
	cmd.Flags().String("auth-method", "", fmt.Sprintf("how to authenticate the %s machine identity ["+MachineIdentityAuthMethods+"]", identity))
	cmd.Flags().String("client-id", "", fmt.Sprintf("client id for universal auth, for the %s machine identity", identity))
	cmd.Flags().String("client-secret", "", fmt.Sprintf("client secret for universal auth, for the %s machine identity", identity))
	cmd.Flags().String("machine-identity-id", "", "machine identity id, for every method except universal-auth")
	cmd.Flags().String("service-account-token-path", "", "service account token path for kubernetes auth (on a pod, /var/run/secrets/kubernetes.io/serviceaccount/token)")
	cmd.Flags().String("service-account-key-file-path", "", "service account key file path for gcp-iam auth")
	cmd.Flags().String("jwt", "", "JWT for the jwt-based methods [oidc-auth, jwt-auth]")
	cmd.Flags().String("ldap-username", "", "username for ldap-auth")
	cmd.Flags().String("ldap-password", "", "password for ldap-auth")
	cmd.Flags().String("organization-slug", "", "scope the identity to this sub-organization. Defaults to the organization the identity was created in")
}

// Returns "" for "user" as well as for nothing: some callers spell out the human login.
func ResolveAuthMethod(cmd *cobra.Command) (string, error) {
	authMethod, err := GetCmdFlagOrEnvWithDefaultValue(cmd, "auth-method", []string{INFISICAL_AUTH_METHOD_NAME}, "")
	if err != nil {
		return "", err
	}
	if authMethod == "user" {
		return "", nil
	}
	return authMethod, nil
}

func ValidateAuthMethod(authMethod string) error {
	valid, strategy := IsAuthMethodValid(authMethod, false)
	if !valid {
		return fmt.Errorf("invalid auth method %q. Supported: %s", authMethod, MachineIdentityAuthMethods)
	}
	if !machineIdentityStrategies[strategy] {
		return fmt.Errorf("auth method %q is not supported here. Supported: %s", authMethod, MachineIdentityAuthMethods)
	}
	return nil
}

// IsAuthMethodValid accepts strategies with no handler below. Those must be reported rather than
// indexed: a nil func panics, which is what `infisical login` does today for ldap-auth.
var machineIdentityStrategies = map[AuthStrategyType]bool{
	AuthStrategy.UNIVERSAL_AUTH:    true,
	AuthStrategy.KUBERNETES_AUTH:   true,
	AuthStrategy.AZURE_AUTH:        true,
	AuthStrategy.GCP_ID_TOKEN_AUTH: true,
	AuthStrategy.GCP_IAM_AUTH:      true,
	AuthStrategy.AWS_IAM_AUTH:      true,
	AuthStrategy.OIDC_AUTH:         true,
	AuthStrategy.JWT_AUTH:          true,
	AuthStrategy.LDAP_AUTH:         true,
}

func MachineIdentityLoginFunc(cmd *cobra.Command, client infisicalSdk.InfisicalClientInterface, authMethod string) (func() (infisicalSdk.MachineIdentityCredential, error), error) {
	if err := ValidateAuthMethod(authMethod); err != nil {
		return nil, err
	}
	_, strategy := IsAuthMethodValid(authMethod, false)

	authenticator := NewSdkAuthenticator(client, cmd)
	strategies := map[AuthStrategyType]func() (infisicalSdk.MachineIdentityCredential, error){
		AuthStrategy.UNIVERSAL_AUTH:    authenticator.HandleUniversalAuthLogin,
		AuthStrategy.KUBERNETES_AUTH:   authenticator.HandleKubernetesAuthLogin,
		AuthStrategy.AZURE_AUTH:        authenticator.HandleAzureAuthLogin,
		AuthStrategy.GCP_ID_TOKEN_AUTH: authenticator.HandleGcpIdTokenAuthLogin,
		AuthStrategy.GCP_IAM_AUTH:      authenticator.HandleGcpIamAuthLogin,
		AuthStrategy.AWS_IAM_AUTH:      authenticator.HandleAwsIamAuthLogin,
		AuthStrategy.OIDC_AUTH:         authenticator.HandleOidcAuthLogin,
		AuthStrategy.JWT_AUTH:          authenticator.HandleJwtAuthLogin,
		AuthStrategy.LDAP_AUTH:         authenticator.HandleLdapAuthLogin,
	}

	login, supported := strategies[strategy]
	if !supported {
		return nil, fmt.Errorf("auth method %q is not supported here. Supported: %s", authMethod, MachineIdentityAuthMethods)
	}
	return login, nil
}
