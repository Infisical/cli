package util

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/Infisical/infisical-merge/packages/config"
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

// resolveReLoginDomain decides which domain the automatic re-login child process
// should be pinned to, or returns "" to leave the child's normal domain
// resolution (and its interactive region prompt) untouched.
//
// storedDomain is LoggedInUserDomain from the config file, i.e. the instance
// whose session just expired, so it wins. resolvedURL is config.INFISICAL_URL as
// already resolved by the root command from --domain, INFISICAL_DOMAIN or
// .infisical.json; it is only forwarded when it differs from the built-in US
// default, since that default is what an unconfigured invocation looks like and
// forwarding it would silently skip the region prompt for first-time logins.
func resolveReLoginDomain(storedDomain string, resolvedURL string) string {
	if storedDomain != "" {
		return storedDomain
	}
	if resolvedURL != "" && resolvedURL != AppendAPIEndpoint(INFISICAL_DEFAULT_US_URL) {
		return resolvedURL
	}
	return ""
}

// buildReLoginArgs returns the argv for the re-login child process.
func buildReLoginArgs(domain string) []string {
	args := []string{"login", "--silent"}
	if domain != "" {
		args = append(args, "--domain", domain)
	}
	return args
}

// EstablishUserLoginSession handles the login flow to either create a new session or restore an expired one.
// It returns fresh user details if login is successful.
func EstablishUserLoginSession() LoggedInUserDetails {
	log.Info().Msg("No valid login session found, triggering login flow")

	exePath, err := os.Executable()
	if err != nil {
		PrintErrorMessageAndExit(fmt.Sprintf("Failed to determine executable path: %v", err))
	}

	// The child process resolves its own domain from scratch and would otherwise
	// fall back to US Cloud, so forward the domain this session was using.
	// Without this an expired EU Cloud session re-prompts for a region, opens the
	// US login page, and on completion rewrites LoggedInUserDomain to US.
	var storedDomain string
	if configFile, configErr := GetConfigFile(); configErr == nil {
		storedDomain = configFile.LoggedInUserDomain
	}
	domain := resolveReLoginDomain(storedDomain, config.INFISICAL_URL)

	// Spawn infisical login command
	loginCmd := exec.Command(exePath, buildReLoginArgs(domain)...)
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
