/*
Copyright (c) 2023 Infisical Inc.
*/
package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	localkmip "github.com/Infisical/infisical-merge/packages/kmip"
	"github.com/Infisical/infisical-merge/packages/util"
	kmip "github.com/infisical/infisical-kmip"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var kmipCmd = &cobra.Command{
	Example: `  infisical kmip
  infisical kmip start --enroll-method=token --token=<enrollment-token> --server-name=<server-name> --domain=<your-infisical-domain>
  sudo infisical kmip systemd install --enroll-method=token --token=<enrollment-token> --server-name=<server-name> --domain=<your-infisical-domain>`,
	Short:                 "Used to manage KMIP servers",
	Use:                   "kmip",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
}

var kmipStartCmd = &cobra.Command{
	Example:               `infisical kmip start`,
	Short:                 "Used to start a KMIP server",
	Use:                   "start",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run:                   startKmipServer,
}

const (
	INFISICAL_KMIP_LISTEN_ADDRESS_ENV_NAME   = "INFISICAL_KMIP_LISTEN_ADDRESS"
	INFISICAL_KMIP_SERVER_NAME_ENV_NAME      = "INFISICAL_KMIP_SERVER_NAME"
	INFISICAL_KMIP_CERTIFICATE_TTL_ENV_NAME  = "INFISICAL_KMIP_CERTIFICATE_TTL"
	INFISICAL_KMIP_HOSTNAMES_OR_IPS_ENV_NAME = "INFISICAL_KMIP_HOSTNAMES_OR_IPS"
)

func startKmipServer(cmd *cobra.Command, args []string) {
	listenAddr, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "listen-address", []string{INFISICAL_KMIP_LISTEN_ADDRESS_ENV_NAME}, "localhost:5696")
	if err != nil {
		util.HandleError(err, "Unable to parse listen address")
	}

	serverName, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "server-name", []string{INFISICAL_KMIP_SERVER_NAME_ENV_NAME}, "kmip-server")
	if err != nil {
		util.HandleError(err, "Unable to parse server name")
	}

	certificateTTL, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "certificate-ttl", []string{INFISICAL_KMIP_CERTIFICATE_TTL_ENV_NAME}, "1y")
	if err != nil {
		util.HandleError(err, "Unable to parse certificate TTL")
	}

	hostnamesOrIps, err := util.GetCmdFlagOrEnv(cmd, "hostnames-or-ips", []string{INFISICAL_KMIP_HOSTNAMES_OR_IPS_ENV_NAME})
	if err != nil {
		util.HandleError(err, "Unable to parse hostnames or IPs")
	}

	enrollMethod, _ := cmd.Flags().GetString("enroll-method")
	if enrollMethod == "" {
		enrollMethod = os.Getenv(localkmip.INFISICAL_KMIP_ENROLL_METHOD_KEY)
	}
	if enrollMethod != "" && enrollMethod != localkmip.EnrollMethodToken && enrollMethod != localkmip.EnrollMethodAws {
		util.HandleError(fmt.Errorf("invalid --enroll-method %q: supported values are %q and %q",
			enrollMethod, localkmip.EnrollMethodToken, localkmip.EnrollMethodAws))
	}

	// Resolve the Infisical domain: explicit flag, then the value stored at enrollment, then the logged-in user's domain.
	if flagDomain, _ := cmd.Flags().GetString("domain"); flagDomain != "" {
		config.INFISICAL_URL = util.AppendAPIEndpoint(flagDomain)
	} else if storedDomain, _ := localkmip.LoadStoredDomain(serverName); storedDomain != "" {
		config.INFISICAL_URL = util.AppendAPIEndpoint(storedDomain)
	} else if configFile, cfgErr := util.GetConfigFile(); cfgErr == nil && configFile.LoggedInUserDomain != "" {
		config.INFISICAL_URL = util.AppendAPIEndpoint(configFile.LoggedInUserDomain)
	}

	serverConfig := kmip.ServerConfig{
		Addr:                listenAddr,
		InfisicalBaseAPIURL: config.INFISICAL_URL,
		ServerName:          serverName,
		CertificateTTL:      certificateTTL,
		HostnamesOrIps:      hostnamesOrIps,
	}

	if enrollMethod != "" {
		serverConfig.AccessToken = enrollKmipServer(cmd, enrollMethod, serverName)
	} else {
		serverConfig.IdentityClientId, serverConfig.IdentityClientSecret = resolveKmipIdentityCredentials(cmd)
	}

	kmip.StartServer(serverConfig)
}

// enrollKmipServer obtains a KMIP server access token via token or AWS enrollment,
// persisting the relevant state under the KMIP server's config file.
func enrollKmipServer(cmd *cobra.Command, enrollMethod, serverName string) string {
	httpClient, err := util.GetRestyClientWithCustomHeaders()
	if err != nil {
		util.HandleError(err, "unable to create HTTP client")
	}

	if enrollMethod == localkmip.EnrollMethodAws {
		kmipServerID, _ := cmd.Flags().GetString("kmip-server-id")
		if kmipServerID == "" {
			kmipServerID = os.Getenv(localkmip.INFISICAL_KMIP_SERVER_ID_KEY)
		}
		if kmipServerID == "" {
			stored, _ := localkmip.LoadStoredServerID(serverName)
			kmipServerID = stored
		}
		if kmipServerID == "" {
			util.HandleError(errors.New("--kmip-server-id is required when --enroll-method=aws"))
		}

		log.Info().Msg("Authenticating KMIP server via AWS Auth (STS GetCallerIdentity)...")
		accessToken, err := localkmip.LoginKmipServerWithAws(cmd.Context(), httpClient, kmipServerID)
		if err != nil {
			util.HandleError(err, "AWS Auth login failed")
		}

		if err := localkmip.SaveServerID(serverName, kmipServerID); err != nil {
			util.HandleError(err, "failed to save KMIP server id to config")
		}
		if err := localkmip.SaveDomain(serverName, config.INFISICAL_URL); err != nil {
			util.HandleError(err, "failed to save domain to config")
		}

		log.Info().Msgf("KMIP server authenticated via AWS Auth. State saved to %s", localkmip.GetConfPathDisplay(serverName))
		return accessToken
	}

	// Enrollment token path
	enrollToken, _ := cmd.Flags().GetString("token")

	// Reuse the stored access token when no new token is supplied, or when the supplied token
	// matches the one we already enrolled with. Enrollment tokens are single-use and short-lived,
	// so a restarting server relies on the long-lived access token persisted at enrollment.
	storedEnrollToken, _ := localkmip.LoadStoredEnrollmentToken(serverName)
	if enrollToken == "" || (storedEnrollToken != "" && storedEnrollToken == enrollToken) {
		storedAccessToken, err := localkmip.LoadStoredAccessToken(serverName)
		if err == nil && storedAccessToken != "" {
			log.Info().Msg("Reusing stored KMIP server access token.")
			return storedAccessToken
		}
		if enrollToken == "" {
			util.HandleError(errors.New("--token is required when --enroll-method=token and no access token is stored"))
		}
		// We're here because the supplied token matches the one already enrolled with, but no
		// access token was persisted. Enrollment tokens are single-use, so re-submitting it would
		// fail with an opaque error — surface a clear, actionable message instead of falling through.
		util.HandleError(errors.New("this enrollment token has already been used and no access token is stored locally; generate a new enrollment token from the KMIP server's deploy command and retry"))
	}

	log.Info().Msg("Enrolling KMIP server with enrollment token...")
	enrollResp, err := api.CallKmipServerLogin(httpClient, api.KmipServerLoginRequest{
		Method: localkmip.EnrollMethodToken,
		Token:  enrollToken,
	})
	if err != nil {
		util.HandleError(err, "enrollment failed")
	}

	if err := localkmip.SaveAccessToken(serverName, enrollResp.AccessToken); err != nil {
		util.HandleError(err, "failed to save KMIP server access token")
	}
	if err := localkmip.SaveEnrollmentToken(serverName, enrollToken); err != nil {
		util.HandleError(err, "failed to save enrollment token to config")
	}
	if err := localkmip.SaveDomain(serverName, config.INFISICAL_URL); err != nil {
		util.HandleError(err, "failed to save domain to config")
	}

	log.Info().Msgf("KMIP server enrolled successfully. Access token saved to %s", localkmip.GetConfPathDisplay(serverName))
	return enrollResp.AccessToken
}

// resolveKmipIdentityCredentials parses the legacy machine-identity credentials.
func resolveKmipIdentityCredentials(cmd *cobra.Command) (string, string) {
	identityAuthMethod, err := cmd.Flags().GetString("identity-auth-method")
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}

	authMethodValid, strategy := util.IsAuthMethodValid(identityAuthMethod, false)
	if !authMethodValid {
		util.PrintErrorMessageAndExit(fmt.Sprintf("Invalid login method: %s", identityAuthMethod))
	}

	if strategy != util.AuthStrategy.UNIVERSAL_AUTH {
		util.PrintErrorMessageAndExit(fmt.Sprintf("Unsupported login method: %s", identityAuthMethod))
	}

	identityClientId, err := util.GetCmdFlagOrEnv(cmd, "identity-client-id", []string{util.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME})
	if err != nil {
		util.HandleError(err, "Unable to parse identity client ID")
	}

	identityClientSecret, err := util.GetCmdFlagOrEnv(cmd, "identity-client-secret", []string{util.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET_NAME})
	if err != nil {
		util.HandleError(err, "Unable to parse identity client secret")
	}

	return identityClientId, identityClientSecret
}

var kmipSystemdCmd = &cobra.Command{
	Use:   "systemd",
	Short: "Manage systemd service for Infisical KMIP server",
	Long:  "Manage systemd service for Infisical KMIP server. Use 'systemd install' to install and enable the service.",
	Example: `  sudo infisical kmip systemd install --enroll-method=token --token=<enrollment-token> --server-name=<server-name> --domain=<your-infisical-domain>
  sudo infisical kmip systemd uninstall`,
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
}

var kmipSystemdInstallCmd = &cobra.Command{
	Use:                   "install",
	Short:                 "Install and enable systemd service for the KMIP server (requires sudo)",
	Long:                  "Install and enable systemd service for the KMIP server. Must be run with sudo on Linux.",
	Example:               "sudo infisical kmip systemd install --enroll-method=token --token=<enrollment-token> --server-name=<server-name> --domain=<your-infisical-domain>",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if runtime.GOOS != "linux" {
			util.HandleError(fmt.Errorf("systemd service installation is only supported on Linux"))
		}

		if os.Geteuid() != 0 {
			util.HandleError(fmt.Errorf("systemd service installation requires root/sudo privileges"))
		}

		domain, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "domain", []string{util.INFISICAL_API_URL_ENV_NAME}, "")
		if err != nil {
			util.HandleError(err, "Unable to parse domain")
		}

		// Point the API client at the configured instance before any enrollment call is made.
		if domain != "" {
			config.INFISICAL_URL = util.AppendAPIEndpoint(domain)
		}

		listenAddress, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "listen-address", []string{INFISICAL_KMIP_LISTEN_ADDRESS_ENV_NAME}, "localhost:5696")
		if err != nil {
			util.HandleError(err, "Unable to parse listen address")
		}

		serverName, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "server-name", []string{INFISICAL_KMIP_SERVER_NAME_ENV_NAME}, "kmip-server")
		if err != nil {
			util.HandleError(err, "Unable to parse server name")
		}

		certificateTTL, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "certificate-ttl", []string{INFISICAL_KMIP_CERTIFICATE_TTL_ENV_NAME}, "1y")
		if err != nil {
			util.HandleError(err, "Unable to parse certificate TTL")
		}

		hostnamesOrIps, err := util.GetCmdFlagOrEnv(cmd, "hostnames-or-ips", []string{INFISICAL_KMIP_HOSTNAMES_OR_IPS_ENV_NAME})
		if err != nil {
			util.HandleError(err, "Unable to parse hostnames or IPs")
		}

		enrollMethod, _ := cmd.Flags().GetString("enroll-method")
		if enrollMethod == "" {
			enrollMethod = os.Getenv(localkmip.INFISICAL_KMIP_ENROLL_METHOD_KEY)
		}
		if enrollMethod != "" && enrollMethod != localkmip.EnrollMethodToken && enrollMethod != localkmip.EnrollMethodAws {
			util.HandleError(fmt.Errorf("invalid --enroll-method %q: supported values are %q and %q",
				enrollMethod, localkmip.EnrollMethodToken, localkmip.EnrollMethodAws))
		}

		switch enrollMethod {
		case localkmip.EnrollMethodToken:
			enrollToken, _ := cmd.Flags().GetString("token")
			if enrollToken == "" {
				util.HandleError(errors.New("--token is required when --enroll-method=token"))
			}

			httpClient, clientErr := util.GetRestyClientWithCustomHeaders()
			if clientErr != nil {
				util.HandleError(clientErr, "unable to create HTTP client")
			}

			log.Info().Msg("Enrolling KMIP server with enrollment token...")
			enrollResp, enrollErr := api.CallKmipServerLogin(httpClient, api.KmipServerLoginRequest{
				Method: localkmip.EnrollMethodToken,
				Token:  enrollToken,
			})
			if enrollErr != nil {
				util.HandleError(enrollErr, "enrollment failed")
			}

			if err := localkmip.InstallEnrolledKmipSystemdService(enrollResp.AccessToken, domain, listenAddress, serverName, certificateTTL, hostnamesOrIps); err != nil {
				util.HandleError(err, "Failed to install systemd service")
			}
		case localkmip.EnrollMethodAws:
			kmipServerID, _ := cmd.Flags().GetString("kmip-server-id")
			if kmipServerID == "" {
				kmipServerID = os.Getenv(localkmip.INFISICAL_KMIP_SERVER_ID_KEY)
			}
			if kmipServerID == "" {
				util.HandleError(errors.New("--kmip-server-id is required when --enroll-method=aws"))
			}

			if err := localkmip.InstallAwsAuthKmipSystemdService(kmipServerID, domain, listenAddress, serverName, certificateTTL, hostnamesOrIps); err != nil {
				util.HandleError(err, "Failed to install systemd service")
			}
		default:
			identityClientId, idErr := util.GetCmdFlagOrEnv(cmd, "identity-client-id", []string{util.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME})
			if idErr != nil {
				util.HandleError(idErr, "Unable to parse identity client ID")
			}

			identityClientSecret, secretErr := util.GetCmdFlagOrEnv(cmd, "identity-client-secret", []string{util.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET_NAME})
			if secretErr != nil {
				util.HandleError(secretErr, "Unable to parse identity client secret")
			}

			if err := localkmip.InstallKmipSystemdService(identityClientId, identityClientSecret, domain, listenAddress, serverName, certificateTTL, hostnamesOrIps); err != nil {
				util.HandleError(err, "Failed to install systemd service")
			}
		}

		enableCmd := exec.Command("systemctl", "enable", "infisical-kmip")
		if err := enableCmd.Run(); err != nil {
			util.HandleError(err, "Failed to enable systemd service")
		}

		log.Info().Msg("Successfully installed and enabled infisical-kmip service")
		log.Info().Msg("To start the service, run: sudo systemctl start infisical-kmip")
	},
}

var kmipSystemdUninstallCmd = &cobra.Command{
	Use:                   "uninstall",
	Short:                 "Uninstall and remove systemd service for the KMIP server (requires sudo)",
	Long:                  "Uninstall and remove systemd service for the KMIP server. Must be run with sudo on Linux.",
	Example:               "sudo infisical kmip systemd uninstall",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if runtime.GOOS != "linux" {
			util.HandleError(fmt.Errorf("systemd service installation is only supported on Linux"))
		}

		if os.Geteuid() != 0 {
			util.HandleError(fmt.Errorf("systemd service uninstallation requires root/sudo privileges"))
		}

		if err := localkmip.UninstallKmipSystemdService(); err != nil {
			util.HandleError(err, "Failed to uninstall systemd service")
		}
	},
}

func init() {
	// KMIP start command flags
	// Defaults are applied in startKmipServer so the corresponding env vars (set by the systemd
	// EnvironmentFile) take precedence; a non-empty flag default here would always shadow them.
	kmipStartCmd.Flags().String("listen-address", "", "The address for the KMIP server to listen on. Defaults to localhost:5696")
	kmipStartCmd.Flags().String("enroll-method", "", "Enrollment method for the KMIP server: 'token' or 'aws'. When set, machine-identity flags are ignored.")
	kmipStartCmd.Flags().String("token", "", "Enrollment token (when --enroll-method=token)")
	kmipStartCmd.Flags().String("kmip-server-id", "", "KMIP server ID (when --enroll-method=aws)")
	kmipStartCmd.Flags().String("domain", "", "Domain of your Infisical instance")
	kmipStartCmd.Flags().String("identity-auth-method", string(util.AuthStrategy.UNIVERSAL_AUTH), "The auth method to use for authenticating the machine identity. Defaults to universal-auth.")
	kmipStartCmd.Flags().String("identity-client-id", "", "Universal auth client ID of machine identity")
	kmipStartCmd.Flags().String("identity-client-secret", "", "Universal auth client secret of machine identity")
	kmipStartCmd.Flags().String("server-name", "", "The name of the KMIP server. Defaults to kmip-server")
	kmipStartCmd.Flags().String("certificate-ttl", "", "The TTL duration for the server certificate. Defaults to 1y")
	kmipStartCmd.Flags().String("hostnames-or-ips", "", "Comma-separated list of hostnames or IPs")

	// KMIP systemd install command flags
	kmipSystemdInstallCmd.Flags().String("enroll-method", "", "Enrollment method for the KMIP server: 'token' or 'aws'. When set, machine-identity flags are ignored.")
	kmipSystemdInstallCmd.Flags().String("token", "", "Enrollment token (when --enroll-method=token)")
	kmipSystemdInstallCmd.Flags().String("kmip-server-id", "", "KMIP server ID (when --enroll-method=aws)")
	kmipSystemdInstallCmd.Flags().String("identity-client-id", "", "Universal auth client ID of machine identity")
	kmipSystemdInstallCmd.Flags().String("identity-client-secret", "", "Universal auth client secret of machine identity")
	kmipSystemdInstallCmd.Flags().String("domain", "", "Domain of your self-hosted Infisical instance")
	kmipSystemdInstallCmd.Flags().String("listen-address", "", "The address for the KMIP server to listen on")
	kmipSystemdInstallCmd.Flags().String("server-name", "", "The name of the KMIP server")
	kmipSystemdInstallCmd.Flags().String("certificate-ttl", "", "The TTL duration for the server certificate")
	kmipSystemdInstallCmd.Flags().String("hostnames-or-ips", "", "Comma-separated list of hostnames or IPs")

	// Wire up command hierarchy
	kmipSystemdCmd.AddCommand(kmipSystemdInstallCmd)
	kmipSystemdCmd.AddCommand(kmipSystemdUninstallCmd)

	kmipCmd.AddCommand(kmipStartCmd)
	kmipCmd.AddCommand(kmipSystemdCmd)
	RootCmd.AddCommand(kmipCmd)
}
