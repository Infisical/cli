package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	gatewayv2 "github.com/Infisical/infisical-merge/packages/gateway-v2"
	"github.com/Infisical/infisical-merge/packages/relay"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var relayCmd = &cobra.Command{
	Use:   "relay",
	Short: "Relay-related commands",
	Long:  "Relay-related commands for Infisical",
}

var relayStartCmd = &cobra.Command{
	Use:                   "start",
	Short:                 "Start the Infisical relay component",
	Long:                  "Start the Infisical relay component",
	Example:               "infisical relay start --type=instance --host=<host> --name=<name> --token=<token>",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {

		relayName, err := util.GetCmdFlagOrEnv(cmd, "name", []string{gatewayv2.RELAY_NAME_ENV_NAME})
		if err != nil || relayName == "" {
			util.HandleError(err, fmt.Sprintf("unable to get name flag or %s env", gatewayv2.RELAY_NAME_ENV_NAME))
		}

		enrollMethod, _ := cmd.Flags().GetString("enroll-method")
		if enrollMethod == "" {
			enrollMethod = os.Getenv("INFISICAL_RELAY_ENROLL_METHOD")
		}

		host, _ := util.GetCmdFlagOrEnv(cmd, "host", []string{gatewayv2.RELAY_HOST_ENV_NAME})
		if host == "" && enrollMethod == "" {
			util.HandleError(fmt.Errorf("please provide host flag"), fmt.Sprintf("unable to get host flag or %s env", gatewayv2.RELAY_HOST_ENV_NAME))
		}

		instanceType, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "type", []string{gatewayv2.RELAY_TYPE_ENV_NAME}, "org")
		if err != nil {
			util.HandleError(err, fmt.Sprintf("unable to get type flag or %s env", gatewayv2.RELAY_TYPE_ENV_NAME))
		}

		var enrolledAccessToken string

		// --- AWS Auth path ---
		if enrollMethod == relay.EnrollMethodAws {
			relayID, _ := cmd.Flags().GetString("relay-id")
			if relayID == "" {
				relayID = os.Getenv(relay.INFISICAL_RELAY_ID_KEY)
			}
			if relayID == "" {
				stored, _ := relay.LoadStoredRelayID(relayName)
				relayID = stored
			}
			if relayID == "" {
				util.HandleError(errors.New("--relay-id is required when --enroll-method=aws"))
			}

			domain, _ := cmd.Flags().GetString("domain")
			if domain != "" {
				config.INFISICAL_URL = util.AppendAPIEndpoint(domain)
			} else if storedDomain, _ := relay.LoadStoredDomain(relayName); storedDomain != "" {
				config.INFISICAL_URL = util.AppendAPIEndpoint(storedDomain)
			}

			httpClient, err := util.GetRestyClientWithCustomHeaders()
			if err != nil {
				util.HandleError(err, "unable to create HTTP client")
			}

			log.Info().Msg("Authenticating relay via AWS Auth (STS GetCallerIdentity)...")
			accessTokenStr, err := relay.LoginRelayWithAws(cmd.Context(), httpClient, relayID)
			if err != nil {
				util.HandleError(err, "AWS Auth login failed")
			}

			enrolledAccessToken = accessTokenStr

			if err := relay.SaveRelayID(relayName, relayID); err != nil {
				util.HandleError(err, "failed to save relay id to config")
			}

			effectiveDomain := domain
			if effectiveDomain == "" {
				effectiveDomain = config.INFISICAL_URL
			}
			if effectiveDomain != "" {
				if err := relay.SaveDomain(relayName, effectiveDomain); err != nil {
					util.HandleError(err, "failed to save domain to config")
				}
			}

			log.Info().Msgf("Relay authenticated via AWS Auth. State saved to %s", relay.GetConfPathDisplay(relayName))
			log.Info().Msg("Starting relay...")
		}

		// --- Enrollment token path ---
		if enrollMethod == relay.EnrollMethodToken {
			enrollToken, _ := cmd.Flags().GetString("token")
			if enrollToken == "" {
				util.HandleError(errors.New("--token is required when --enroll-method=token"))
			}

			storedEnrollToken, _ := relay.LoadStoredEnrollmentToken(relayName)
			alreadyEnrolled := storedEnrollToken != "" && storedEnrollToken == enrollToken

			if alreadyEnrolled {
				log.Info().Msg("Enrollment token matches stored token. Skipping enrollment.")
			} else {
				domain, _ := cmd.Flags().GetString("domain")
				if domain != "" {
					config.INFISICAL_URL = util.AppendAPIEndpoint(domain)
				}

				httpClient, err := util.GetRestyClientWithCustomHeaders()
				if err != nil {
					util.HandleError(err, "unable to create HTTP client")
				}

				log.Info().Msg("Enrolling relay with enrollment token...")
				enrollResp, err := api.CallRelayLogin(httpClient, api.RelayLoginRequest{
					Method: "token",
					Token:  enrollToken,
				})
				if err != nil {
					util.HandleError(err, "enrollment failed")
				}

				enrolledAccessToken = enrollResp.AccessToken
				if err := relay.SaveAccessToken(relayName, enrollResp.AccessToken); err != nil {
					util.HandleError(err, "failed to save relay access token")
				}
				if err := relay.SaveEnrollmentToken(relayName, enrollToken); err != nil {
					util.HandleError(err, "failed to save enrollment token to config")
				}

				effectiveDomain := domain
				if effectiveDomain == "" {
					effectiveDomain = config.INFISICAL_URL
				}
				if effectiveDomain != "" {
					if err := relay.SaveDomain(relayName, effectiveDomain); err != nil {
						util.HandleError(err, "failed to save domain to config")
					}
				}

				log.Info().Msgf("Relay enrolled successfully. Access token saved to %s", relay.GetConfPathDisplay(relayName))
			}

			log.Info().Msg("Starting relay...")
		}

		// --- Domain resolution for resource auth / stored token ---
		isResourceAuth := enrollMethod == relay.EnrollMethodToken || enrollMethod == relay.EnrollMethodAws
		if isResourceAuth {
			if flagDomain, _ := cmd.Flags().GetString("domain"); flagDomain != "" {
				config.INFISICAL_URL = util.AppendAPIEndpoint(flagDomain)
			} else if storedDomain, _ := relay.LoadStoredDomain(relayName); storedDomain != "" {
				config.INFISICAL_URL = util.AppendAPIEndpoint(storedDomain)
			}
		}

		relayInstance, err := relay.NewRelay(&relay.RelayConfig{
			RelayName:    relayName,
			SSHPort:      "2222",
			TLSPort:      "8443",
			Host:         host,
			Type:         instanceType,
			EnrollMethod: enrollMethod,
		})

		if err != nil {
			util.HandleError(err, "unable to create relay instance")
		}

		if isResourceAuth {
			// Use the freshly enrolled token, or load the stored one.
			if enrolledAccessToken != "" {
				relayInstance.SetToken(enrolledAccessToken)
			} else {
				storedToken, err := relay.LoadStoredAccessToken(relayName)
				if err != nil || storedToken == "" {
					util.HandleError(errors.New("no stored access token found — re-run with enrollment token"))
				}
				relayInstance.SetToken(storedToken)
			}
		} else if instanceType == "instance" {
			relayAuthSecret := os.Getenv(gatewayv2.RELAY_AUTH_SECRET_ENV_NAME)
			if relayAuthSecret == "" {
				util.HandleError(fmt.Errorf("%s is not set", gatewayv2.RELAY_AUTH_SECRET_ENV_NAME), "unable to get relay auth secret")
			}

			relayInstance.SetToken(relayAuthSecret)
		} else {
			infisicalClient, cancelSdk, err := getInfisicalSdkInstance(cmd)
			if err != nil {
				util.HandleError(err, "unable to get infisical client")
			}
			defer cancelSdk()

			var accessToken atomic.Value
			accessToken.Store(infisicalClient.Auth().GetAccessToken())

			if accessToken.Load().(string) == "" {
				util.HandleError(errors.New("no access token found"))
			}

			relayInstance.SetToken(accessToken.Load().(string))

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

			ctx, cancelCmd := context.WithCancel(cmd.Context())
			defer cancelCmd()

			go func() {
				<-sigCh
				log.Info().Msg("Received shutdown signal, shutting down relay...")
				cancelCmd()
				cancelSdk()

				select {
				case <-sigCh:
					log.Warn().Msg("Second signal received, force exit triggered")
					os.Exit(1)
				case <-time.After(10 * time.Second):
					log.Info().Msg("Graceful shutdown completed")
					os.Exit(0)
				}
			}()

			go func() {
				tokenRefreshTicker := time.NewTicker(10 * time.Second)
				defer tokenRefreshTicker.Stop()

				for {
					select {
					case <-tokenRefreshTicker.C:
						if ctx.Err() != nil {
							return
						}

						newToken := infisicalClient.Auth().GetAccessToken()
						if newToken != "" && newToken != accessToken.Load().(string) {
							accessToken.Store(newToken)
							relayInstance.SetToken(newToken)
						}

					case <-ctx.Done():
						return
					}
				}
			}()
		}

		err = relayInstance.Start(cmd.Context())
		if err != nil {
			util.HandleError(err, "unable to start relay instance")
		}
	},
}

var relaySystemdCmd = &cobra.Command{
	Use:   "systemd",
	Short: "Manage systemd service for Infisical relay",
	Long:  "Manage systemd service for Infisical relay. Use 'systemd install' to install and enable the service.",
	Example: `sudo infisical relay systemd install --token=<token> --name=<name> --host=<host>
  sudo infisical relay systemd install --type=instance --name=<name> --host=<host> --relay-auth-secret=<secret>
  sudo infisical relay systemd uninstall`,
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
}

var relaySystemdInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install and enable systemd service for the relay (requires sudo)",
	Long:  "Install and enable systemd service for the relay. Must be run with sudo on Linux.",
	Example: `sudo infisical relay systemd install --token=<token> --name=<name> --host=<host>
  sudo infisical relay systemd install --type=instance --name=<name> --host=<host> --relay-auth-secret=<secret>`,
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if runtime.GOOS != "linux" {
			util.HandleError(fmt.Errorf("systemd service installation is only supported on Linux"))
		}

		if os.Geteuid() != 0 {
			util.HandleError(fmt.Errorf("systemd service installation requires root/sudo privileges"))
		}

		token, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "token", []string{gatewayv2.INFISICAL_TOKEN_ENV_NAME}, "")
		if err != nil {
			util.HandleError(err, "Unable to parse token flag or env")
		}

		domain, err := cmd.Flags().GetString("domain")
		if err != nil {
			util.HandleError(err, "Unable to parse domain flag")
		}

		name, err := cmd.Flags().GetString("name")
		if err != nil {
			util.HandleError(err, "Unable to parse name flag")
		}
		if name == "" {
			util.HandleError(fmt.Errorf("name flag is required"), "name is required")
		}

		host, err := cmd.Flags().GetString("host")
		if err != nil {
			util.HandleError(err, "Unable to parse host flag")
		}
		if host == "" {
			util.HandleError(fmt.Errorf("host flag is required"), "host is required")
		}

		instanceType, err := cmd.Flags().GetString("type")
		if err != nil {
			util.HandleError(err, "Unable to parse type flag")
		}
		if instanceType == "" {
			util.HandleError(fmt.Errorf("type flag is required"), "type is required")
		}

		relayAuthSecret, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "relay-auth-secret", []string{gatewayv2.RELAY_AUTH_SECRET_ENV_NAME}, "")
		if err != nil {
			util.HandleError(err, "Unable to parse relay-auth-secret flag")
		}

		serviceLogFile, err := cmd.Flags().GetString("log-file")
		if err != nil {
			util.HandleError(err, "Unable to parse log-file flag")
		}

		if instanceType == "instance" && relayAuthSecret == "" {
			util.HandleError(fmt.Errorf("for type 'instance', --relay-auth-secret flag or %s env must be set", gatewayv2.RELAY_AUTH_SECRET_ENV_NAME))
		}

		if instanceType != "instance" && token == "" {
			util.HandleError(fmt.Errorf("for type '%s', --token flag or %s env must be set", instanceType, gatewayv2.INFISICAL_TOKEN_ENV_NAME))
		}

		if err := relay.InstallRelaySystemdService(token, domain, name, host, instanceType, relayAuthSecret, serviceLogFile); err != nil {
			util.HandleError(err, "Failed to install relay systemd service")
		}

		enableCmd := exec.Command("systemctl", "enable", "infisical-relay")
		if err := enableCmd.Run(); err != nil {
			util.HandleError(err, "Failed to enable relay systemd service")
		}

		log.Info().Msg("Successfully installed and enabled infisical-relay service")
		log.Info().Msg("To start the service, run: sudo systemctl start infisical-relay")
	},
}

var relaySystemdUninstallCmd = &cobra.Command{
	Use:                   "uninstall",
	Short:                 "Uninstall and remove systemd service for the relay (requires sudo)",
	Long:                  "Uninstall and remove systemd service for the relay. Must be run with sudo on Linux.",
	Example:               "sudo infisical relay systemd uninstall",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if runtime.GOOS != "linux" {
			util.HandleError(fmt.Errorf("systemd service uninstallation is only supported on Linux"))
		}

		if os.Geteuid() != 0 {
			util.HandleError(fmt.Errorf("systemd service uninstallation requires root/sudo privileges"))
		}

		if err := relay.UninstallRelaySystemdService(); err != nil {
			util.HandleError(err, "Failed to uninstall relay systemd service")
		}
	},
}

func init() {
	relayStartCmd.Flags().String("type", "", "The type of relay to run. Defaults to 'org'")
	relayStartCmd.Flags().String("host", "", "The IP or hostname for the relay")
	relayStartCmd.Flags().String("name", "", "The name of the relay")
	relayStartCmd.Flags().String("token", "", "connect with Infisical using machine identity access token, or a one-time enrollment token when --enroll-method=token")
	relayStartCmd.Flags().String("auth-method", "", "login method [universal-auth, kubernetes, azure, gcp-id-token, gcp-iam, aws-iam, oidc-auth]. if not provided, you must set the token flag")
	relayStartCmd.Flags().String("enroll-method", "", "relay auth method [token, aws]. when set to 'token', uses --token as a one-time enrollment token. when set to 'aws', authenticates via signed STS GetCallerIdentity using --relay-id")
	relayStartCmd.Flags().String("relay-id", "", "relay id (required when --enroll-method=aws)")
	relayStartCmd.Flags().String("domain", "", "domain of your self-hosted Infisical instance (used with --enroll-method)")
	relayStartCmd.Flags().String("client-id", "", "client id for universal auth")
	relayStartCmd.Flags().String("client-secret", "", "client secret for universal auth")
	relayStartCmd.Flags().String("machine-identity-id", "", "machine identity id for kubernetes, azure, gcp-id-token, gcp-iam, and aws-iam auth methods")
	relayStartCmd.Flags().String("service-account-token-path", "", "service account token path for kubernetes auth")
	relayStartCmd.Flags().String("service-account-key-file-path", "", "service account key file path for GCP IAM auth")
	relayStartCmd.Flags().String("jwt", "", "JWT for jwt-based auth methods [oidc-auth, jwt-auth]")

	// systemd install command flags
	relaySystemdInstallCmd.Flags().String("token", "", "Connect with Infisical using machine identity access token (org type)")
	relaySystemdInstallCmd.Flags().String("log-file", "", "The file to write the service logs to. Example: /var/log/infisical/relay.log. If not provided, logs will not be written to a file.")
	relaySystemdInstallCmd.Flags().String("domain", "", "Domain of your self-hosted Infisical instance")
	relaySystemdInstallCmd.Flags().String("name", "", "The name of the relay")
	relaySystemdInstallCmd.Flags().String("host", "", "The IP or hostname for the relay")
	relaySystemdInstallCmd.Flags().String("type", "org", "The type of relay to run. Defaults to 'org'")
	relaySystemdInstallCmd.Flags().String("relay-auth-secret", "", "Relay auth secret (required for type=instance if env not set)")

	relaySystemdCmd.AddCommand(relaySystemdInstallCmd)
	relaySystemdCmd.AddCommand(relaySystemdUninstallCmd)

	relayCmd.AddCommand(relayStartCmd)
	relayCmd.AddCommand(relaySystemdCmd)

	RootCmd.AddCommand(relayCmd)
}
