package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/connector"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var connectorCmd = &cobra.Command{
	Use:   "connector",
	Short: "Connector-related commands",
	Long:  "Connector-related commands for Infisical",
}

var connectorStartCmd = &cobra.Command{
	Use:                   "start",
	Short:                 "Start the Infisical connector component",
	Long:                  "Start the Infisical connector component. Use 'connector install' to set up the systemd service.",
	Example:               "infisical connector start --relay=us-west-1 --name=my-connector --token=<token>",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {

		relayName, err := util.GetCmdFlagOrEnv(cmd, "relay", []string{connector.RELAY_NAME_ENV_NAME})
		if err != nil {
			util.HandleError(err, fmt.Sprintf("unable to get relay flag or %s env", connector.RELAY_NAME_ENV_NAME))
		}

		connectorName, err := util.GetCmdFlagOrEnv(cmd, "name", []string{connector.CONNECTOR_NAME_ENV_NAME})
		if err != nil {
			util.HandleError(err, fmt.Sprintf("unable to get name flag or %s env", connector.CONNECTOR_NAME_ENV_NAME))
		}

		connectorInstance, err := connector.NewConnector(&connector.ConnectorConfig{
			Name:           connectorName,
			RelayName:      relayName,
			ReconnectDelay: 10 * time.Second,
		})

		if err != nil {
			util.HandleError(err, "unable to create connector instance")
		}

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

		connectorInstance.SetToken(accessToken.Load().(string))

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

		ctx, cancelCmd := context.WithCancel(cmd.Context())
		defer cancelCmd()

		go func() {
			<-sigCh
			log.Info().Msg("Received shutdown signal, shutting down connector...")
			cancelCmd()
			cancelSdk()

			// Give graceful shutdown 10 seconds, then force exit on second signal
			select {
			case <-sigCh:
				log.Warn().Msg("Second signal received, force exit triggered")
				os.Exit(1)
			case <-time.After(10 * time.Second):
				log.Info().Msg("Graceful shutdown completed")
				os.Exit(0)
			}
		}()

		// Token refresh goroutine - runs every 10 seconds
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
						connectorInstance.SetToken(newToken)
					}

				case <-ctx.Done():
					return
				}
			}
		}()

		err = connectorInstance.Start(ctx)
		if err != nil {
			util.HandleError(err, "unable to start connector instance")
		}

	},
}

var connectorInstallCmd = &cobra.Command{
	Use:                   "install",
	Short:                 "Install and enable systemd service for the connector (requires sudo)",
	Long:                  "Install and enable systemd service for the connector. Must be run with sudo on Linux.",
	Example:               "sudo infisical connector install --token=<token> --domain=<domain> --name=<name> --relay=<relay-name>",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if runtime.GOOS != "linux" {
			util.HandleError(fmt.Errorf("systemd service installation is only supported on Linux"))
		}

		if os.Geteuid() != 0 {
			util.HandleError(fmt.Errorf("systemd service installation requires root/sudo privileges"))
		}

		token, err := util.GetInfisicalToken(cmd)
		if err != nil {
			util.HandleError(err, "Unable to parse flag")
		}

		if token == nil {
			util.HandleError(errors.New("Token not found"))
		}

		domain, err := cmd.Flags().GetString("domain")
		if err != nil {
			util.HandleError(err, "Unable to parse domain flag")
		}

		connectorName, err := cmd.Flags().GetString("name")
		if err != nil {
			util.HandleError(err, "Unable to parse name flag")
		}
		if connectorName == "" {
			util.HandleError(errors.New("Connector name is required"))
		}

		relayName, err := cmd.Flags().GetString("relay")
		if err != nil {
			util.HandleError(err, "Unable to parse relay flag")
		}
		if relayName == "" {
			util.HandleError(errors.New("Relay name is required"))
		}

		err = connector.InstallConnectorSystemdService(token.Token, domain, connectorName, relayName)
		if err != nil {
			util.HandleError(err, "Unable to install systemd service")
		}
	},
}

var connectorUninstallCmd = &cobra.Command{
	Use:                   "uninstall",
	Short:                 "Uninstall and remove systemd service for the connector (requires sudo)",
	Long:                  "Uninstall and remove systemd service for the connector. Must be run with sudo on Linux.",
	Example:               "sudo infisical connector uninstall",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if runtime.GOOS != "linux" {
			util.HandleError(fmt.Errorf("systemd service installation is only supported on Linux"))
		}

		if os.Geteuid() != 0 {
			util.HandleError(fmt.Errorf("systemd service installation requires root/sudo privileges"))
		}

		if err := connector.UninstallConnectorSystemdService(); err != nil {
			util.HandleError(err, "Failed to uninstall systemd service")
		}
	},
}

func init() {
	connectorStartCmd.Flags().String("relay", "", "The name of the relay to connect to")
	connectorStartCmd.Flags().String("name", "", "The name of the connector")
	connectorStartCmd.Flags().String("token", "", "connect with Infisical using machine identity access token. if not provided, you must set the auth-method flag")
	connectorStartCmd.Flags().String("auth-method", "", "login method [universal-auth, kubernetes, azure, gcp-id-token, gcp-iam, aws-iam, oidc-auth]. if not provided, you must set the token flag")
	connectorStartCmd.Flags().String("client-id", "", "client id for universal auth")
	connectorStartCmd.Flags().String("client-secret", "", "client secret for universal auth")
	connectorStartCmd.Flags().String("machine-identity-id", "", "machine identity id for kubernetes, azure, gcp-id-token, gcp-iam, and aws-iam auth methods")
	connectorStartCmd.Flags().String("service-account-token-path", "", "service account token path for kubernetes auth")
	connectorStartCmd.Flags().String("service-account-key-file-path", "", "service account key file path for GCP IAM auth")
	connectorStartCmd.Flags().String("jwt", "", "JWT for jwt-based auth methods [oidc-auth, jwt-auth]")

	connectorInstallCmd.Flags().String("token", "", "Connect with Infisical using machine identity access token")
	connectorInstallCmd.Flags().String("domain", "", "Domain of your self-hosted Infisical instance")
	connectorInstallCmd.Flags().String("name", "", "The name of the connector")
	connectorInstallCmd.Flags().String("relay", "", "The name of the relay")

	connectorCmd.AddCommand(connectorStartCmd)
	connectorCmd.AddCommand(connectorInstallCmd)
	connectorCmd.AddCommand(connectorUninstallCmd)

	rootCmd.AddCommand(connectorCmd)
}
