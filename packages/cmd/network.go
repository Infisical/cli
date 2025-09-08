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

	gatewayv2 "github.com/Infisical/infisical-merge/packages/gateway-v2"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var networkCmd = &cobra.Command{
	Use:   "network",
	Short: "Network-related commands",
	Long:  "Network-related commands for Infisical",
}

var networkGatewayCmd = &cobra.Command{
	Use:                   "gateway",
	Short:                 "Run the Infisical gateway component",
	Long:                  "Run the Infisical gateway component. Use 'network gateway install' to set up the systemd service.",
	Example:               "infisical network gateway --relay=<relay-name> --name=<name> --token=<token>",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {

		relayName, err := util.GetCmdFlagOrEnv(cmd, "relay", []string{gatewayv2.RELAY_NAME_ENV_NAME})
		if err != nil {
			util.HandleError(err, fmt.Sprintf("unable to get relay flag or %s env", gatewayv2.RELAY_NAME_ENV_NAME))
		}

		gatewayName, err := util.GetCmdFlagOrEnv(cmd, "name", []string{gatewayv2.GATEWAY_NAME_ENV_NAME})
		if err != nil {
			util.HandleError(err, fmt.Sprintf("unable to get name flag or %s env", gatewayv2.GATEWAY_NAME_ENV_NAME))
		}

		gatewayInstance, err := gatewayv2.NewGateway(&gatewayv2.GatewayConfig{
			Name:           gatewayName,
			RelayName:      relayName,
			ReconnectDelay: 10 * time.Second,
		})

		if err != nil {
			util.HandleError(err, "unable to create gateway instance")
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

		gatewayInstance.SetToken(accessToken.Load().(string))

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

		ctx, cancelCmd := context.WithCancel(cmd.Context())
		defer cancelCmd()

		go func() {
			<-sigCh
			log.Info().Msg("Received shutdown signal, shutting down gateway...")
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
						gatewayInstance.SetToken(newToken)
					}

				case <-ctx.Done():
					return
				}
			}
		}()

		err = gatewayInstance.Start(ctx)
		if err != nil {
			util.HandleError(err, "unable to start gateway instance")
		}

	},
}

var networkGatewayInstallCmd = &cobra.Command{
	Use:                   "install",
	Short:                 "Install and enable systemd service for the gateway (requires sudo)",
	Long:                  "Install and enable systemd service for the gateway. Must be run with sudo on Linux.",
	Example:               "sudo infisical network gateway install --token=<token> --domain=<domain> --name=<name> --relay=<relay-name>",
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

		gatewayName, err := cmd.Flags().GetString("name")
		if err != nil {
			util.HandleError(err, "Unable to parse name flag")
		}
		if gatewayName == "" {
			util.HandleError(errors.New("Gateway name is required"))
		}

		relayName, err := cmd.Flags().GetString("relay")
		if err != nil {
			util.HandleError(err, "Unable to parse relay flag")
		}
		if relayName == "" {
			util.HandleError(errors.New("Relay is required"))
		}

		err = gatewayv2.InstallGatewaySystemdService(token.Token, domain, gatewayName, relayName)
		if err != nil {
			util.HandleError(err, "Unable to install systemd service")
		}
	},
}

var networkGatewayUninstallCmd = &cobra.Command{
	Use:                   "uninstall",
	Short:                 "Uninstall and remove systemd service for the gateway (requires sudo)",
	Long:                  "Uninstall and remove systemd service for the gateway. Must be run with sudo on Linux.",
	Example:               "sudo infisical network gateway uninstall",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if runtime.GOOS != "linux" {
			util.HandleError(fmt.Errorf("systemd service installation is only supported on Linux"))
		}

		if os.Geteuid() != 0 {
			util.HandleError(fmt.Errorf("systemd service installation requires root/sudo privileges"))
		}

		if err := gatewayv2.UninstallGatewaySystemdService(); err != nil {
			util.HandleError(err, "Failed to uninstall systemd service")
		}
	},
}

func init() {
	networkGatewayCmd.Flags().String("relay", "", "The name of the relay to connect to")
	networkGatewayCmd.Flags().String("name", "", "The name of the gateway")
	networkGatewayCmd.Flags().String("token", "", "connect with Infisical using machine identity access token. if not provided, you must set the auth-method flag")
	networkGatewayCmd.Flags().String("auth-method", "", "login method [universal-auth, kubernetes, azure, gcp-id-token, gcp-iam, aws-iam, oidc-auth]. if not provided, you must set the token flag")
	networkGatewayCmd.Flags().String("client-id", "", "client id for universal auth")
	networkGatewayCmd.Flags().String("client-secret", "", "client secret for universal auth")
	networkGatewayCmd.Flags().String("machine-identity-id", "", "machine identity id for kubernetes, azure, gcp-id-token, gcp-iam, and aws-iam auth methods")
	networkGatewayCmd.Flags().String("service-account-token-path", "", "service account token path for kubernetes auth")
	networkGatewayCmd.Flags().String("service-account-key-file-path", "", "service account key file path for GCP IAM auth")
	networkGatewayCmd.Flags().String("jwt", "", "JWT for jwt-based auth methods [oidc-auth, jwt-auth]")

	networkGatewayInstallCmd.Flags().String("token", "", "Connect with Infisical using machine identity access token")
	networkGatewayInstallCmd.Flags().String("domain", "", "Domain of your self-hosted Infisical instance")
	networkGatewayInstallCmd.Flags().String("name", "", "The name of the gateway")
	networkGatewayInstallCmd.Flags().String("relay", "", "The name of the relay")

	networkGatewayCmd.AddCommand(networkGatewayInstallCmd)
	networkGatewayCmd.AddCommand(networkGatewayUninstallCmd)

	networkCmd.AddCommand(networkGatewayCmd)

	rootCmd.AddCommand(networkCmd)
}
