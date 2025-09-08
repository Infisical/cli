package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

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
	Example:               "infisical relay start --type=instance --ip=<ip> --name=<name> --token=<token>",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {

		relayName, err := cmd.Flags().GetString("name")
		if err != nil || relayName == "" {
			util.HandleError(err, "unable to get name flag")
		}

		ip, err := cmd.Flags().GetString("ip")
		if err != nil || ip == "" {
			util.HandleError(err, "unable to get ip flag")
		}

		instanceType, err := cmd.Flags().GetString("type")
		if err != nil {
			util.HandleError(err, "unable to get type flag")
		}

		relayInstance, err := relay.NewRelay(&relay.RelayConfig{
			RelayName: relayName,
			SSHPort:   "2222",
			TLSPort:   "8443",
			StaticIP:  ip,
			Type:      instanceType,
		})

		if err != nil {
			util.HandleError(err, "unable to create relay instance")
		}

		if instanceType == "instance" {
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

func init() {
	relayStartCmd.Flags().String("type", "org", "The type of relay to run. Must be either 'instance' or 'org'")
	relayStartCmd.Flags().String("ip", "", "The IP address of the relay")
	relayStartCmd.Flags().String("name", "", "The name of the relay")
	relayStartCmd.Flags().String("token", "", "connect with Infisical using machine identity access token. if not provided, you must set the auth-method flag")
	relayStartCmd.Flags().String("auth-method", "", "login method [universal-auth, kubernetes, azure, gcp-id-token, gcp-iam, aws-iam, oidc-auth]. if not provided, you must set the token flag")
	relayStartCmd.Flags().String("client-id", "", "client id for universal auth")
	relayStartCmd.Flags().String("client-secret", "", "client secret for universal auth")
	relayStartCmd.Flags().String("machine-identity-id", "", "machine identity id for kubernetes, azure, gcp-id-token, gcp-iam, and aws-iam auth methods")
	relayStartCmd.Flags().String("service-account-token-path", "", "service account token path for kubernetes auth")
	relayStartCmd.Flags().String("service-account-key-file-path", "", "service account key file path for GCP IAM auth")
	relayStartCmd.Flags().String("jwt", "", "JWT for jwt-based auth methods [oidc-auth, jwt-auth]")

	relayCmd.AddCommand(relayStartCmd)

	rootCmd.AddCommand(relayCmd)
}
