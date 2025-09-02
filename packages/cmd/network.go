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
	"github.com/Infisical/infisical-merge/packages/proxy"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var networkCmd = &cobra.Command{
	Use:   "network",
	Short: "Network-related commands",
	Long:  "Network-related commands for Infisical",
}

var networkProxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Run the Infisical proxy component",
	Long:  "Run the Infisical proxy component",
	Run: func(cmd *cobra.Command, args []string) {

		proxyName, err := cmd.Flags().GetString("name")
		if err != nil || proxyName == "" {
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

		proxyInstance, err := proxy.NewProxy(&proxy.ProxyConfig{
			ProxyName: proxyName,
			SSHPort:   "2222",
			TLSPort:   "443",
			StaticIP:  ip,
			Type:      instanceType,
		})

		if err != nil {
			util.HandleError(err, "unable to create proxy instance")
		}

		if instanceType == "instance" {
			proxyAuthSecret := os.Getenv(gatewayv2.PROXY_AUTH_SECRET_ENV_NAME)
			if proxyAuthSecret == "" {
				util.HandleError(fmt.Errorf("%s is not set", gatewayv2.PROXY_AUTH_SECRET_ENV_NAME), "unable to get proxy auth secret")
			}

			proxyInstance.SetToken(proxyAuthSecret)
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

			proxyInstance.SetToken(accessToken.Load().(string))

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

			ctx, cancelCmd := context.WithCancel(cmd.Context())
			defer cancelCmd()

			go func() {
				<-sigCh
				log.Info().Msg("Received shutdown signal, shutting down proxy...")
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
							proxyInstance.SetToken(newToken)
						}

					case <-ctx.Done():
						return
					}
				}
			}()
		}

		// Use the same context for the proxy server
		err = proxyInstance.Start(cmd.Context())
		if err != nil {
			util.HandleError(err, "unable to start proxy instance")
		}
	},
}

var networkProxyInstallCmd = &cobra.Command{
	Use:   "proxy install",
	Short: "Install and enable systemd service for the proxy (requires sudo)",
	Long:  "Install and enable systemd service for the proxy. Must be run with sudo on Linux.",
	Run: func(cmd *cobra.Command, args []string) {
		// TODO: Implement this
	},
}

var networkGatewayCmd = &cobra.Command{
	Use:   "gateway",
	Short: "Run the Infisical gateway component",
	Long:  "Run the Infisical gateway component",
	Run: func(cmd *cobra.Command, args []string) {

		proxyName, err := util.GetCmdFlagOrEnv(cmd, "proxy-name", []string{gatewayv2.PROXY_NAME_ENV_NAME})
		if err != nil {
			util.HandleError(err, fmt.Sprintf("unable to get proxy-name flag or %s env", gatewayv2.PROXY_NAME_ENV_NAME))
		}

		gatewayName, err := util.GetCmdFlagOrEnv(cmd, "name", []string{gatewayv2.GATEWAY_NAME_ENV_NAME})
		if err != nil {
			util.HandleError(err, fmt.Sprintf("unable to get name flag or %s env", gatewayv2.GATEWAY_NAME_ENV_NAME))
		}

		gatewayInstance, err := gatewayv2.NewGateway(&gatewayv2.GatewayConfig{
			Name:           gatewayName,
			ProxyName:      proxyName,
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

func init() {
	networkGatewayCmd.Flags().String("proxy-name", "", "The name of the proxy to connect to")
	networkGatewayCmd.Flags().String("name", "", "The name of the gateway")
	networkGatewayCmd.Flags().String("token", "", "connect with Infisical using machine identity access token. if not provided, you must set the auth-method flag")
	networkGatewayCmd.Flags().String("auth-method", "", "login method [universal-auth, kubernetes, azure, gcp-id-token, gcp-iam, aws-iam, oidc-auth]. if not provided, you must set the token flag")
	networkGatewayCmd.Flags().String("client-id", "", "client id for universal auth")
	networkGatewayCmd.Flags().String("client-secret", "", "client secret for universal auth")
	networkGatewayCmd.Flags().String("machine-identity-id", "", "machine identity id for kubernetes, azure, gcp-id-token, gcp-iam, and aws-iam auth methods")
	networkGatewayCmd.Flags().String("service-account-token-path", "", "service account token path for kubernetes auth")
	networkGatewayCmd.Flags().String("service-account-key-file-path", "", "service account key file path for GCP IAM auth")
	networkGatewayCmd.Flags().String("jwt", "", "JWT for jwt-based auth methods [oidc-auth, jwt-auth]")

	networkProxyCmd.Flags().String("type", "org", "The type of proxy to run. Must be either 'instance' or 'org'")
	networkProxyCmd.Flags().String("ip", "", "The IP address of the proxy")
	networkProxyCmd.Flags().String("name", "", "The name of the proxy")
	networkProxyCmd.Flags().String("token", "", "connect with Infisical using machine identity access token. if not provided, you must set the auth-method flag")
	networkProxyCmd.Flags().String("auth-method", "", "login method [universal-auth, kubernetes, azure, gcp-id-token, gcp-iam, aws-iam, oidc-auth]. if not provided, you must set the token flag")
	networkProxyCmd.Flags().String("client-id", "", "client id for universal auth")
	networkProxyCmd.Flags().String("client-secret", "", "client secret for universal auth")
	networkProxyCmd.Flags().String("machine-identity-id", "", "machine identity id for kubernetes, azure, gcp-id-token, gcp-iam, and aws-iam auth methods")
	networkProxyCmd.Flags().String("service-account-token-path", "", "service account token path for kubernetes auth")
	networkProxyCmd.Flags().String("service-account-key-file-path", "", "service account key file path for GCP IAM auth")
	networkProxyCmd.Flags().String("jwt", "", "JWT for jwt-based auth methods [oidc-auth, jwt-auth]")

	networkProxyCmd.AddCommand(networkProxyInstallCmd)

	networkCmd.AddCommand(networkProxyCmd)
	networkCmd.AddCommand(networkGatewayCmd)

	rootCmd.AddCommand(networkCmd)
}
