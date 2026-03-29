/*
Copyright (c) 2023 Infisical Inc.
*/
package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/Infisical/infisical-merge/packages/config"
	localkmip "github.com/Infisical/infisical-merge/packages/kmip"
	"github.com/Infisical/infisical-merge/packages/util"
	kmip "github.com/infisical/infisical-kmip"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var kmipCmd = &cobra.Command{
	Example: `  infisical kmip
  infisical kmip start --identity-client-id=<client-id> --identity-client-secret=<client-secret> --hostnames-or-ips=<hostnames-or-ips>
  sudo infisical kmip systemd install --identity-client-id=<client-id> --identity-client-secret=<client-secret> --hostnames-or-ips=<hostnames-or-ips>`,
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

	identityAuthMethod, err := cmd.Flags().GetString("identity-auth-method")
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}

	authMethodValid, strategy := util.IsAuthMethodValid(identityAuthMethod, false)
	if !authMethodValid {
		util.PrintErrorMessageAndExit(fmt.Sprintf("Invalid login method: %s", identityAuthMethod))
	}

	var identityClientId string
	var identityClientSecret string

	if strategy == util.AuthStrategy.UNIVERSAL_AUTH {
		identityClientId, err = util.GetCmdFlagOrEnv(cmd, "identity-client-id", []string{util.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME})
		if err != nil {
			util.HandleError(err, "Unable to parse identity client ID")
		}

		identityClientSecret, err = util.GetCmdFlagOrEnv(cmd, "identity-client-secret", []string{util.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET_NAME})
		if err != nil {
			util.HandleError(err, "Unable to parse identity client secret")
		}
	} else {
		util.PrintErrorMessageAndExit(fmt.Sprintf("Unsupported login method: %s", identityAuthMethod))
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

	kmip.StartServer(kmip.ServerConfig{
		Addr:                 listenAddr,
		InfisicalBaseAPIURL:  config.INFISICAL_URL,
		IdentityClientId:     identityClientId,
		IdentityClientSecret: identityClientSecret,
		ServerName:           serverName,
		CertificateTTL:       certificateTTL,
		HostnamesOrIps:       hostnamesOrIps,
	})
}

var kmipSystemdCmd = &cobra.Command{
	Use:   "systemd",
	Short: "Manage systemd service for Infisical KMIP server",
	Long:  "Manage systemd service for Infisical KMIP server. Use 'systemd install' to install and enable the service.",
	Example: `  sudo infisical kmip systemd install --identity-client-id=<client-id> --identity-client-secret=<client-secret> --hostnames-or-ips=<hostnames-or-ips>
  sudo infisical kmip systemd uninstall`,
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
}

var kmipSystemdInstallCmd = &cobra.Command{
	Use:                   "install",
	Short:                 "Install and enable systemd service for the KMIP server (requires sudo)",
	Long:                  "Install and enable systemd service for the KMIP server. Must be run with sudo on Linux.",
	Example:               "sudo infisical kmip systemd install --identity-client-id=<client-id> --identity-client-secret=<client-secret> --hostnames-or-ips=<hostnames-or-ips>",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if runtime.GOOS != "linux" {
			util.HandleError(fmt.Errorf("systemd service installation is only supported on Linux"))
		}

		if os.Geteuid() != 0 {
			util.HandleError(fmt.Errorf("systemd service installation requires root/sudo privileges"))
		}

		identityClientId, err := util.GetCmdFlagOrEnv(cmd, "identity-client-id", []string{util.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME})
		if err != nil {
			util.HandleError(err, "Unable to parse identity client ID")
		}

		identityClientSecret, err := util.GetCmdFlagOrEnv(cmd, "identity-client-secret", []string{util.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET_NAME})
		if err != nil {
			util.HandleError(err, "Unable to parse identity client secret")
		}

		domain, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "domain", []string{util.INFISICAL_API_URL_ENV_NAME}, "")
		if err != nil {
			util.HandleError(err, "Unable to parse domain")
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

		err = localkmip.InstallKmipSystemdService(identityClientId, identityClientSecret, domain, listenAddress, serverName, certificateTTL, hostnamesOrIps)
		if err != nil {
			util.HandleError(err, "Failed to install systemd service")
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
	kmipStartCmd.Flags().String("listen-address", "localhost:5696", "The address for the KMIP server to listen on. Defaults to localhost:5696")
	kmipStartCmd.Flags().String("identity-auth-method", string(util.AuthStrategy.UNIVERSAL_AUTH), "The auth method to use for authenticating the machine identity. Defaults to universal-auth.")
	kmipStartCmd.Flags().String("identity-client-id", "", "Universal auth client ID of machine identity")
	kmipStartCmd.Flags().String("identity-client-secret", "", "Universal auth client secret of machine identity")
	kmipStartCmd.Flags().String("server-name", "kmip-server", "The name of the KMIP server. Defaults to kmip-server")
	kmipStartCmd.Flags().String("certificate-ttl", "1y", "The TTL duration for the server certificate. Defaults to 1y")
	kmipStartCmd.Flags().String("hostnames-or-ips", "", "Comma-separated list of hostnames or IPs")

	// KMIP systemd install command flags
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
