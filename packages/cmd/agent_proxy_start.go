package cmd

import (
	"fmt"
	"time"

	"github.com/Infisical/infisical-merge/packages/agentproxy"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/fatih/color"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func runAgentProxyStart(cmd *cobra.Command, args []string) {
	port, _ := cmd.Flags().GetInt("port")
	unmatchedHost, _ := cmd.Flags().GetString("unmatched-host")
	if unmatchedHost != agentproxy.UnmatchedAllow && unmatchedHost != agentproxy.UnmatchedBlock {
		util.HandleError(fmt.Errorf("--unmatched-host must be 'allow' or 'block', got %q", unmatchedHost))
	}
	pollInterval, _ := cmd.Flags().GetInt("poll-interval")

	// Authenticate as the agent proxy machine identity.
	clientID, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "client-id", []string{util.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME}, "")
	if err != nil || clientID == "" {
		util.HandleError(fmt.Errorf("agent proxy credentials required; set INFISICAL_UNIVERSAL_AUTH_CLIENT_ID / _SECRET or pass --client-id / --client-secret"))
	}
	clientSecret, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "client-secret", []string{util.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET_NAME}, "")
	if err != nil || clientSecret == "" {
		util.HandleError(fmt.Errorf("agent proxy client secret required"))
	}

	loginResp, err := util.UniversalAuthLogin(clientID, clientSecret)
	if err != nil {
		util.HandleError(err, "Failed to authenticate the agent proxy machine identity")
	}

	log.Info().Msg(color.GreenString("Agent proxy authenticated; starting MITM proxy"))

	caClient := resty.New().SetAuthToken(loginResp.AccessToken)

	err = agentproxy.Start(agentproxy.Options{
		Port:          port,
		UnmatchedHost: unmatchedHost,
		PollInterval:  time.Duration(pollInterval) * time.Second,
		ProxyToken:    loginResp.AccessToken,
		CaHTTPClient:  caClient,
	})
	if err != nil {
		util.HandleError(err, "Agent proxy failed")
	}
}
