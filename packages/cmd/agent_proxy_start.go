package cmd

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/Infisical/infisical-merge/packages/agentproxy"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/fatih/color"
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

	var proxyToken atomic.Value
	proxyToken.Store(loginResp.AccessToken)
	go refreshProxyToken(&proxyToken, clientID, clientSecret, loginResp.AccessTokenTTL)

	err = agentproxy.Start(agentproxy.Options{
		Port:          port,
		UnmatchedHost: unmatchedHost,
		PollInterval:  time.Duration(pollInterval) * time.Second,
		ProxyToken:    func() string { return proxyToken.Load().(string) },
	})
	if err != nil {
		util.HandleError(err, "Agent proxy failed")
	}
}

func refreshProxyToken(token *atomic.Value, clientID, clientSecret string, ttlSeconds int) {
	const retryInterval = 30 * time.Second

	halfTTL := func() time.Duration {
		wait := time.Duration(ttlSeconds) * time.Second / 2
		if wait < retryInterval {
			wait = retryInterval
		}
		return wait
	}

	wait := halfTTL()
	for {
		time.Sleep(wait)

		loginResp, err := util.UniversalAuthLogin(clientID, clientSecret)
		if err != nil {
			log.Warn().Err(err).Msgf("Failed to refresh agent proxy token, retrying in %s", retryInterval)
			wait = retryInterval
			continue
		}
		token.Store(loginResp.AccessToken)
		if loginResp.AccessTokenTTL > 0 {
			ttlSeconds = loginResp.AccessTokenTTL
		}
		wait = halfTTL()
	}
}
