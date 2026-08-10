package cmd

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/Infisical/infisical-merge/packages/agentproxy"
	"github.com/Infisical/infisical-merge/packages/telemetry"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/fatih/color"
	infisicalSdk "github.com/infisical/go-sdk"
	"github.com/posthog/posthog-go"
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

	logFormat, _ := cmd.Flags().GetString("log-format")
	if logFormat != "" && logFormat != "console" && logFormat != "json" {
		util.HandleError(fmt.Errorf("--log-format must be 'console' or 'json', got %q", logFormat))
	}
	logFile, _ := cmd.Flags().GetString("log-file")
	logWriter, err := BuildAgentProxyLogWriter(logFormat, logFile)
	if err != nil {
		util.HandleError(err)
	}
	log.Logger = log.Output(logWriter)

	// Same order as connect and as `pam agentic-access`: a ready-made token first, then a machine
	// identity authenticating with its own credentials.
	var accessToken string
	var accessTokenTTL int
	var login func() (infisicalSdk.MachineIdentityCredential, error)
	credentialSource := "token"

	if token := resolveAgentProxyStaticToken(cmd, "the provided token"); token != nil {
		// A token minted elsewhere. Nothing here can renew it, and the proxy is meant to outlive any
		// single token, so this is worth saying out loud rather than leaving to be discovered when every
		// request starts failing at once.
		accessToken = token.Token
		log.Warn().Msg("The agent proxy is running on a fixed token, which it cannot renew. It will stop working when that token expires; use --auth-method or client credentials to have it re-authenticate on its own.")
	} else {
		login, credentialSource = resolveAgentProxyLogin(cmd)
		if login == nil {
			util.HandleError(fmt.Errorf("agent proxy credentials required; pass --auth-method [%s] with that method's credentials, --client-id/--client-secret, or a token", util.MachineIdentityAuthMethods))
		}
		credential, err := login()
		if err != nil {
			util.HandleError(err, "Failed to authenticate the agent proxy machine identity")
		}
		accessToken = credential.AccessToken
		accessTokenTTL = int(credential.ExpiresIn)
	}

	Telemetry.SetActor(telemetry.IdentityClaimsFromToken(accessToken))
	Telemetry.CaptureEvent("cli-command:agent-proxy start", posthog.NewProperties().
		Set("version", util.CLI_VERSION).
		Set("unmatchedHost", unmatchedHost).
		Set("pollInterval", pollInterval).
		Set("credentialSource", credentialSource))

	log.Info().Msg(color.GreenString("Agent proxy authenticated; starting MITM proxy"))

	// atomic.Value rather than the SDK's own getter: the proxy reads this on the per-request path while
	// the refresher writes it, and Auth().GetAccessToken reads the SDK's token field without holding
	// the client's mutex. See resolveAgentProxyLogin.
	var proxyToken atomic.Value
	proxyToken.Store(accessToken)
	if login != nil {
		go refreshProxyToken(&proxyToken, login, accessTokenTTL)
	}

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

// refreshProxyToken re-authenticates the proxy's machine identity on a schedule, whatever method it
// uses: login performs a full authentication rather than a renewal, so nothing here depends on which
// one it is.
func refreshProxyToken(token *atomic.Value, login func() (infisicalSdk.MachineIdentityCredential, error), ttlSeconds int) {
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

		credential, err := login()
		if err != nil {
			log.Warn().Err(err).Msgf("Failed to refresh agent proxy token, retrying in %s", retryInterval)
			wait = retryInterval
			continue
		}
		token.Store(credential.AccessToken)
		if credential.ExpiresIn > 0 {
			ttlSeconds = int(credential.ExpiresIn)
		}
		wait = halfTTL()
	}
}
