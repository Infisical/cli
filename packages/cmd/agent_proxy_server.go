package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Infisical/infisical-merge/packages/agentproxy"
	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/posthog/posthog-go"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// The access token is written here after enrollment so a restart does not need a fresh enrollment token,
// which is one-time use.
const agentProxyTokenRelativePath = ".infisical/agent-proxy/access-token"

var agentProxyServerCmd = &cobra.Command{
	Use:   "agent-proxy",
	Short: "Run an agent proxy that brokers credentials on the intersection of agent and user policies",
	Long: `Run an agent proxy.

An agent proxy is registered in Infisical under Networking. Point an agent's HTTP_PROXY at it with a
session token as the proxy credential, and it applies the policies for that session: a request is allowed
when both the agent's policies and the user's allow it, and only then is a credential attached.`,
	Example: `# First run, with a one-time enrollment token from the Infisical UI
infisical agent-proxy start --token=<enrollment-token> --port=17323

# Later runs reuse the saved access token
infisical agent-proxy start`,
	DisableFlagsInUseLine: true,
}

var agentProxyServerStartCmd = &cobra.Command{
	Use:                   "start",
	Short:                 "Start the agent proxy",
	DisableFlagsInUseLine: true,
	Run:                   runAgentProxyServerStart,
}

func agentProxyTokenPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, agentProxyTokenRelativePath), nil
}

func saveAgentProxyToken(token string) error {
	path, err := agentProxyTokenPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(token), 0o600)
}

func loadAgentProxyToken() string {
	path, err := agentProxyTokenPath()
	if err != nil {
		return ""
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(contents)
}

// resolveAgentProxyAccessToken enrolls with a one-time token when one is supplied, and otherwise reuses
// the saved access token. An enrollment token can only be redeemed once, so enrolling always wins: it is
// what an operator reaches for when the previous token was revoked.
func resolveAgentProxyAccessToken(cmd *cobra.Command) string {
	enrollmentToken, _ := cmd.Flags().GetString("token")
	if enrollmentToken == "" {
		enrollmentToken = os.Getenv("INFISICAL_AGENT_PROXY_ENROLLMENT_TOKEN")
	}

	if enrollmentToken != "" {
		resp, err := api.CallAgentProxyLogin(resty.New(), enrollmentToken)
		if err != nil {
			util.HandleError(err, "Failed to enroll the agent proxy")
		}
		if err := saveAgentProxyToken(resp.AccessToken); err != nil {
			log.Warn().Err(err).Msg("enrolled, but could not save the access token; the next start will need a new enrollment token")
		}
		log.Info().Msgf("Enrolled agent proxy [agentProxyId=%s]", resp.AgentProxyID)
		return resp.AccessToken
	}

	if saved := loadAgentProxyToken(); saved != "" {
		return saved
	}

	util.HandleError(fmt.Errorf("no access token found; pass --token with an enrollment token from Infisical (Organization Settings > Networking > Agent Proxies) or set INFISICAL_AGENT_PROXY_ENROLLMENT_TOKEN"))
	return ""
}

func runAgentProxyServerStart(cmd *cobra.Command, args []string) {
	port, err := cmd.Flags().GetInt("port")
	if err != nil {
		util.HandleError(err, "Unable to parse --port")
	}
	pollInterval, err := cmd.Flags().GetInt("poll-interval")
	if err != nil {
		util.HandleError(err, "Unable to parse --poll-interval")
	}
	logFormat, _ := cmd.Flags().GetString("log-format")
	if logFormat != "" && logFormat != "console" && logFormat != "json" {
		util.HandleError(fmt.Errorf("--log-format must be 'console' or 'json', got %q", logFormat))
	}
	logWriter, err := BuildAgentProxyLogWriter(logFormat, "")
	if err != nil {
		util.HandleError(err)
	}
	log.Logger = log.Output(logWriter)

	accessToken := resolveAgentProxyAccessToken(cmd)

	Telemetry.CaptureEvent("cli-command:agent-proxy start", posthog.NewProperties().Set("version", util.CLI_VERSION))

	if err := agentproxy.StartPolicyProxy(agentproxy.PolicyOptions{
		Port:         port,
		PollInterval: time.Duration(pollInterval) * time.Second,
		ProxyToken:   func() string { return accessToken },
	}); err != nil {
		util.HandleError(err, "Agent proxy failed")
	}
}

func init() {
	agentProxyServerStartCmd.Flags().Int("port", 17323, "port for the agent proxy to listen on")
	agentProxyServerStartCmd.Flags().Int("poll-interval", 60, "seconds between policy refreshes for active sessions")
	agentProxyServerStartCmd.Flags().String("token", "", "one-time enrollment token from Infisical (falls back to INFISICAL_AGENT_PROXY_ENROLLMENT_TOKEN)")
	agentProxyServerStartCmd.Flags().String("log-format", "console", "log output format: console | json")

	agentProxyServerCmd.AddCommand(agentProxyServerStartCmd)
	RootCmd.AddCommand(agentProxyServerCmd)
}
