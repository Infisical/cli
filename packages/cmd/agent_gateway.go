package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"text/tabwriter"
	"time"

	"github.com/Infisical/infisical-merge/packages/agentproxy"
	"github.com/Infisical/infisical-merge/packages/agentproxy/tunnel"
	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/gatewaydial"
	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// The product concept is an Agent Gateway, so the command says so. `agent-proxy` stays as a hidden alias for
// the shipped form rather than breaking scripts on the spot.
var agentGatewayCmd = &cobra.Command{
	Use:                   "gateway",
	Short:                 "Broker your agent's requests to proxied services through an Agent Gateway",
	DisableFlagsInUseLine: true,
}

var agentGatewayListCmd = &cobra.Command{
	Use:                   "list",
	Short:                 "List the Agent Gateways you can use in a project",
	DisableFlagsInUseLine: true,
	Run:                   runAgentGatewayList,
}

func resolveAgentGatewayName(cmd *cobra.Command) string {
	if name, _ := cmd.Flags().GetString("name"); name != "" {
		return name
	}
	if name := os.Getenv(util.INFISICAL_AGENT_GATEWAY_NAME_ENV); name != "" {
		return name
	}
	// Unlike --proxy, a committed name is safe to honour: it escalates nothing, because the backend
	// authorizes the caller against that agent gateway's access list regardless of who names it.
	if workspaceFile, err := util.GetWorkSpaceFromFile(); err == nil {
		return workspaceFile.DefaultAgentGateway
	}
	return ""
}

// Mixing --name with the old folder-scope flags is an error rather than a silent preference. Quietly ignoring
// flags in a tool that decides which credentials reach an agent is not acceptable. --projectId is not one of
// them: agent gateway names are unique per project, so naming the project is still how the lookup is scoped.
func assertNoLegacyScopeFlags(cmd *cobra.Command) error {
	var offenders []string
	for _, flag := range []string{"proxy", "env", "path"} {
		if cmd.Flags().Changed(flag) {
			offenders = append(offenders, "--"+flag)
		}
	}
	if len(offenders) > 0 {
		return fmt.Errorf(
			"--name cannot be combined with %s: an Agent Gateway already defines which services are brokered and where their secrets live",
			strings.Join(offenders, ", "),
		)
	}
	return nil
}

// Auth for every agent gateway command, in the order a caller expects: an explicit token, then the usual
// token environment variables, then universal-auth client credentials, then the interactive login. The
// client-credential path matters because remote mode is the unattended case, where there is no keyring
// login to fall back on.
func resolveAgentGatewayToken(cmd *cobra.Command) (*models.TokenDetails, string, error) {
	if token, err := util.GetInfisicalToken(cmd); err == nil && token != nil && token.Token != "" {
		return token, "token", nil
	}

	clientID, _ := util.GetCmdFlagOrEnvWithDefaultValue(
		cmd,
		"client-id",
		[]string{util.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME},
		"",
	)
	clientSecret, _ := util.GetCmdFlagOrEnvWithDefaultValue(
		cmd,
		"client-secret",
		[]string{util.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET_NAME},
		"",
	)

	if clientID != "" && clientSecret != "" {
		loginResponse, err := util.UniversalAuthLogin(clientID, clientSecret)
		if err != nil {
			return nil, "", fmt.Errorf("failed to authenticate the machine identity: %w", err)
		}
		return &models.TokenDetails{
			Type:  util.UNIVERSAL_AUTH_TOKEN_IDENTIFIER,
			Token: loginResponse.AccessToken,
		}, "machine identity", nil
	}

	// Naming the halves that are missing, because setting only one of the pair is the common mistake.
	if clientID != "" || clientSecret != "" {
		missing := "--client-secret (or INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET)"
		if clientID == "" {
			missing = "--client-id (or INFISICAL_UNIVERSAL_AUTH_CLIENT_ID)"
		}
		return nil, "", fmt.Errorf("machine identity credentials are incomplete: %s is missing", missing)
	}

	details, err := util.GetCurrentLoggedInUserDetails(true)
	if err != nil || !details.IsUserLoggedIn || details.LoginExpired || details.UserCredentials.JTWToken == "" {
		return nil, "", fmt.Errorf(
			"could not resolve your Infisical credentials; run 'infisical login', pass --token, or set INFISICAL_UNIVERSAL_AUTH_CLIENT_ID and INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET",
		)
	}

	return &models.TokenDetails{Token: details.UserCredentials.JTWToken}, details.UserCredentials.Email, nil
}

func agentGatewayHTTPClient(token string) *resty.Client {
	return resty.New().SetAuthToken(token)
}

// Resolves a name to an agent gateway the caller may actually use, and explains what to do when it cannot.
func lookupAgentGateway(client *resty.Client, projectId string, name string) (api.GetAgentGatewayByNameResponse, error) {
	found, err := api.CallGetAgentGatewayByName(client, projectId, name)
	if err == nil {
		return found, nil
	}

	// Naming what they *can* use turns a dead end into a next step.
	if listed, listErr := api.CallListAgentGateways(client, projectId); listErr == nil && len(listed.AgentGateways) > 0 {
		names := make([]string, 0, len(listed.AgentGateways))
		for _, agentGateway := range listed.AgentGateways {
			names = append(names, agentGateway.Name)
		}
		return api.GetAgentGatewayByNameResponse{}, fmt.Errorf(
			"agent gateway %q not found, or you do not have access to it. Agent gateways you can use: %s",
			name,
			strings.Join(names, ", "),
		)
	}

	return api.GetAgentGatewayByNameResponse{}, fmt.Errorf(
		"agent gateway %q not found, or you do not have access to it. Ask a project admin to create one, or to add you to its access list",
		name,
	)
}

func runAgentGatewayList(cmd *cobra.Command, args []string) {
	token, _, err := resolveAgentGatewayToken(cmd)
	if err != nil {
		util.HandleError(err)
	}

	projectId, err := getAgentGatewayProjectId(cmd)
	if err != nil {
		util.HandleError(err)
	}

	listed, err := api.CallListAgentGateways(agentGatewayHTTPClient(token.Token), projectId)
	if err != nil {
		util.HandleError(err, "Failed to list agent gateways")
	}

	if len(listed.AgentGateways) == 0 {
		fmt.Println("No agent gateways in this project yet.")
		return
	}

	writer := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintln(writer, "NAME\tSERVICES\tGATEWAY\tSTATUS")
	for _, agentGateway := range listed.AgentGateways {
		gatewayName := "local only"
		status := "-"
		if agentGateway.Gateway != nil {
			gatewayName = agentGateway.Gateway.Name
			switch {
			case !agentGateway.Gateway.IsHealthy:
				status = "unreachable"
			case !agentGateway.Gateway.SupportsAgentProxy:
				status = "needs upgrade"
			default:
				status = "online"
			}
		}
		fmt.Fprintf(writer, "%s\t%d\t%s\t%s\n", agentGateway.Name, agentGateway.ProxiedServiceCount, gatewayName, status)
	}
	writer.Flush()
}

func getAgentGatewayProjectId(cmd *cobra.Command) (string, error) {
	if projectId, _ := cmd.Flags().GetString("projectId"); projectId != "" {
		return projectId, nil
	}
	if projectId := os.Getenv(util.INFISICAL_PROJECT_ID_NAME); projectId != "" {
		return projectId, nil
	}
	// Names are unique per project, so a project is required. Making them org-unique would introduce a new
	// namespace that will collide.
	workspaceFile, err := util.GetWorkSpaceFromFile()
	if err != nil || workspaceFile.WorkspaceId == "" {
		return "", fmt.Errorf("could not determine which project to use; pass --projectId, set INFISICAL_PROJECT_ID, or run this from a directory with an .infisical.json")
	}
	return workspaceFile.WorkspaceId, nil
}

// remoteBrokerSession holds a live remote session and keeps its certificate and expiry fresh. The certificate
// is the revocation clock: renewal re-checks the access list, so a principal removed from it stops being able
// to renew and the session dies with its last certificate.
type remoteBrokerSession struct {
	client    *resty.Client
	sessionID string

	mu        atomic.Pointer[tunnel.Client]
	transport atomic.Pointer[api.AgentGatewayTransportResponse]
}

func (s *remoteBrokerSession) dial(ctx context.Context) (*tunnel.Client, error) {
	transport := s.transport.Load()
	if transport == nil {
		fresh, err := api.CallGetAgentGatewayTransport(s.client, s.sessionID)
		if err != nil {
			return nil, err
		}
		transport = &fresh
		s.transport.Store(transport)
	}

	conn, err := gatewaydial.Dial(gatewaydial.ALPNInfisicalAgentGateway, gatewaydial.Credentials{
		RelayHost:              transport.RelayHost,
		RelayClientCert:        transport.Relay.ClientCertificate,
		RelayClientKey:         transport.Relay.ClientPrivateKey,
		RelayServerCertChain:   transport.Relay.ServerCertificateChain,
		GatewayClientCert:      transport.Gateway.ClientCertificate,
		GatewayClientKey:       transport.Gateway.ClientPrivateKey,
		GatewayServerCertChain: transport.Gateway.ServerCertificateChain,
	})
	if err != nil {
		if strings.Contains(err.Error(), "no application protocol") {
			return nil, fmt.Errorf(
				"the Infisical Gateway brokering this Agent Gateway is running a CLI version without Agent Gateway support. Upgrade the gateway and restart it",
			)
		}
		return nil, err
	}

	if err := writeAgentGatewayPreamble(conn); err != nil {
		conn.Close()
		return nil, err
	}

	client, err := tunnel.NewClient(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	s.mu.Store(client)
	return client, nil
}

func writeAgentGatewayPreamble(conn net.Conn) error {
	preamble, err := json.Marshal(map[string]any{
		"protocolVersion": 1,
		"clientVersion":   util.CLI_VERSION,
	})
	if err != nil {
		return err
	}
	if _, err := conn.Write(append(preamble, '\n')); err != nil {
		return fmt.Errorf("failed to greet the gateway: %w", err)
	}

	// The gateway answers with the version it will speak, so a mismatch is an actionable message rather than
	// mis-framed bytes later.
	buf := make([]byte, 0, 256)
	one := make([]byte, 1)
	for {
		n, err := conn.Read(one)
		if err != nil {
			return fmt.Errorf("failed to read the gateway's greeting: %w", err)
		}
		if n == 0 || one[0] == '\n' {
			break
		}
		buf = append(buf, one[0])
		if len(buf) > 4096 {
			return fmt.Errorf("the gateway's greeting was unexpectedly long")
		}
	}

	var ack struct {
		ProtocolVersion int    `json:"protocolVersion"`
		Error           string `json:"error,omitempty"`
	}
	if err := json.Unmarshal(buf, &ack); err != nil {
		return fmt.Errorf("failed to parse the gateway's greeting: %w", err)
	}
	if ack.Error != "" {
		return fmt.Errorf("%s", ack.Error)
	}
	return nil
}

// keepAlive renews the session at half-life for as long as the agent runs. A failure here is fatal to the
// session by design: it means the access list no longer includes the caller.
func (s *remoteBrokerSession) keepAlive(ctx context.Context, renewAfter time.Duration) {
	if renewAfter <= 0 {
		renewAfter = 30 * time.Minute
	}
	ticker := time.NewTicker(renewAfter)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, _, err := api.CallRenewAgentGatewaySession(s.client, s.sessionID); err != nil {
				log.Error().Err(err).Msg(
					"agent gateway session could not be renewed; the agent's brokered requests will start failing. Restart the command",
				)
				return
			}
			// A renewed session gets fresh certificates on the next dial.
			s.transport.Store(nil)
		}
	}
}

// startLocalListener serves the agent a plain forward proxy on loopback and relays each accepted connection
// over its own tunnel stream. The local secret is what stops any other process on the machine using this
// listener: remote mode has no sandbox, so without it an unauthenticated loopback proxy would inject
// credentials for anything that asked.
func startLocalListener(ctx context.Context, session *remoteBrokerSession, localSecret string) (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("failed to open the local proxy listener: %w", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port

	go func() {
		defer listener.Close()
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				select {
				case <-ctx.Done():
					return
				default:
					log.Debug().Err(acceptErr).Msg("local proxy listener stopped accepting")
					return
				}
			}
			go relayToGateway(ctx, session, conn, localSecret)
		}
	}()

	return port, nil
}

func relayToGateway(ctx context.Context, session *remoteBrokerSession, conn net.Conn, localSecret string) {
	defer conn.Close()

	client := session.mu.Load()
	if client == nil {
		fresh, err := session.dial(ctx)
		if err != nil {
			log.Error().Err(err).Msg("failed to reach the Agent Gateway")
			return
		}
		client = fresh
	}

	stream, err := client.Open(ctx)
	if err != nil {
		// The mux died; a fresh dial re-establishes it rather than failing every later request too.
		session.mu.Store(nil)
		session.transport.Store(nil)
		log.Error().Err(err).Msg("failed to open a tunnel to the Agent Gateway")
		return
	}
	defer stream.Close()

	agentproxy.PipeConns(conn, stream)
}

func init() {
	agentGatewayListCmd.Flags().String("projectId", "", "project id (falls back to INFISICAL_PROJECT_ID or .infisical.json)")
	agentGatewayListCmd.Flags().String("token", "", "machine identity access token")
	agentGatewayListCmd.Flags().String("client-id", "", "universal auth client id (falls back to INFISICAL_UNIVERSAL_AUTH_CLIENT_ID)")
	agentGatewayListCmd.Flags().String("client-secret", "", "universal auth client secret (falls back to INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET)")

	agentGatewayCmd.AddCommand(agentGatewayListCmd)
	secretsAgentCmd.AddCommand(agentGatewayCmd)
}

var agentGatewayConnectCmd = &cobra.Command{
	Use:   "connect [flags] -- [agent start command]",
	Short: "Run an agent with its requests brokered by a remote Agent Gateway",
	Long: `Run an agent whose outbound HTTP(S) requests are brokered by an Agent Gateway running inside an
Infisical Gateway. The agent gets no Infisical token and never sees a brokered credential: the broker applies
them on the wire, on another host.`,
	DisableFlagsInUseLine: true,
	Run:                   runAgentGatewayConnect,
}

var agentGatewayRunCmd = &cobra.Command{
	Use:   "run [flags] -- [agent start command]",
	Short: "Run an agent locally with its requests brokered on this machine",
	Long: `Start a broker alongside your agent on this machine and stop it when the agent exits. Credentials
resolve under your own permissions, because the broker shares your process and there is no boundary between
you and the plaintext; the sandbox is what keeps the agent away from them.`,
	DisableFlagsInUseLine: true,
	Run:                   runAgentGatewayRun,
}

// openAgentGatewaySession is the shared front half of both modes: resolve the name, check the mode is
// allowed, and open a session.
func openAgentGatewaySession(cmd *cobra.Command, mode api.AgentGatewaySessionMode) (*resty.Client, api.CreateAgentGatewaySessionResponse, error) {
	if err := assertNoLegacyScopeFlags(cmd); err != nil {
		return nil, api.CreateAgentGatewaySessionResponse{}, err
	}

	name := resolveAgentGatewayName(cmd)
	if name == "" {
		return nil, api.CreateAgentGatewaySessionResponse{}, fmt.Errorf(
			"no agent gateway named; pass --name, set INFISICAL_AGENT_GATEWAY, or add defaultAgentGateway to .infisical.json. Run 'infisical secrets agent gateway list' to see the ones you can use",
		)
	}

	token, _, err := resolveAgentGatewayToken(cmd)
	if err != nil {
		return nil, api.CreateAgentGatewaySessionResponse{}, err
	}

	projectId, err := getAgentGatewayProjectId(cmd)
	if err != nil {
		return nil, api.CreateAgentGatewaySessionResponse{}, err
	}

	client := agentGatewayHTTPClient(token.Token)
	agentGateway, err := lookupAgentGateway(client, projectId, name)
	if err != nil {
		return nil, api.CreateAgentGatewaySessionResponse{}, err
	}

	// Caught here rather than at the API so the message can name the other mode, which is almost always what
	// the person actually wanted.
	if mode == api.AgentGatewaySessionModeRemote && agentGateway.AgentGateway.Gateway == nil {
		return nil, api.CreateAgentGatewaySessionResponse{}, fmt.Errorf(
			"agent gateway %q has no Infisical Gateway attached, so it can only be used locally. Run: infisical secrets agent gateway run --name %s -- <command>",
			name, name,
		)
	}
	if mode == api.AgentGatewaySessionModeLocal && !agentGateway.AgentGateway.IsLocalModeEnabled {
		return nil, api.CreateAgentGatewaySessionResponse{}, fmt.Errorf(
			"agent gateway %q does not allow local mode. Enable local mode on it, or use 'infisical secrets agent gateway connect' instead",
			name,
		)
	}
	if len(agentGateway.AgentGateway.ProxiedServices) == 0 {
		// A brokering session with nothing to broker is always a misconfiguration, so it fails rather than
		// starting an agent whose requests all pass through untouched.
		return nil, api.CreateAgentGatewaySessionResponse{}, fmt.Errorf(
			"agent gateway %q has no proxied services connected, so nothing would be brokered. Connect at least one service in the Infisical dashboard",
			name,
		)
	}

	session, err := api.CallCreateAgentGatewaySession(client, agentGateway.AgentGateway.ID, api.CreateAgentGatewaySessionRequest{Mode: mode})
	if err != nil {
		return nil, api.CreateAgentGatewaySessionResponse{}, err
	}

	return client, session, nil
}

func runAgentGatewayConnect(cmd *cobra.Command, args []string) {
	client, session, err := openAgentGatewaySession(cmd, api.AgentGatewaySessionModeRemote)
	if err != nil {
		util.HandleError(err)
	}

	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	remote := &remoteBrokerSession{client: client, sessionID: session.Session.ID}
	transport, err := api.CallGetAgentGatewayTransport(client, session.Session.ID)
	if err != nil {
		util.HandleError(err, "Failed to get the Agent Gateway's connection details")
	}
	remote.transport.Store(&transport)

	// A 32-byte secret in the proxy URL, checked only by this listener. Remote mode has no sandbox, so
	// without it any other process on this machine could use the listener and have credentials applied.
	localSecret := util.GenerateRandomString(32)

	port, err := startLocalListener(ctx, remote, localSecret)
	if err != nil {
		util.HandleError(err)
	}

	go remote.keepAlive(ctx, time.Duration(session.Session.RenewAfterSeconds)*time.Second)

	// Best effort: a SIGKILLed CLI never gets here, which is why the backend sweeps expired sessions.
	defer func() {
		if endErr := api.CallEndAgentGatewaySession(client, session.Session.ID); endErr != nil {
			log.Debug().Err(endErr).Msg("failed to end the agent gateway session")
		}
	}()

	log.Info().Msgf(
		"Brokering through agent gateway %q on 127.0.0.1:%d",
		session.Session.AgentGatewayName,
		port,
	)

	placeholders := make([]agentproxy.Placeholder, 0, len(transport.Placeholders))
	for _, placeholder := range transport.Placeholders {
		placeholders = append(placeholders, agentproxy.Placeholder{Key: placeholder.Key, Value: placeholder.Value})
	}

	if err := runAgentBehindLocalProxy(cmd, args, port, localSecret, transport.CaCertificate, placeholders); err != nil {
		util.HandleError(err)
	}
}

// localBrokerSession is what a local run needs to broker: the session it opened, the token to resolve
// credentials with, and the placeholders the agent expects to find in its environment.
type localBrokerSession struct {
	ID               string
	AgentGatewayID   string
	AgentGatewayName string
	ActorName        string
	ExpiresAt        time.Time
	Placeholders     []agentproxy.Placeholder
	Token            func() string
	// The agent gateway's own policy for unmatched hosts. The flag can only tighten it, never loosen it.
	UnmatchedHost string
	// Hosts the agent gateway permits without a credential. A local run may add to these, never remove.
	AllowedHosts []string
}

func runAgentGatewayRun(cmd *cobra.Command, args []string) {
	client, session, err := openAgentGatewaySession(cmd, api.AgentGatewaySessionModeLocal)
	if err != nil {
		util.HandleError(err)
	}

	// os.Exit at the end of runLocalBroker skips defers, so the session is ended explicitly on every path.
	endSession := func() {
		if endErr := api.CallEndAgentGatewaySession(client, session.Session.ID); endErr != nil {
			log.Debug().Err(endErr).Msg("failed to end the agent gateway session")
		}
	}

	// Local mode resolves under the caller's own permissions: the broker shares this process, so there is no
	// boundary between the caller and the plaintext, and delegating would be a privilege-escalation path.
	src := resolveDeveloperTokenSource(cmd)

	// The same bundle the broker will serve, fetched once up front so the agent's environment carries the
	// placeholders and a credential the caller cannot read is reported before the agent starts.
	resolved, err := api.CallGetAgentGatewayPlaceholders(agentGatewayHTTPClient(src.token()), session.Session.ID)
	if err != nil {
		endSession()
		util.HandleError(err, "Failed to resolve what this Agent Gateway brokers")
	}
	placeholders := make([]agentproxy.Placeholder, 0, len(resolved))
	for _, placeholder := range resolved {
		placeholders = append(placeholders, agentproxy.Placeholder{Key: placeholder.Key, Value: placeholder.Value})
	}

	defer endSession()
	runLocalBroker(cmd, args, localBrokerSession{
		ID:               session.Session.ID,
		AgentGatewayID:   session.Session.AgentGatewayID,
		AgentGatewayName: session.Session.AgentGatewayName,
		ActorName:        src.label,
		ExpiresAt:        session.Session.ExpiresAt,
		Placeholders:     placeholders,
		Token:            src.token,
		UnmatchedHost:    session.Session.UnmatchedHostPolicy,
		AllowedHosts:     session.Session.AllowedHosts,
	}, endSession)
}

func init() {
	for _, command := range []*cobra.Command{agentGatewayConnectCmd, agentGatewayRunCmd} {
		command.Flags().String("name", "", "name of the Agent Gateway to broker through (falls back to INFISICAL_AGENT_GATEWAY or defaultAgentGateway in .infisical.json)")
		command.Flags().String("projectId", "", "project id (falls back to INFISICAL_PROJECT_ID or .infisical.json)")
		command.Flags().String("token", "", "machine identity access token")
		command.Flags().String("client-id", "", "universal auth client id (falls back to INFISICAL_UNIVERSAL_AUTH_CLIENT_ID)")
		command.Flags().String("client-secret", "", "universal auth client secret (falls back to INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET)")
		command.Flags().String("no-proxy", "", "additional comma-separated hosts to bypass the proxy (always merged with localhost,127.0.0.1)")
		command.Flags().StringArray("pass-env", nil, "pass one of your environment variables through to the agent (can be specified multiple times)")
		command.Flags().StringArray("set-env", nil, "set an environment variable in the agent as KEY=VALUE (can be specified multiple times)")
		command.Flags().Bool("no-trust-store", false, "do not add the brokering CA to the OS trust store; tools that ignore the CA environment variables (gh, most Go programs) will then reject brokered connections")
	}

	// Local-only: everything below is about the broker and the sandbox this process runs, neither of which
	// exists in remote mode. The unmatched-host policy is deliberately not a connect flag either; there it
	// comes from the Agent Gateway, because an agent choosing its own passthrough behaviour would defeat the
	// point of an allowlist.
	agentGatewayRunCmd.Flags().Bool("sandbox", true, "run the agent inside the OS sandbox")
	agentGatewayRunCmd.Flags().Bool("no-sandbox", false, "disable the OS sandbox; the agent can then read your files and reach the network directly")
	agentGatewayRunCmd.Flags().String("unmatched-host", "allow", "policy for hosts with no proxied service: allow | block")
	agentGatewayRunCmd.Flags().String("log-file", "", "write the broker's per-request activity log to this path")
	agentGatewayRunCmd.Flags().StringArray("allow-read", nil, "allow the agent to read a path the sandbox denies by default (can be specified multiple times)")
	agentGatewayRunCmd.Flags().StringArray("allow-write", nil, "allow the agent to write a path (can be specified multiple times)")
	agentGatewayRunCmd.Flags().StringArray("allow-host", nil, "allow the agent to reach a host that has no proxied service (can be specified multiple times)")

	agentGatewayCmd.AddCommand(agentGatewayConnectCmd)
	agentGatewayCmd.AddCommand(agentGatewayRunCmd)
}

// runAgentBehindLocalProxy points the agent's HTTP clients at the local listener and runs it. Deliberately no
// Infisical token reaches the agent: it has no Infisical identity of its own, so it cannot act as the caller
// against the API, and brokered credentials never enter its environment either.
func runAgentBehindLocalProxy(
	cmd *cobra.Command,
	args []string,
	port int,
	localSecret string,
	caCertificate string,
	placeholders []agentproxy.Placeholder,
) error {
	skipTrustStore, _ := cmd.Flags().GetBool("no-trust-store")

	if len(args) == 0 {
		return fmt.Errorf("nothing to run; put your agent's command after --, for example: -- claude")
	}

	caPath := ""
	if caCertificate != "" {
		written, err := writeBrokerCa(caCertificate)
		if err != nil {
			return fmt.Errorf("failed to write the CA the agent must trust: %w", err)
		}
		caPath = written

		// The trust environment variables below cover clients that read them (curl, Node, Python, Deno), but
		// Go tools such as gh consult the OS trust store instead and ignore them entirely. Without this, `gh`
		// fails with "certificate is not trusted" while curl through the same broker succeeds. Non-fatal: if
		// the prompt is declined, everything except natively-trusting tools still works.
		if !skipTrustStore {
			switch installed, err := ensureCATrusted(caPath); {
			case err != nil:
				util.PrintWarning(fmt.Sprintf(
					"Unable to add your organization's Infisical CA to the login keychain (%v). Tools that read the CA environment variables still work; Go tools such as gh will report a certificate error.",
					err,
				))
			case installed:
				util.PrintWarning(
					"Added your organization's Infisical CA to your login keychain as a trusted anchor, so tools that use the OS trust store (gh, and most Go programs) accept brokered connections. This is one-time and persists. Pass --no-trust-store to skip it.",
				)
			}
		}
	}

	// Remote mode has no sandbox, so the environment scrub is the only thing keeping the caller's own
	// credentials out of the agent. Same builder as the local path.
	env := buildLocalAgentEnv(cmd, localProxyURL(fmt.Sprintf("127.0.0.1:%d", port), localSecret), caPath, placeholders)

	return runAgentProcess(args, env)
}
