package cmd

import (
	"cmp"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/agentvault"
	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/sandbox"
	"github.com/Infisical/infisical-merge/packages/telemetry"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/fatih/color"
	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	"github.com/mattn/go-isatty"
	"github.com/posthog/posthog-go"
	"github.com/spf13/cobra"
)

// The server validates names as slugs; matching that here keeps a typo a one-line message instead of a raw
// 422 body, which is all the CLI can print for a schema rejection.
var agentVaultBundleNameRe = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

// One file per proxy, so a run against a second proxy cannot overwrite the certificate an agent that is
// already running still trusts through its environment. The ID comes from the proxy over unauthenticated
// HTTP, so it is checked as a UUID before it can shape a path.
func agentVaultCaFilePath(dataDir, proxyID string) (string, error) {
	if _, err := uuid.Parse(proxyID); err != nil {
		return "", fmt.Errorf("the proxy reported an invalid proxy ID %q; something other than an Agent Vault proxy may be answering at that address", proxyID)
	}
	return filepath.Join(dataDir, "ca-"+proxyID+".pem"), nil
}

// Served by the proxy itself over plain HTTP, not by Infisical, so it uses its own net/http client.
// Proxy is nil rather than absent: the default transport would route this through the operator's
// HTTP_PROXY, and the address names a machine on their own network, so it never belongs to a proxy.
var agentVaultProxyHTTPClient = &http.Client{
	Timeout:   10 * time.Second,
	Transport: &http.Transport{Proxy: nil},
}

// The endpoint is unauthenticated plain HTTP, so whatever answers at that address is bounded before
// it is read. A certificate and three short fields are a couple of kilobytes.
const agentVaultCaResponseLimit = 1 << 20

// Bound the revoke, which otherwise waits on retries against an unreachable Infisical. An operator who
// interrupted the run is waiting at the terminal, so that revoke gives up sooner.
const (
	agentVaultInterruptRevokeTimeout = 10 * time.Second
	agentVaultExitRevokeTimeout      = 30 * time.Second
)

type agentVaultProxyCa struct {
	ProxyID     string `json:"proxyId"`
	Name        string `json:"name"`
	Certificate string `json:"certificate"`
	Fingerprint string `json:"fingerprint"`
}

func fetchAgentVaultProxyCa(proxyAddr string) (agentVaultProxyCa, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/_agent-vault/ca", proxyAddr), nil)
	if err != nil {
		return agentVaultProxyCa{}, err
	}
	req.Header.Set("User-Agent", api.USER_AGENT)

	resp, err := agentVaultProxyHTTPClient.Do(req)
	if err != nil {
		return agentVaultProxyCa{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return agentVaultProxyCa{}, fmt.Errorf("the proxy answered %d to the certificate request", resp.StatusCode)
	}

	var ca agentVaultProxyCa
	if err := json.NewDecoder(io.LimitReader(resp.Body, agentVaultCaResponseLimit)).Decode(&ca); err != nil {
		return agentVaultProxyCa{}, fmt.Errorf("the proxy's certificate response could not be read: %w", err)
	}
	return ca, nil
}

var agentVaultRunCmd = &cobra.Command{
	Use:   "run [flags] --proxy <host:port> -- [agent command]",
	Short: "Launch an agent that holds no credentials, routed through an Agent Vault proxy",
	Long: `Launch an agent that holds no credentials, routed through an Agent Vault proxy.

The agent's HTTP traffic is pointed at the proxy, which attaches the real credential at the network boundary.
The process you start receives a session token, the proxy address and the proxy's certificate authority, and
inherits the rest of your environment.

Two ways to get a session, exactly one of them required:

  --access-bundle   mint one now over the named bundle, or set INFISICAL_AGENT_VAULT_ACCESS_BUNDLE
                    (needs your login or a machine identity). Revoked when the agent exits unless
                    --keep-session is set. The bundle is looked up in the Agent Vault project from
                    --project-id, or else INFISICAL_AGENT_VAULT_PROJECT_ID or INFISICAL_PROJECT_ID,
                    in that order.
  --session-token   run with a session token minted in the dashboard, or set
                    INFISICAL_AGENT_VAULT_SESSION_TOKEN. Never revoked by this command.

Both accept a variable instead of the flag, and a flag beats a variable. If both variables are set and
neither flag is passed, the run stops and asks which you meant.

The proxy's certificate authority is fetched from the proxy on every run and trusted for the agent. Pass
--ca-fingerprint to abort if the served certificate does not match the proxy's fingerprint from Infisical.

The proxy says which Infisical it works with, and the agent gets that Infisical's URL in INFISICAL_AGENT_VAULT_URL.
Through the proxy, the agent lists the services its session reaches at
$INFISICAL_AGENT_VAULT_URL/api/v1/agent-vault/session/services, with no credential of its own.

The session's skills (its access bundle's, the ones it names and the ones sent with it), plus infisical-agent-vault,
which tells the agent how to work behind the proxy, are fetched through the proxy and installed when the agent starts, into
~/.agents/skills, where Codex, OpenCode and OpenClaw find them. A proxy too old to pass skills on is skipped and
Infisical asked directly. Pass --no-agent-vault-skill to leave out infisical-agent-vault. If ~/.claude (or $CLAUDE_CONFIG_DIR) or
~/.hermes (or $HERMES_HOME) exists, each skill is also linked into its skills folder for Claude Code or
Hermes, and for Claude Code whenever the agent is claude. Pass --skills-dir to install them into another
folder instead, with no links, or --no-skills to start without them. Installed skills stay after the agent
exits, and folders of your own with a skill's name are left alone. Restart the agent to pick up changes to
them. If they cannot be installed, the agent starts without them.

When the agent is claude, the session's MCP servers that are ready are added to it with --mcp-config, on top of any
you pass, each with a placeholder credential the proxy replaces, so Claude Code has their tools from the start. Pass
--no-mcp-servers to leave them out.

Unlike 'secrets agent-proxy run', this command does not sandbox the agent: it sets environment variables
and starts the process.`,
	Example: `  infisical agent-vault run --access-bundle on-call-infrastructure --proxy 10.0.1.5:17323 -- claude
  infisical agent-vault run --session-token agv_... --proxy 10.0.1.5:17323 --ca-fingerprint SHA256:9F:2C:... -- claude`,
	DisableFlagsInUseLine: true,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("provide the agent command to run after '--', e.g. -- claude")
		}
		return nil
	},
	Run: runAgentVaultRun,
}

// nonBlank drops values that name nothing, so a stray empty --access-bundle does not count towards
// the one-bundle limit.
func nonBlank(values []string) []string {
	var kept []string
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			kept = append(kept, value)
		}
	}
	return kept
}

const (
	agentVaultSessionTokenEnv = "INFISICAL_AGENT_VAULT_SESSION_TOKEN"
	agentVaultAccessBundleEnv = "INFISICAL_AGENT_VAULT_ACCESS_BUNDLE"
	agentVaultProxyAddressEnv = "INFISICAL_AGENT_VAULT_PROXY_ADDRESS"
)

// Where a setting came from. A flag was typed for this run; a variable is ambient and may be left over
// from another one.
type agentVaultSource int

const (
	agentVaultSourceNone agentVaultSource = iota
	agentVaultSourceEnv
	agentVaultSourceFlag
)

// An explicit but empty --session-token is an error rather than a fall back to the environment: that
// shape is "$SOME_VAR" with the variable unset, and running on a session the operator did not name is
// the surprise worth avoiding.
func resolveAgentVaultSessionToken(cmd *cobra.Command) (token string, source agentVaultSource, err error) {
	flagValue, err := cmd.Flags().GetString("session-token")
	if err != nil {
		return "", agentVaultSourceNone, err
	}
	if cmd.Flags().Changed("session-token") {
		if strings.TrimSpace(flagValue) == "" {
			return "", agentVaultSourceFlag, fmt.Errorf(
				"--session-token was given but is empty; pass a session token from the dashboard, or drop the flag and set %s", agentVaultSessionTokenEnv)
		}
		return strings.TrimSpace(flagValue), agentVaultSourceFlag, nil
	}
	if token = strings.TrimSpace(os.Getenv(agentVaultSessionTokenEnv)); token != "" {
		return token, agentVaultSourceEnv, nil
	}
	return "", agentVaultSourceNone, nil
}

// The variable names one bundle; the flag stays repeatable so that passing it twice is still rejected
// by name rather than silently taking the last one.
func resolveAgentVaultAccessBundles(cmd *cobra.Command) (bundles []string, source agentVaultSource, err error) {
	if cmd.Flags().Changed("access-bundle") {
		values, err := cmd.Flags().GetStringArray("access-bundle")
		if err != nil {
			return nil, agentVaultSourceNone, err
		}
		if bundles = nonBlank(values); len(bundles) == 0 {
			return nil, agentVaultSourceFlag, errAgentVaultEmptyAccessBundle()
		}
		return bundles, agentVaultSourceFlag, nil
	}
	if name := strings.TrimSpace(os.Getenv(agentVaultAccessBundleEnv)); name != "" {
		return []string{name}, agentVaultSourceEnv, nil
	}
	return nil, agentVaultSourceNone, nil
}

// A session comes either from a token or from a bundle to mint over, never both. A flag beats a
// variable; two variables with no flag is a tie this refuses to break, since neither was typed for
// this run and guessing wrong is invisible.
func decideAgentVaultSession(tokenSource, bundleSource agentVaultSource) (useToken bool, warning string, err error) {
	switch {
	case tokenSource == agentVaultSourceNone && bundleSource == agentVaultSourceNone:
		return false, "", fmt.Errorf(
			"a session is required; pass --access-bundle <name> to mint one (or set %s), or --session-token <session token> from the dashboard (or set %s)",
			agentVaultAccessBundleEnv, agentVaultSessionTokenEnv)
	case bundleSource == agentVaultSourceNone:
		return true, "", nil
	case tokenSource == agentVaultSourceNone:
		return false, "", nil
	case tokenSource == agentVaultSourceFlag && bundleSource == agentVaultSourceFlag:
		return false, "", fmt.Errorf("--access-bundle and --session-token are two ways to get one session; pass one of them, not both")
	case tokenSource == agentVaultSourceEnv && bundleSource == agentVaultSourceEnv:
		return false, "", fmt.Errorf(
			"%s and %s are both set, and they are two ways to get one session. Unset one, or pass --session-token or --access-bundle to say which you mean",
			agentVaultSessionTokenEnv, agentVaultAccessBundleEnv)
	case tokenSource == agentVaultSourceFlag:
		return true, fmt.Sprintf("%s is set, but --session-token was passed: running on that session and ignoring the bundle in the environment.", agentVaultAccessBundleEnv), nil
	default:
		return false, fmt.Sprintf("%s is set, but --access-bundle was passed: minting a new session and ignoring the token in the environment.", agentVaultSessionTokenEnv), nil
	}
}

// Which of the two spellings of a setting to blame in a message, so an operator who typed no flag is not
// pointed at one.
func agentVaultSourceName(source agentVaultSource, flagName, envName string) string {
	if source == agentVaultSourceEnv {
		return envName
	}
	return flagName
}

// resolveAgentVaultSessionLabel returns the label to send when this command mints a session. A session token names
// a session created in the dashboard, whose label is edited there, so --label alongside one is refused.
func resolveAgentVaultSessionLabel(cmd *cobra.Command, sessionToken string, tokenSource agentVaultSource) (string, error) {
	if sessionToken != "" && cmd.Flags().Changed("label") {
		return "", fmt.Errorf(
			"--label applies to a session this command mints; label the one behind %s in the dashboard. Drop --label, or mint here with --access-bundle",
			agentVaultSourceName(tokenSource, "--session-token", agentVaultSessionTokenEnv))
	}
	label, _ := cmd.Flags().GetString("label")
	return strings.TrimSpace(label), nil
}

// None of these can reach a session minted in the dashboard: its expiry and project were fixed when it was
// created, and this command never revokes it.
func refuseAgentVaultMintOnlyFlags(cmd *cobra.Command, sessionToken string, tokenSource agentVaultSource) error {
	if sessionToken == "" {
		return nil
	}
	tokenName := agentVaultSourceName(tokenSource, "--session-token", agentVaultSessionTokenEnv)
	switch {
	case cmd.Flags().Changed("ttl"):
		return fmt.Errorf(
			"--ttl applies to a session this command mints; the one behind %s was given its lifetime in the dashboard. Drop --ttl, or mint here with --access-bundle", tokenName)
	case cmd.Flags().Changed("keep-session"):
		return fmt.Errorf(
			"--keep-session applies to a session this command mints; the one behind %s is never revoked here. Drop --keep-session, or mint here with --access-bundle", tokenName)
	case cmd.Flags().Changed("project-id"):
		return fmt.Errorf(
			"--project-id applies to a session this command mints; the one behind %s already belongs to a project. Drop --project-id, or mint here with --access-bundle", tokenName)
	}
	return nil
}

func runAgentVaultRun(cmd *cobra.Command, args []string) {
	sessionToken, tokenSource, err := resolveAgentVaultSessionToken(cmd)
	if err != nil {
		util.HandleError(err)
	}
	accessBundles, bundleSource, err := resolveAgentVaultAccessBundles(cmd)
	if err != nil {
		util.HandleError(err)
	}

	useToken, warning, err := decideAgentVaultSession(tokenSource, bundleSource)
	if err != nil {
		util.HandleError(err)
	}
	if warning != "" {
		util.PrintWarning(warning)
	}
	// The discarded side stops being a source, so later messages and the summary only ever name what this
	// run actually used.
	if useToken {
		accessBundles = nil
		bundleSource = agentVaultSourceNone
	} else {
		sessionToken = ""
		tokenSource = agentVaultSourceNone
	}

	if err := validateAgentVaultAccessBundles(accessBundles, bundleSource); err != nil {
		util.HandleError(err)
	}

	skillsDir, noSkills, err := resolveAgentVaultRunSkills(cmd)
	if err != nil {
		util.HandleError(err)
	}

	ttl, _ := cmd.Flags().GetString("ttl")
	label, err := resolveAgentVaultSessionLabel(cmd, sessionToken, tokenSource)
	if err != nil {
		util.HandleError(err)
	}

	if err := refuseAgentVaultMintOnlyFlags(cmd, sessionToken, tokenSource); err != nil {
		util.HandleError(err)
	}

	var project agentVaultProject
	if len(accessBundles) > 0 {
		if project, err = resolveAgentVaultProject(cmd); err != nil {
			util.HandleError(err)
		}
	}

	// Same reasoning as the empty --session-token: "$AV_PROXY" with the variable unset would otherwise fall
	// through to whatever the environment holds, and the session token is sent to that address.
	if flagValue, _ := cmd.Flags().GetString("proxy"); cmd.Flags().Changed("proxy") && strings.TrimSpace(flagValue) == "" {
		util.HandleError(fmt.Errorf("--proxy was given but is empty; pass the address as host:port, or drop the flag and set %s", agentVaultProxyAddressEnv))
	}
	proxyAddr, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "proxy", []string{agentVaultProxyAddressEnv}, "")
	if err != nil {
		util.HandleError(err, "Unable to read --proxy")
	}
	// Trimmed here as well as in the env lookup, so a flag holding only spaces gets the message below
	// rather than a parse error about a space in the host name.
	proxyAddr = strings.TrimSpace(proxyAddr)
	if proxyAddr == "" {
		util.HandleError(fmt.Errorf("the proxy address is required; pass --proxy <host:port> or set INFISICAL_AGENT_VAULT_PROXY_ADDRESS. The same proxy has a different address from every network, so there is no name to look it up by"))
	}
	proxyAddr = trimProxyScheme(proxyAddr)
	if err := validateProxyAddr(proxyAddr); err != nil {
		util.HandleError(err)
	}

	pinnedFingerprint, _ := cmd.Flags().GetString("ca-fingerprint")
	// An empty pin would otherwise run unpinned in silence, and "$AV_PIN" with the variable unset is how
	// the unattended runs the pin exists for would produce one.
	if cmd.Flags().Changed("ca-fingerprint") && strings.TrimSpace(pinnedFingerprint) == "" {
		util.HandleError(fmt.Errorf("--ca-fingerprint was passed with no value. Give it the proxy's fingerprint from Infisical, or drop the flag to run without a pin"))
	}
	noCaTrust, _ := cmd.Flags().GetBool("no-ca-trust")
	keepSession, _ := cmd.Flags().GetBool("keep-session")
	extraNoProxy, _ := cmd.Flags().GetString("no-proxy")

	caResp, err := fetchAgentVaultProxyCa(proxyAddr)
	if err != nil {
		util.HandleError(err, fmt.Sprintf("Unable to reach the Agent Vault proxy at %s. Check the address and that 'infisical agent-vault proxy' is running there", proxyAddr))
	}

	caFile, _ := cmd.Flags().GetString("ca-file")
	if caFile == "" {
		dataDir, dirErr := agentvault.DefaultDataDir()
		if dirErr != nil {
			util.HandleError(dirErr, "Unable to resolve the default data directory; pass --ca-file")
		}
		caFile, err = agentVaultCaFilePath(dataDir, caResp.ProxyID)
		if err != nil {
			util.HandleError(err)
		}
	}
	// The path goes into the agent's environment, and the agent resolves it against its own working directory.
	caFile, err = filepath.Abs(caFile)
	if err != nil {
		util.HandleError(err, "Unable to resolve --ca-file to an absolute path")
	}
	// Only the certificate the fingerprint was taken from is trusted from here on.
	caPEM, servedFingerprint, err := agentVaultCaFingerprint(caResp.Certificate)
	if err != nil {
		util.HandleError(err, "The proxy served a certificate authority that could not be read")
	}
	if pinnedFingerprint != "" && !agentVaultFingerprintsEqual(pinnedFingerprint, servedFingerprint) {
		util.HandleError(fmt.Errorf("the proxy at %s serves a certificate authority with fingerprint %s, not the pinned %s. Nothing was written and the agent was not started. If the proxy's token was rotated, take the new fingerprint from Infisical; otherwise something else is answering at that address", proxyAddr, servedFingerprint, pinnedFingerprint))
	}

	caPath := ""
	if !noCaTrust {
		if err := os.MkdirAll(filepath.Dir(caFile), 0o700); err != nil {
			util.HandleError(err, "Unable to create the directory for the certificate authority file")
		}
		if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
			util.HandleError(err, "Unable to write the certificate authority file")
		}
		caPath = caFile

		// Go binaries such as gh and docker ignore the CA environment variables and read the system trust store,
		// so macOS gets the keychain entry too.
		if runtime.GOOS == "darwin" && isatty.IsTerminal(os.Stdin.Fd()) {
			onPrompt := func() {
				util.PrintWarning("Adding the Agent Vault proxy's certificate authority to your login keychain, so tools that read the system trust store accept it. Approve the macOS prompt, or press Ctrl-C and re-run with --no-ca-trust to skip it.")
			}
			switch installed, terr := ensureAgentVaultCATrusted(caPath, onPrompt); {
			case errors.Is(terr, errAgentVaultTrustTimedOut):
				util.PrintWarning("The keychain prompt went unanswered, so the certificate authority was not added. The agent still runs, and tools that read the system trust store may report a certificate error. Re-run with --no-ca-trust to skip this step.")
			case terr != nil:
				util.PrintWarning(fmt.Sprintf("Unable to add the Agent Vault proxy CA to your login keychain (%v). Most tools will still work, but some may report a certificate error.", terr))
			case installed:
				util.PrintWarning("Added the Agent Vault proxy CA to your login keychain. This is one-time per proxy and persists for future runs.")
			}
		}
	}

	// Minted last, once every file is written and the keychain prompt has been answered: from here to the
	// child starting nothing may exit, or the session outlives the command with no message naming it.
	var minted *api.AgentVaultSession
	if len(accessBundles) > 0 {
		identity := resolveAgentVaultIdentityToken(cmd)
		minted = mintAgentVaultSessionOrExit(identity, project, accessBundles, ttl, label)
		sessionToken = minted.Token

		Telemetry.SetActor(telemetry.IdentityClaimsFromToken(identity))
	}

	Telemetry.CaptureEventAsync("cli-command:agent-vault run", posthog.NewProperties().
		Set("version", util.CLI_VERSION).
		Set("agent", telemetryAgentName(args)).
		Set("platform", runtime.GOOS).
		Set("sessionSource", map[bool]string{true: "access-bundle", false: "token"}[minted != nil]).
		Set("ttl", ttl).
		Set("keepSession", keepSession).
		Set("pinned", pinnedFingerprint != "").
		Set("caTrust", !noCaTrust))

	printAgentVaultRunSummary(proxyAddr, caResp, servedFingerprint, minted, project, tokenSource, bundleSource)

	noBuiltinSkill, _ := cmd.Flags().GetBool("no-agent-vault-skill")
	noMCPServers, _ := cmd.Flags().GetBool("no-mcp-servers")
	sessionClient := func(tunnel *agentVaultSkillsTunnel, proxyTooOld bool) (*agentVaultSkillsClient, error) {
		httpClient, err := newAgentVaultSessionHTTPClient()
		if err != nil {
			return nil, err
		}
		return &agentVaultSkillsClient{
			httpClient:        httpClient,
			sessionToken:      sessionToken,
			retryUnauthorized: minted != nil,
			includeBuiltin:    !noBuiltinSkill,
			tunnel:            tunnel,
			proxyTooOld:       proxyTooOld,
			beforeDirect: func() {
				if minted == nil {
					useAgentVaultSessionTokenDomain()
				}
			},
		}, nil
	}
	var installSkills agentVaultRunProxyStep
	if !noSkills {
		installSkills = func(ctx context.Context, tunnel *agentVaultSkillsTunnel, proxyTooOld bool) {
			skillsClient, clientErr := sessionClient(tunnel, proxyTooOld)
			if clientErr != nil {
				util.PrintWarning(fmt.Sprintf("Starting without skills: %v.", clientErr))
				return
			}
			installAgentVaultRunSkills(ctx, skillsClient, agentvault.InstallOptions{Dir: skillsDir, ForceClaude: agentVaultRunStartsClaude(args)}, !noBuiltinSkill)
		}
	}
	// Claude Code loads MCP servers only when it starts, so the session's are handed to it rather than left for the agent
	// to find.
	var mcpConfigPath string
	removeMCPConfig := func() {}
	var listMCPServers agentVaultRunProxyStep
	if !noMCPServers && agentVaultRunStartsClaude(args) {
		silent, _ := cmd.Flags().GetBool("silent")
		bypassesProxy := agentVaultBypassesProxy(agentVaultRunNoProxy(os.Environ(), extraNoProxy))
		listMCPServers = func(ctx context.Context, tunnel *agentVaultSkillsTunnel, proxyTooOld bool) {
			servicesClient, clientErr := sessionClient(tunnel, proxyTooOld)
			if clientErr != nil {
				util.PrintWarning(fmt.Sprintf("Starting Claude Code without the session's MCP servers: %v.", clientErr))
				return
			}
			if path, remove := agentVaultRunMCPConfig(ctx, servicesClient, bypassesProxy, silent, args[0]); path != "" {
				mcpConfigPath, removeMCPConfig = path, remove
			}
		}
	}
	var agentAPIURL string
	if exitCode, interrupted := runAgentVaultRunStartupStep(
		func(ctx context.Context) {
			agentAPIURL = prepareAgentVaultRunProxy(ctx, proxyAddr, sessionToken, caPEM, minted != nil, installSkills, listMCPServers)
		},
		func(ctx context.Context) {
			revokeAgentVaultRunSession(ctx, cmd, minted, keepSession, "The run was interrupted", true)
		}); interrupted {
		removeMCPConfig()
		os.Exit(exitCode)
	}

	if minted == nil {
		useAgentVaultSessionTokenDomain()
	}
	env := withAgentVaultConnectEnv(
		buildAgentVaultRunEnv(os.Environ(), proxyAddr, sessionToken, caPath, extraNoProxy, agentAPIURL),
		proxyAddr, sessionToken, caPath, config.INFISICAL_URL, cmd.Flags().Changed("domain"))
	if mcpConfigPath != "" {
		args = withAgentVaultMCPConfig(args, mcpConfigPath)
	}
	exitCode := runAgentVaultChild(args, env)
	removeMCPConfig()

	revokeAgentVaultRunSession(context.Background(), cmd, minted, keepSession, "The agent exited", false)
	os.Exit(exitCode)
}

// resolveAgentVaultRunSkills returns the folder to install the session's skills into, empty for
// ~/.agents/skills, and whether --no-skills skips them.
func resolveAgentVaultRunSkills(cmd *cobra.Command) (dir string, skip bool, err error) {
	dir, _ = cmd.Flags().GetString("skills-dir")
	if cmd.Flags().Changed("skills-dir") && strings.TrimSpace(dir) == "" {
		return "", false, fmt.Errorf("--skills-dir was given but is empty; pass a folder, or drop the flag to install into ~/.agents/skills")
	}
	skip, _ = cmd.Flags().GetBool("no-skills")
	if skip && cmd.Flags().Changed("skills-dir") {
		return "", false, fmt.Errorf("--skills-dir was given with --no-skills, which installs no skills; drop one of the two")
	}
	if dir, err = expandAgentVaultHomeDir(dir); err != nil {
		return "", false, err
	}
	return dir, skip, nil
}

// A quoted or flag=value path reaches us with its "~" unexpanded by the shell.
func expandAgentVaultHomeDir(dir string) (string, error) {
	if dir != "~" && !strings.HasPrefix(dir, "~/") && !strings.HasPrefix(dir, "~"+string(filepath.Separator)) {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("unable to expand ~ in --skills-dir: %w", err)
	}
	return filepath.Join(home, dir[1:]), nil
}

func agentVaultRunStartsClaude(args []string) bool {
	switch telemetryAgentName(args) {
	case "claude", "claude.exe", "claude.cmd", "claude.bat":
		return true
	}
	return false
}

// runAgentVaultRunStartupStep runs prepare, which talks to the proxy and installs skills before the agent starts. The
// signals are the ones the agent step forwards to the agent; when one interrupts the step, onInterrupt runs with a
// context that a second signal cancels, and the step returns the exit code a shell reports for the last signal received.
func runAgentVaultRunStartupStep(prepare func(context.Context), onInterrupt func(context.Context)) (exitCode int, interrupted bool) {
	interruptCtx, abortCtx, stopSignals := notifyAgentVaultTerminationSignals()
	interrupted = prepareAgentVaultRunStartup(interruptCtx, prepare, func() { onInterrupt(abortCtx) })
	stopSignals()
	if !interrupted {
		return 0, false
	}
	for _, ctx := range []context.Context{abortCtx, interruptCtx} {
		var received agentVaultReceivedSignal
		if errors.As(context.Cause(ctx), &received) {
			return agentVaultSignalExitCode(received.signal), true
		}
	}
	return agentVaultSignalExitCode(os.Interrupt), true
}

type agentVaultReceivedSignal struct{ signal os.Signal }

func (r agentVaultReceivedSignal) Error() string { return "received " + r.signal.String() }

// notifyAgentVaultTerminationSignals cancels interruptCtx on the first termination signal and abortCtx on the
// second. Signals stay caught until stop so that a second Ctrl-C during the revoke cuts it short with its warning
// instead of killing the process silently; a third gets the default handling.
func notifyAgentVaultTerminationSignals() (interruptCtx, abortCtx context.Context, stop func()) {
	interruptCtx, cancelInterrupt := context.WithCancelCause(context.Background())
	abortCtx, cancelAbort := context.WithCancelCause(context.Background())
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	done := make(chan struct{})
	go func() {
		for _, cancel := range []context.CancelCauseFunc{cancelInterrupt, cancelAbort} {
			select {
			case sig := <-sigCh:
				cancel(agentVaultReceivedSignal{signal: sig})
			case <-done:
				return
			}
		}
		signal.Stop(sigCh)
	}()
	var once sync.Once
	return interruptCtx, abortCtx, func() {
		once.Do(func() {
			signal.Stop(sigCh)
			close(done)
		})
	}
}

func agentVaultSignalExitCode(sig os.Signal) int {
	if s, ok := sig.(syscall.Signal); ok {
		return 128 + int(s)
	}
	return 128 + int(syscall.SIGINT)
}

func revokeAgentVaultRunSession(parent context.Context, cmd *cobra.Command, minted *api.AgentVaultSession, keepSession bool, event string, interrupted bool) {
	if minted == nil || keepSession {
		return
	}
	timeout, loginPolicy := agentVaultExitRevokeTimeout, util.DefaultRetryPolicy()
	if interrupted {
		timeout, loginPolicy = agentVaultInterruptRevokeTimeout, util.BestEffortRetryPolicy()
	}
	// Never resolve the identity the usual way here: a long run would exit on the expiry check, or open the
	// login wizard on a terminal nobody is watching.
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	httpClient, clientErr := util.GetRestyClientWithCustomHeaders()
	token, tokenErr := revocationToken(ctx, cmd, loginPolicy)
	switch {
	case clientErr != nil || tokenErr != nil:
		util.PrintWarning(fmt.Sprintf(
			"%s but its session could not be revoked (%v). Revoke it in Infisical.",
			event, cmp.Or(clientErr, tokenErr)))
	default:
		httpClient.SetAuthToken(token)
		if revokeErr := api.CallRevokeAgentVaultSession(ctx, httpClient, minted.ID); revokeErr != nil {
			util.PrintWarning(fmt.Sprintf("%s but its session could not be revoked (%v). Revoke it in Infisical.", event, revokeErr))
		} else {
			fmt.Fprintln(os.Stderr, color.HiBlackString("session revoked"))
		}
	}
}

func revocationToken(ctx context.Context, cmd *cobra.Command, loginPolicy util.RetryPolicy) (string, error) {
	clientID, _ := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "client-id", []string{util.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME}, "")
	clientSecret, _ := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "client-secret", []string{util.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET_NAME}, "")
	if clientID != "" && clientSecret != "" {
		httpClient, err := util.GetRestyClientWithPolicy(loginPolicy)
		if err != nil {
			return "", err
		}
		// CallUniversalAuthLogin takes no context, and a login that never answers would hold an exiting run open.
		httpClient.OnBeforeRequest(func(_ *resty.Client, req *resty.Request) error {
			req.SetContext(ctx)
			return nil
		})
		loginResp, err := api.CallUniversalAuthLogin(httpClient, api.UniversalAuthLoginRequest{ClientId: clientID, ClientSecret: clientSecret})
		if err != nil {
			return "", err
		}
		return loginResp.AccessToken, nil
	}

	for _, name := range []string{util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME, util.INFISICAL_TOKEN_NAME} {
		if token := os.Getenv(name); token != "" {
			return token, nil
		}
	}

	details, err := util.GetCurrentLoggedInUserDetails(true)
	if err != nil {
		return "", err
	}
	if !details.IsUserLoggedIn || details.LoginExpired || details.UserCredentials.JTWToken == "" {
		return "", errors.New("your Infisical login is no longer valid")
	}
	return details.UserCredentials.JTWToken, nil
}

func resolveAgentVaultIdentityToken(cmd *cobra.Command) string {
	return resolveAgentVaultIdentity(cmd, true)
}

// Without the wizard, an expired or missing login is an error rather than an interactive sign-in, for a command
// whose output is being captured and so has nobody watching its prompts.
func resolveAgentVaultIdentity(cmd *cobra.Command, allowLoginWizard bool) string {
	clientID, _ := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "client-id", []string{util.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME}, "")
	clientSecret, _ := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "client-secret", []string{util.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET_NAME}, "")
	if clientID != "" && clientSecret != "" {
		loginResp, err := util.UniversalAuthLogin(clientID, clientSecret)
		if err != nil {
			util.HandleError(err, "Failed to authenticate the machine identity")
		}
		return loginResp.AccessToken
	}

	for _, name := range []string{util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME, util.INFISICAL_TOKEN_NAME} {
		if token := os.Getenv(name); token != "" {
			failIfTokenExpired(token, fmt.Sprintf("the %s token", name))
			return token
		}
	}

	details, err := util.GetCurrentLoggedInUserDetails(true)
	if err = agentVaultLoginReadError(err); err != nil {
		util.HandleError(err, "Unable to read your Infisical login")
	}
	if !details.IsUserLoggedIn || details.LoginExpired {
		if !allowLoginWizard {
			util.HandleError(fmt.Errorf("your Infisical login has expired or is missing, and this command's output is being captured, so it can't sign you in. Run 'infisical login' first, set %s, or pass --client-id and --client-secret", util.INFISICAL_TOKEN_NAME))
		}
		details = util.EstablishUserLoginSession()
	}
	if details.UserCredentials.JTWToken == "" {
		util.HandleError(fmt.Errorf("could not resolve your Infisical login; run 'infisical login', set %s, or pass --client-id and --client-secret", util.INFISICAL_TOKEN_NAME))
	}
	failIfTokenExpired(details.UserCredentials.JTWToken, "your login")
	return details.UserCredentials.JTWToken
}

// A login missing from the keyring is a missing login, which signing in fixes. Any other error (a broken config
// file, an unreadable keyring, a profile for another domain) would not be fixed by the wizard, so it is shown.
func agentVaultLoginReadError(err error) error {
	if err == nil || errors.Is(err, util.ErrUserNotLoggedIn) {
		return nil
	}
	return err
}

// Windows resolves variable names case-insensitively, so os.Getenv finds a lowercase spelling and the run
// uses it, while an exact match here would hand that same spelling to the agent.
func isAgentVaultSessionTokenKey(key string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(key, agentVaultSessionTokenEnv)
	}
	return key == agentVaultSessionTokenEnv
}

// The parent's environment, with stale proxy settings replaced by ours and the CA-trust variables added.
//
// Only one variable is removed, and not to keep a secret from the agent. This command does not sandbox it,
// so on a workstation it runs as the operator and can read the stored login regardless of its environment.
// In a container the identity credentials may exist only in the environment, but there they belong to a
// machine identity granted the one bundle the agent was started on, so a session it mints for itself
// reaches no further than the one it was given. Those credentials, the bundle name and the domain are
// inherited on purpose.
//
// The session token variable is the exception, because the agent could run on that session instead of this
// run's:
//
//	INFISICAL_AGENT_VAULT_SESSION_TOKEN=agv_old   # this morning's session, wider bundle
//	infisical agent-vault run --access-bundle code-review --proxy ... -- claude
//
// That run mints a narrow session and prints that it is ignoring agv_old, then without this would hand
// agv_old to the agent anyway. The same happens with --session-token agv_new while the variable still holds
// agv_old. So it is dropped whenever it names a session other than the one being handed over, and kept when
// it names that same session, where the agent already has it as the proxy password.
//
// 'secrets agent-proxy run' strips a longer list because its agent is sandboxed and cannot read those
// credentials back from disk.
// agentVaultRunNoProxy is the agent's NO_PROXY: the operator's own entries and --no-proxy, merged with the ones every
// run needs.
func agentVaultRunNoProxy(parent []string, extraNoProxy string) string {
	var operatorNoProxy []string
	for _, kv := range parent {
		if key, value, ok := strings.Cut(kv, "="); ok && (key == "NO_PROXY" || key == "no_proxy") {
			operatorNoProxy = append(operatorNoProxy, value)
		}
	}
	return mergeNoProxy(append(operatorNoProxy, extraNoProxy)...)
}

func buildAgentVaultRunEnv(parent []string, proxyAddr, sessionToken, caPath, extraNoProxy, apiURL string) []string {
	// The URL is the proxy's to name, so a value from the environment never reaches the agent in its place.
	stale := map[string]bool{agentvault.URLEnv: true}
	for _, k := range proxyEnvKeys {
		stale[k] = true
	}

	env := map[string]string{}
	for _, kv := range parent {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		if parts[0] == "NO_PROXY" || parts[0] == "no_proxy" {
			continue
		}
		if isAgentVaultSessionTokenKey(parts[0]) && parts[1] != sessionToken {
			continue
		}
		if !stale[parts[0]] {
			env[parts[0]] = parts[1]
		}
	}

	setProxyEnv(env, agentVaultProxyURL(proxyAddr, sessionToken), agentVaultRunNoProxy(parent, extraNoProxy))
	// Through the proxy like any request, so the session comes from the tunnel and the agent never handles its token.
	if infisicalURL := agentvault.InfisicalURL(apiURL); infisicalURL != "" {
		env[agentvault.URLEnv] = infisicalURL
	}

	if caPath != "" {
		for _, k := range caTrustEnvVars {
			env[k] = caPath
		}
	}

	result := make([]string, 0, len(env))
	for k, v := range env {
		result = append(result, fmt.Sprintf("%s=%s", k, v))
	}
	return result
}

// url.Parse is no use here: the documented input is a bare host:port, which it either rejects outright
// or reads as a scheme with an empty host. A scheme is accepted anyway because people paste one.
// The address goes into the agent's proxy URL with the session token as the password, so anything that is
// not a bare host and port reaches the agent as a malformed URL, and curl prints that URL, token included.
func validateProxyAddr(addr string) error {
	return validateProxyAddrFrom(addr, "--proxy")
}

// source is where the address came from (a flag or a variable), so the error names what to fix.
func validateProxyAddrFrom(addr, source string) error {
	if strings.ContainsAny(addr, "/?#") {
		return fmt.Errorf("%s must be host:port with nothing after the port, such as 10.0.1.5:17323, got %q", source, addr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || strings.ContainsAny(host, " \t@") {
		return fmt.Errorf("%s must be host:port, such as 10.0.1.5:17323, got %q", source, addr)
	}
	if n, convErr := strconv.Atoi(port); convErr != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%s must name a port between 1 and 65535, got %q", source, addr)
	}
	return nil
}

func trimProxyScheme(addr string) string {
	for _, scheme := range []string{"http://", "https://"} {
		if len(addr) >= len(scheme) && strings.EqualFold(addr[:len(scheme)], scheme) {
			return addr[len(scheme):]
		}
	}
	return addr
}

// Both halves have to be filled or undici, urllib, requests and libcurl send no credentials at all and
// every CONNECT comes back 407, while git refuses to start and asks for a password. The token is the
// password half because tools mask that one and print the username; git names it verbatim in its errors.
func agentVaultProxyURL(proxyAddr, sessionToken string) string {
	u := url.URL{Scheme: "http", User: url.UserPassword(agentvault.ProxyAuthUsername, sessionToken), Host: proxyAddr}
	return u.String()
}

func agentVaultCaFingerprint(certificatePEM string) ([]byte, string, error) {
	block, _ := pem.Decode([]byte(certificatePEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, "", fmt.Errorf("the response did not contain a PEM certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return nil, "", fmt.Errorf("the certificate could not be parsed: %w", err)
	}
	single := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})
	return single, agentvault.FingerprintOf(block.Bytes), nil
}

// What `infisical agent-vault connect` needs when the agent runs it: the session, the proxy, the CA file to trust
// it by, and the Infisical the session belongs to. The token already reaches the agent in HTTPS_PROXY, so naming it
// again exposes nothing new. A domain the operator's environment set is left as it is, unless --domain was passed:
// then the session is on that Infisical, and an inherited one would send the agent's lookups elsewhere.
func withAgentVaultConnectEnv(env []string, proxyAddr, sessionToken, caPath, apiURL string, domainFlag bool) []string {
	set := map[string]string{
		agentVaultSessionTokenEnv: sessionToken,
		agentVaultProxyAddressEnv: proxyAddr,
	}
	// Without a CA file of this run, a stale one from the parent would name another proxy's CA.
	if caPath != "" {
		set[agentVaultCaFileEnv] = caPath
	}
	sameKey := func(a, b string) bool {
		if runtime.GOOS == "windows" {
			return strings.EqualFold(a, b)
		}
		return a == b
	}

	hasDomain := false
	out := make([]string, 0, len(env)+len(set)+1)
	for _, kv := range env {
		key, _, _ := strings.Cut(kv, "=")
		replaced := sameKey(key, agentVaultCaFileEnv)
		for name := range set {
			if sameKey(key, name) {
				replaced = true
			}
		}
		for _, name := range util.DomainEnvNames {
			if sameKey(key, name) {
				if domainFlag && apiURL != "" {
					replaced = true
				} else {
					hasDomain = true
				}
			}
		}
		if !replaced {
			out = append(out, kv)
		}
	}
	for name, value := range set {
		out = append(out, name+"="+value)
	}
	if !hasDomain && apiURL != "" {
		out = append(out, util.INFISICAL_DOMAIN_ENV_NAME+"="+strings.TrimSuffix(apiURL, "/api"))
	}
	return out
}

func agentVaultFingerprintsEqual(a, b string) bool {
	normalize := func(s string) string {
		s = strings.TrimSpace(s)
		s = strings.TrimPrefix(strings.ToUpper(s), "SHA256:")
		return strings.ReplaceAll(s, ":", "")
	}
	return normalize(a) != "" && normalize(a) == normalize(b)
}

func printAgentVaultRunSummary(proxyAddr string, ca agentVaultProxyCa, fingerprint string, minted *api.AgentVaultSession, project agentVaultProject, tokenSource, bundleSource agentVaultSource) {
	dim := color.HiBlackString
	fmt.Fprintln(os.Stderr, color.GreenString("Starting agent behind Agent Vault proxy %q at %s", ca.Name, proxyAddr))
	fmt.Fprintln(os.Stderr, dim("proxy CA fingerprint: "+fingerprint))
	// A flag was typed and needs no echo. A variable is ambient, so the run says which session it picked up.
	if tokenSource == agentVaultSourceEnv {
		fmt.Fprintln(os.Stderr, dim("session from "+agentVaultSessionTokenEnv))
	}
	if bundleSource == agentVaultSourceEnv {
		fmt.Fprintln(os.Stderr, dim("access bundle from "+agentVaultAccessBundleEnv))
	}
	if minted != nil {
		fmt.Fprintln(os.Stderr, dim(fmt.Sprintf("Agent Vault project %s from %s", project.ID, project.Source)))
		expiry := "never"
		if minted.ExpiresAt != nil {
			expiry = *minted.ExpiresAt
		}
		fmt.Fprintln(os.Stderr, dim("session expires: "+expiry))
	}

}

// os.Exit here would skip the session revoke.
func runAgentVaultChild(args, env []string) int {
	// #nosec G204 -- the command is provided directly by the operator running the CLI
	proc := exec.Command(args[0], args[1:]...)
	proc.Stdin = os.Stdin
	proc.Stdout = os.Stdout
	proc.Stderr = os.Stderr
	proc.Env = env

	if err := proc.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start the agent process: %v\n", err)
		return 1
	}

	stopForwarding := sandbox.ForwardTerminationSignals(proc)
	err := proc.Wait()
	stopForwarding()
	if err == nil {
		return 0
	}
	code, ok := sandbox.WaitExitCode(err)
	if !ok {
		fmt.Fprintf(os.Stderr, "agent process error: %v\n", err)
	}
	return code
}

func init() {
	agentVaultRunCmd.Flags().StringArray("access-bundle", nil, "mint a session over the access bundle with this `name` (falls back to "+agentVaultAccessBundleEnv+")")
	agentVaultRunCmd.Flags().String("session-token", "", "run with a session token minted in the dashboard instead of minting one (falls back to "+agentVaultSessionTokenEnv+")")
	agentVaultRunCmd.Flags().String("ttl", "never", "lifetime of the session this command creates: one number and one unit, such as 30m, 8h or 7d (not 2h30m), or never")
	agentVaultRunCmd.Flags().Bool("keep-session", false, "leave a minted session active when the agent exits")
	agentVaultRunCmd.Flags().String("project-id", "", "Agent Vault project of the access bundle to mint over (falls back to "+agentVaultProjectIDEnv+", then INFISICAL_PROJECT_ID)")
	agentVaultRunCmd.Flags().String("label", "", "describe what the session this command creates is for (up to 128 characters)")
	agentVaultRunCmd.Flags().String("proxy", "", "address of the Agent Vault proxy as host:port (falls back to "+agentVaultProxyAddressEnv+")")
	agentVaultRunCmd.Flags().String("ca-fingerprint", "", "abort unless the proxy's certificate authority matches this SHA256 fingerprint from Infisical")
	agentVaultRunCmd.Flags().String("no-proxy", "", "additional comma-separated hosts to bypass the proxy (always merged with localhost,127.0.0.1)")
	agentVaultRunCmd.Flags().String("ca-file", "", "where to write the certificate authority fetched from the proxy; an output path, not a CA to trust (default: "+filepath.Join(defaultDataDirHelp(), "ca-<proxy-id>.pem")+")")
	agentVaultRunCmd.Flags().Bool("no-ca-trust", false, "skip writing the certificate authority and setting the trust variables, for a host that already trusts this proxy's CA (a pinned fingerprint is still checked)")
	agentVaultRunCmd.Flags().String("skills-dir", "", "install the session's skills into this `folder` instead of ~/.agents/skills, without linking them for Claude Code or Hermes")
	agentVaultRunCmd.Flags().Bool("no-skills", false, "start the agent without installing the session's skills")
	agentVaultRunCmd.Flags().Bool("no-agent-vault-skill", false, "skip the built-in "+agentvault.BuiltinSkillName+" skill, which tells the agent how to work behind the proxy (--no-skills skips it too)")
	agentVaultRunCmd.Flags().Bool("no-mcp-servers", false, "don't add the session's MCP servers to Claude Code with --mcp-config")
	agentVaultRunCmd.Flags().String("client-id", "", "universal auth client id of the machine identity that mints the session (falls back to INFISICAL_UNIVERSAL_AUTH_CLIENT_ID)")
	agentVaultRunCmd.Flags().String("client-secret", "", "universal auth client secret of that machine identity (falls back to INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET)")

	agentVaultCmd.AddCommand(agentVaultRunCmd)
}
