package cmd

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/telemetry"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	"github.com/mattn/go-isatty"
	"github.com/posthog/posthog-go"
	"github.com/spf13/cobra"
)

var agentVaultSessionsCmd = &cobra.Command{
	Use:   "sessions",
	Short: "Create and revoke Agent Vault sessions",
}

var agentVaultSessionsCreateCmd = &cobra.Command{
	Use:   "create --access-bundle <name>",
	Short: "Create a session over an access bundle and print its token",
	Long: `Create a session over an access bundle and print its token.

The session belongs to the Agent Vault project from --project-id, or else INFISICAL_AGENT_VAULT_PROJECT_ID,
agent-vault.project-id in .infisical.yaml, or INFISICAL_PROJECT_ID, in that order.

Only the token is printed, so it can be captured into a variable. Pass -o json or -o yaml for the session's
ID, project, access bundle, label and expiry as well. The session stays active until it expires or you revoke
it with 'infisical agent-vault sessions revoke'.`,
	Example: `  export INFISICAL_AGENT_VAULT_SESSION_TOKEN=$(infisical agent-vault sessions create --access-bundle coding-agent --ttl 8h)
  infisical agent-vault sessions create --project-id 4f0c... --access-bundle coding-agent --label "nightly deploy" -o json`,
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run:                   runAgentVaultSessionsCreate,
}

type agentVaultSessionOutput struct {
	ID           string  `json:"id"`
	Token        string  `json:"token"`
	ProjectID    string  `json:"projectId"`
	AccessBundle string  `json:"accessBundle"`
	Label        *string `json:"label"`
	ExpiresAt    *string `json:"expiresAt"`
}

func runAgentVaultSessionsCreate(cmd *cobra.Command, args []string) {
	outputFormat, err := cmd.Flags().GetString("output")
	if err != nil {
		util.HandleError(err, "Unable to read --output")
	}
	// Checked before the session exists, so a typo never leaves one behind with its token unprinted.
	if outputFormat != "" && outputFormat != util.OUTPUT_FORMAT_JSON && outputFormat != util.OUTPUT_FORMAT_YAML {
		util.HandleError(fmt.Errorf("--output must be json or yaml, got %q; leave it out to print only the token", outputFormat))
	}

	accessBundles, bundleSource, err := resolveAgentVaultAccessBundles(cmd)
	if err != nil {
		util.HandleError(err)
	}
	if bundleSource == agentVaultSourceNone {
		util.HandleError(fmt.Errorf("an access bundle is required; pass --access-bundle <name> or set %s", agentVaultAccessBundleEnv))
	}
	if err := validateAgentVaultAccessBundles(accessBundles, bundleSource); err != nil {
		util.HandleError(err)
	}

	project, err := resolveAgentVaultProject(cmd)
	if err != nil {
		util.HandleError(err)
	}
	echoAgentVaultProject(project)

	ttl, _ := cmd.Flags().GetString("ttl")
	label, _ := cmd.Flags().GetString("label")
	label = strings.TrimSpace(label)

	stdoutIsTerminal := isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
	identity := resolveAgentVaultIdentity(cmd, stdoutIsTerminal)
	minted := mintAgentVaultSessionOrExit(identity, project, accessBundles, ttl, label)

	Telemetry.SetActor(telemetry.IdentityClaimsFromToken(identity))
	Telemetry.CaptureEvent("cli-command:agent-vault sessions create", posthog.NewProperties().
		Set("version", util.CLI_VERSION).
		Set("platform", runtime.GOOS).
		Set("ttl", ttl).
		Set("labeled", label != "").
		Set("projectSource", agentVaultProjectSourceKind(project)).
		Set("output", outputFormat))

	if outputFormat == "" {
		fmt.Println(minted.Token)
		return
	}
	formatted, err := util.FormatOutput(outputFormat, agentVaultSessionOutputFrom(*minted, project, accessBundles[0]), nil)
	if err != nil {
		util.HandleError(err, "Unable to format the session")
	}
	fmt.Println(strings.TrimRight(formatted, "\n"))
}

func agentVaultSessionOutputFrom(minted api.AgentVaultSession, project agentVaultProject, accessBundle string) agentVaultSessionOutput {
	out := agentVaultSessionOutput{
		ID:           minted.ID,
		Token:        minted.Token,
		ProjectID:    cmp.Or(minted.ProjectID, project.ID),
		AccessBundle: accessBundle,
		Label:        minted.Label,
		ExpiresAt:    minted.ExpiresAt,
	}
	if len(minted.AccessBundles) > 0 {
		out.AccessBundle = minted.AccessBundles[0].Name
	}
	return out
}

var agentVaultSessionsRevokeCmd = &cobra.Command{
	Use:   "revoke [session-id]",
	Short: "Revoke a session by its ID or its token",
	Long: `Revoke a session by its ID or its token.

By ID, the session is revoked as you, or as the machine identity from --client-id and --client-secret, which
needs access to it. By --session-token, the session token alone is enough: whoever holds it can end the session.
Revoking a session that has already ended succeeds.`,
	Example: `  infisical agent-vault sessions revoke 0b6f3a1e-...
  infisical agent-vault sessions revoke --session-token "$INFISICAL_AGENT_VAULT_SESSION_TOKEN"`,
	DisableFlagsInUseLine: true,
	Args:                  cobra.MaximumNArgs(1),
	Run:                   runAgentVaultSessionsRevoke,
}

func runAgentVaultSessionsRevoke(cmd *cobra.Command, args []string) {
	token, _ := cmd.Flags().GetString("session-token")
	if err := validateAgentVaultRevokeTarget(args, cmd.Flags().Changed("session-token"), token); err != nil {
		util.HandleError(err)
	}

	httpClient, err := util.GetRestyClientWithCustomHeaders()
	if err != nil {
		util.HandleError(err, "Failed to build the API client")
	}

	byToken := len(args) == 0
	var sessionID string
	if byToken {
		sessionID, err = revokeAgentVaultSessionByToken(httpClient, strings.TrimSpace(token))
		if err != nil {
			var apiErr *api.APIError
			if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized {
				util.HandleError(err, "Infisical does not recognize this session token. Check that it was copied whole")
			}
			util.HandleError(err, "Unable to revoke the session")
		}
	} else {
		sessionID = args[0]
		identity := resolveAgentVaultIdentityToken(cmd)
		httpClient.SetAuthToken(identity)
		if err := api.CallRevokeAgentVaultSession(context.Background(), httpClient, sessionID); err != nil {
			util.HandleError(err, "Unable to revoke the session")
		}
		Telemetry.SetActor(telemetry.IdentityClaimsFromToken(identity))
	}

	Telemetry.CaptureEvent("cli-command:agent-vault sessions revoke", posthog.NewProperties().
		Set("version", util.CLI_VERSION).
		Set("platform", runtime.GOOS).
		Set("by", map[bool]string{true: "token", false: "id"}[byToken]))

	fmt.Printf("Session %s is revoked\n", sessionID)
}

func validateAgentVaultRevokeTarget(args []string, tokenGiven bool, token string) error {
	switch {
	case len(args) == 1 && tokenGiven:
		return errors.New("pass a session ID or --session-token, not both")
	case len(args) == 1:
		if _, err := uuid.Parse(args[0]); err != nil || len(args[0]) != 36 {
			return fmt.Errorf("%q is not a session ID; pass the ID shown on the session in Infisical, or revoke by --session-token", args[0])
		}
		return nil
	case !tokenGiven:
		return errors.New("name the session to revoke: pass its ID, or --session-token with its session token")
	case strings.TrimSpace(token) == "":
		return errors.New("--session-token was given but is empty; pass the session token, or pass the session's ID instead")
	default:
		return nil
	}
}

func revokeAgentVaultSessionByToken(httpClient *resty.Client, token string) (string, error) {
	res, err := api.CallRevokeAgentVaultSessionByToken(context.Background(), httpClient, token)
	if err != nil {
		return "", err
	}
	return res.Session.ID, nil
}

// The variable names one bundle and the flag is repeatable only so that passing it twice is refused by name.
func validateAgentVaultAccessBundles(bundles []string, source agentVaultSource) error {
	if len(bundles) > 1 {
		return errors.New("a session carries one access bundle; pass --access-bundle once")
	}
	for _, name := range bundles {
		if !agentVaultBundleNameRe.MatchString(name) {
			return fmt.Errorf("%q from %s is not an access bundle name; names are lowercase letters, numbers and hyphens, for example 'coding-agent'",
				name, agentVaultSourceName(source, "--access-bundle", agentVaultAccessBundleEnv))
		}
	}
	return nil
}

func mintAgentVaultSession(httpClient *resty.Client, project agentVaultProject, accessBundles []string, ttl, label string) (api.AgentVaultSession, error) {
	created, err := api.CallCreateAgentVaultSession(httpClient, api.CreateAgentVaultSessionRequest{
		ProjectID:     project.ID,
		AccessBundles: accessBundles,
		TTL:           ttl,
		Label:         label,
	})
	if err != nil {
		return api.AgentVaultSession{}, err
	}
	return created.Session, nil
}

func mintAgentVaultSessionOrExit(identity string, project agentVaultProject, accessBundles []string, ttl, label string) *api.AgentVaultSession {
	httpClient, err := util.GetRestyClientWithCustomHeaders()
	if err != nil {
		util.HandleError(err, "Failed to build the API client")
	}
	httpClient.SetAuthToken(identity)

	minted, err := mintAgentVaultSession(httpClient, project, accessBundles, ttl, label)
	if err != nil {
		util.HandleError(err, append([]string{"Unable to mint an Agent Vault session"}, agentVaultProjectHints(err, project)...)...)
	}
	return &minted
}

func init() {
	agentVaultSessionsCreateCmd.Flags().String("project-id", "", "Agent Vault project to create the session in (falls back to "+agentVaultProjectIDEnv+", then agent-vault.project-id in .infisical.yaml, then INFISICAL_PROJECT_ID)")
	agentVaultSessionsCreateCmd.Flags().StringArray("access-bundle", nil, "create the session over the access bundle with this `name` (falls back to "+agentVaultAccessBundleEnv+")")
	agentVaultSessionsCreateCmd.Flags().String("ttl", "never", "lifetime of the session: one number and one unit, such as 30m, 8h or 7d (not 2h30m), or never")
	agentVaultSessionsCreateCmd.Flags().String("label", "", "describe what the session is for (up to 128 characters)")
	agentVaultSessionsCreateCmd.Flags().String("client-id", "", "universal auth client id of the machine identity that creates the session (falls back to INFISICAL_UNIVERSAL_AUTH_CLIENT_ID)")
	agentVaultSessionsCreateCmd.Flags().String("client-secret", "", "universal auth client secret of that machine identity (falls back to INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET)")
	agentVaultSessionsCreateCmd.Flags().StringP("output", "o", "", "print the session's ID, token, project, access bundle, label and expiry as json or yaml, instead of only its token")

	agentVaultSessionsRevokeCmd.Flags().String("session-token", "", "revoke the session this session token belongs to, instead of naming it by ID")
	agentVaultSessionsRevokeCmd.Flags().String("client-id", "", "universal auth client id of the machine identity to revoke as (falls back to INFISICAL_UNIVERSAL_AUTH_CLIENT_ID)")
	agentVaultSessionsRevokeCmd.Flags().String("client-secret", "", "universal auth client secret of that machine identity (falls back to INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET)")

	agentVaultSessionsCmd.AddCommand(agentVaultSessionsCreateCmd)
	agentVaultSessionsCmd.AddCommand(agentVaultSessionsRevokeCmd)
	agentVaultCmd.AddCommand(agentVaultSessionsCmd)
}
