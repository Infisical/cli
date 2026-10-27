package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/agentvault"
	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/fatih/color"
	"github.com/rs/zerolog/log"
)

const (
	// Infisical caps one skill at 1 MB, but not how many a session can reach.
	agentVaultSkillsResponseLimit = 64 << 20
	agentVaultSkillsTimeout       = 30 * time.Second
)

// No client timeout: the skills step has its own deadline, and a response for many skills takes longer
// than the certificate request the shared client is sized for.
var agentVaultSkillsHTTPClient = &http.Client{Transport: &http.Transport{Proxy: nil}}

var errAgentVaultSkillsUnsupported = errors.New("skills unsupported")

type agentVaultSkillsLister interface {
	list(ctx context.Context) (api.AgentVaultProxySkillsResponse, error)
}

type agentVaultSkillsClient struct {
	proxyAddr    string
	sessionToken string
	httpClient   *http.Client
}

func (c *agentVaultSkillsClient) list(ctx context.Context) (api.AgentVaultProxySkillsResponse, error) {
	var out api.AgentVaultProxySkillsResponse
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://%s%s", c.proxyAddr, agentvault.SkillsPath), nil)
	if err != nil {
		return out, err
	}
	req.Header.Set("User-Agent", api.USER_AGENT)
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString(
		[]byte(agentvault.ProxyAuthUsername+":"+c.sessionToken)))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusNotImplemented:
		return out, errAgentVaultSkillsUnsupported
	case http.StatusForbidden:
		return out, errors.New("the proxy reports the session is no longer valid")
	case http.StatusProxyAuthRequired:
		return out, errors.New("the proxy did not accept the session token")
	case http.StatusServiceUnavailable:
		return out, errors.New("the proxy's own token was rejected by Infisical")
	case http.StatusBadGateway:
		return out, errors.New("the proxy could not fetch them from Infisical")
	default:
		return out, fmt.Errorf("the proxy answered %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, agentVaultSkillsResponseLimit)).Decode(&out); err != nil {
		return out, fmt.Errorf("the proxy's response could not be read: %w", err)
	}
	return out, nil
}

// installAgentVaultRunSkills fetches the session's skills once and installs them before the agent starts. No
// failure here may keep the agent from starting, so each one becomes a single warning.
func installAgentVaultRunSkills(ctx context.Context, skillsDir string, client agentVaultSkillsLister, symlink func(oldname, newname string) error) {
	listed, err := client.list(ctx)
	switch {
	case errors.Is(err, errAgentVaultSkillsUnsupported):
		log.Debug().Msg("agent-vault: the proxy or Infisical does not deliver skills, starting without them")
		return
	case errors.Is(ctx.Err(), context.Canceled):
		return
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		util.PrintWarning(fmt.Sprintf("Starting without skills: the proxy did not send them within %s.", agentVaultSkillsTimeout))
		return
	case err != nil:
		util.PrintWarning(fmt.Sprintf("Starting without skills: %v.", err))
		return
	case len(listed.Skills) == 0:
		return
	}

	result, err := agentvault.InstallSkills(ctx, listed.Skills, agentvault.InstallOptions{Dir: skillsDir, Symlink: symlink})
	if err != nil {
		names := make([]string, 0, len(listed.Skills))
		for _, skill := range listed.Skills {
			names = append(names, skill.Name)
		}
		util.PrintWarning(fmt.Sprintf("Starting without the skills %s: %v.", strings.Join(names, ", "), err))
		return
	}
	if len(result.Failed) > 0 {
		util.PrintWarning(fmt.Sprintf("Starting without these skills: %s", strings.Join(result.Failed, "; ")))
	}
	if len(result.LinkFailed) > 0 {
		util.PrintWarning(fmt.Sprintf("Unable to link these skills: %s", strings.Join(result.LinkFailed, "; ")))
	}
	if result.Installed > 0 {
		fmt.Fprintln(os.Stderr, color.HiBlackString(agentVaultSkillsInstalledLine(result)))
	}
}

func agentVaultSkillsInstalledLine(result agentvault.InstallResult) string {
	noun := "skills"
	if result.Installed == 1 {
		noun = "skill"
	}
	line := fmt.Sprintf("Installed %d %s in %s", result.Installed, noun, result.Dir)
	if len(result.Linked) > 0 {
		line += fmt.Sprintf(" (linked for %s)", strings.Join(result.Linked, " and "))
	}
	return line + "."
}

// prepareAgentVaultRunSkills runs the skills step under its deadline, with ctx cancelled by Ctrl-C or SIGTERM.
// When the operator interrupts it, onInterrupt revokes the session, the same as when the agent exits;
// interrupted then tells the caller to exit without starting the agent. stopSignals runs first so that a
// second Ctrl-C during the revoke ends the process instead of being swallowed.
func prepareAgentVaultRunSkills(ctx context.Context, install func(context.Context), stopSignals func(), onInterrupt func()) (interrupted bool) {
	stepCtx, cancel := context.WithTimeout(ctx, agentVaultSkillsTimeout)
	defer cancel()
	install(stepCtx)
	if ctx.Err() != nil {
		stopSignals()
		onInterrupt()
		return true
	}
	return false
}
