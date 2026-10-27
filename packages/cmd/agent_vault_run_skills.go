package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/agentvault"
	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/fatih/color"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

const agentVaultSkillsTimeout = 30 * time.Second

// Fastify's own answer for a route it does not have, which is how an Infisical older than skills answers. A
// NotFoundError thrown by a handler is named "NotFound" and never carries documentationUrl.
const infisicalRouteMissingName = "Not Found"

func isInfisicalRouteMissing(err error) bool {
	var apiErr *api.APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound &&
		apiErr.Name == infisicalRouteMissingName && apiErr.DocumentationURL != ""
}

func isAgentVaultSessionInvalid(err error) bool {
	var apiErr *api.APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized
}

type agentVaultSkillsLister interface {
	list(ctx context.Context) (api.ListAgentVaultSessionSkillsResponse, error)
}

type agentVaultSkillsClient struct {
	httpClient   *resty.Client
	sessionToken string
}

func (c *agentVaultSkillsClient) list(ctx context.Context) (api.ListAgentVaultSessionSkillsResponse, error) {
	return api.CallListAgentVaultSessionSkills(ctx, c.httpClient, c.sessionToken)
}

func agentVaultSkillsFailureReason(err error) string {
	var apiErr *api.APIError
	if errors.As(err, &apiErr) {
		if apiErr.ErrorMessage != "" {
			return fmt.Sprintf("Infisical answered %d: %s", apiErr.StatusCode, apiErr.ErrorMessage)
		}
		return fmt.Sprintf("Infisical answered %d", apiErr.StatusCode)
	}
	return err.Error()
}

// installAgentVaultRunSkills fetches the session's skills once and installs them before the agent starts. No
// failure here may keep the agent from starting, so each one becomes a single warning.
func installAgentVaultRunSkills(ctx context.Context, skillsDir string, client agentVaultSkillsLister, symlink func(oldname, newname string) error) {
	listed, err := client.list(ctx)
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		util.PrintWarning(fmt.Sprintf("Starting without skills: Infisical did not send them within %s.", agentVaultSkillsTimeout))
		return
	case isInfisicalRouteMissing(err):
		log.Debug().Msg("agent-vault: this Infisical does not deliver skills, starting without them")
		return
	case isAgentVaultSessionInvalid(err):
		util.PrintWarning("Starting without skills: the session is no longer valid.")
		return
	case err != nil:
		util.PrintWarning(fmt.Sprintf("Starting without skills: %s.", agentVaultSkillsFailureReason(err)))
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
