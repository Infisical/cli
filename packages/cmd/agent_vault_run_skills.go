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

// A variable so tests can shorten it.
var agentVaultSkillsTimeout = 30 * time.Second

// The waits before each retry of a list that answered 401 on a minted run.
var agentVaultSkillsUnauthorizedRetryDelays = []time.Duration{500 * time.Millisecond, time.Second}

// Fastify's own answer for a route it does not have, which is how an Infisical older than skills answers. Some
// versions add documentationUrl and some send Fastify's default body, whose message is "Route GET:<path> not
// found". A NotFoundError thrown by a handler is named "NotFound" and carries neither.
const infisicalRouteMissingName = "Not Found"

func isInfisicalRouteMissing(err error) bool {
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound || apiErr.Name != infisicalRouteMissingName {
		return false
	}
	return apiErr.DocumentationURL != "" ||
		(strings.HasPrefix(apiErr.ErrorMessage, "Route ") && strings.HasSuffix(apiErr.ErrorMessage, " not found"))
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
	// retryUnauthorized is set for a session this run just minted: the read that follows the mint can reach
	// a database replica that has not seen the session yet, which answers 401.
	retryUnauthorized bool
}

func (c *agentVaultSkillsClient) list(ctx context.Context) (api.ListAgentVaultSessionSkillsResponse, error) {
	listed, err := api.CallListAgentVaultSessionSkills(ctx, c.httpClient, c.sessionToken)
	if !c.retryUnauthorized {
		return listed, err
	}
	for _, delay := range agentVaultSkillsUnauthorizedRetryDelays {
		if !isAgentVaultSessionInvalid(err) {
			break
		}
		select {
		case <-ctx.Done():
			return listed, err
		case <-time.After(delay):
		}
		listed, err = api.CallListAgentVaultSessionSkills(ctx, c.httpClient, c.sessionToken)
	}
	return listed, err
}

func agentVaultSessionInvalidWarning(err error) string {
	reason := "the session is no longer valid"
	var apiErr *api.APIError
	if errors.As(err, &apiErr) {
		if message := strings.TrimSuffix(strings.TrimSpace(apiErr.ErrorMessage), "."); message != "" {
			reason = message
		}
	}
	return fmt.Sprintf("Starting without skills: %s.", reason)
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
func installAgentVaultRunSkills(ctx context.Context, client agentVaultSkillsLister, opts agentvault.InstallOptions) {
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
		util.PrintWarning(agentVaultSessionInvalidWarning(err))
		return
	case err != nil:
		util.PrintWarning(fmt.Sprintf("Starting without skills: %s.", agentVaultSkillsFailureReason(err)))
		return
	case len(listed.Skills) == 0:
		return
	}

	result, err := agentvault.InstallSkills(ctx, listed.Skills, opts)
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
		util.PrintWarning(fmt.Sprintf("Unable to link %s.", strings.Join(result.LinkFailed, "; ")))
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
		dirs := make([]string, 0, len(result.Linked))
		for _, linked := range result.Linked {
			dirs = append(dirs, linked.Dir)
		}
		line += fmt.Sprintf(" (linked in %s)", strings.Join(dirs, " and "))
	}
	return line + "."
}

// prepareAgentVaultRunSkills runs the skills step under its deadline, with ctx cancelled by Ctrl-C or another
// termination signal.
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
