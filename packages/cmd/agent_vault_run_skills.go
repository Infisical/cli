package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/agentvault"
	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/fatih/color"
	"github.com/go-resty/resty/v2"
)

// Variables so tests can shorten them.
var (
	agentVaultSkillsTimeout = 30 * time.Second
	// A host that cannot reach Infisical gives up on each connection attempt here, while a slow but reachable
	// Infisical still gets the whole step to send the files.
	agentVaultSkillsConnectTimeout = 5 * time.Second
)

const agentVaultSkillsUnreachableHint = " Pass --no-skills if this host can't reach Infisical."

func newAgentVaultSkillsHTTPClient() (*resty.Client, error) {
	// A busy Infisical (429 or 5xx) is asked again, but a connection that never opens is not, since each
	// attempt would wait out the connect timeout again.
	policy := util.DefaultRetryPolicy()
	policy.StatusOnly = true
	httpClient, err := util.GetRestyClientWithPolicy(policy)
	if err != nil {
		return nil, err
	}
	transport, err := httpClient.Transport()
	if err != nil {
		return nil, err
	}
	transport.DialContext = (&net.Dialer{Timeout: agentVaultSkillsConnectTimeout, KeepAlive: 30 * time.Second}).DialContext
	return httpClient, nil
}

// A session token goes only to a domain the user chose: --domain, the domain variables, or the logged-in
// profile, else US Cloud. A command holding only the token has not loaded the profile, so nothing else would
// point it at the profile's domain.
func useAgentVaultSessionTokenDomain() {
	if !config.INFISICAL_DOMAIN_EXPLICITLY_SET {
		config.INFISICAL_URL = agentVaultSessionTokenAPIURL()
	}
}

func agentVaultSessionTokenAPIURL() string {
	domain := util.ActiveProfileDomain()
	if domain == "" {
		domain = util.INFISICAL_DEFAULT_US_URL
	}
	return util.AppendAPIEndpoint(domain)
}

// The waits before each retry of a list that answered 401 on a minted run.
var agentVaultSkillsUnauthorizedRetryDelays = []time.Duration{500 * time.Millisecond, time.Second}

// Fastify's own answer for a route it does not have, with documentationUrl or with its default message "Route
// GET:<path> not found". A NotFoundError thrown by a handler is named "NotFound" and carries neither.
const infisicalRouteMissingName = "Not Found"

func isInfisicalRouteMissing(err error) bool {
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound || apiErr.Name != infisicalRouteMissingName {
		return false
	}
	return apiErr.DocumentationURL != "" ||
		(strings.HasPrefix(apiErr.ErrorMessage, "Route ") && strings.HasSuffix(apiErr.ErrorMessage, " not found"))
}

// Infisical's 401, or the proxy refusing the session before it forwards the request.
func isAgentVaultSessionInvalid(err error) bool {
	var apiErr *api.APIError
	return errors.As(err, &apiErr) && (apiErr.StatusCode == http.StatusUnauthorized || agentvault.IsSessionRefusal(apiErr.Name))
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
	includeBuiltin    bool
	// Asks the proxy's reserved name, which forwards the request to the proxy's own Infisical, so the agent's host
	// needs to reach only the proxy. Nil asks Infisical directly.
	tunnel *agentVaultSkillsTunnel
	// Runs before the first request that goes to Infisical directly, which only happens behind a proxy too old to
	// forward the request.
	beforeDirect func()
}

func (c *agentVaultSkillsClient) list(ctx context.Context) (api.ListAgentVaultSessionSkillsResponse, error) {
	proxyTooOld := false
	if c.tunnel != nil {
		listed, err := c.retrying(ctx, func() (api.ListAgentVaultSessionSkillsResponse, error) {
			return api.CallListAgentVaultSessionSkillsThroughProxy(ctx, c.tunnel.httpClient, agentVaultReservedAPIURL, c.sessionToken, c.includeBuiltin)
		})
		answered, marked := c.tunnel.outcome()
		if marked || ctx.Err() != nil {
			return listed, err
		}
		proxyTooOld = answered
	}
	if c.beforeDirect != nil {
		c.beforeDirect()
	}
	listed, err := c.retrying(ctx, func() (api.ListAgentVaultSessionSkillsResponse, error) {
		return api.CallListAgentVaultSessionSkills(ctx, c.httpClient, c.sessionToken, c.includeBuiltin)
	})
	if err != nil && proxyTooOld {
		var tunnelProxy string
		if c.tunnel != nil {
			tunnelProxy = c.tunnel.proxyAddr
		}
		return listed, &agentVaultProxyTooOldError{proxyAddr: tunnelProxy, err: err}
	}
	return listed, err
}

const agentVaultReservedAPIURL = "https://" + agentvault.DiscoveryHost + "/api"

// agentVaultSkillsTunnel sends requests through the proxy, trusting only the certificate authority this run verified,
// and remembers how the proxy answered. A proxy that forwards these requests marks every answer, its own and the ones
// it passes on from Infisical. An older proxy doesn't know the reserved name: it refuses the tunnel, or tries to reach
// the name upstream and fails, and marks neither.
type agentVaultSkillsTunnel struct {
	proxyAddr  string
	httpClient *resty.Client

	mu       sync.Mutex
	answered bool
	marked   bool
}

func newAgentVaultSkillsTunnel(proxyAddr, sessionToken string, caPEM []byte) (*agentVaultSkillsTunnel, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("the proxy's certificate authority could not be read")
	}
	tunnel := &agentVaultSkillsTunnel{proxyAddr: proxyAddr}
	proxyURL := &url.URL{Scheme: "http", Host: proxyAddr, User: url.UserPassword(agentvault.ProxyAuthUsername, sessionToken)}
	tunnel.httpClient = resty.NewWithClient(&http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		DialContext:     (&net.Dialer{Timeout: agentVaultSkillsConnectTimeout, KeepAlive: 30 * time.Second}).DialContext,
		// Called before Go checks for a 200, so a refused tunnel is seen too.
		OnProxyConnectResponse: func(_ context.Context, _ *url.URL, _ *http.Request, res *http.Response) error {
			tunnel.note(res.Header)
			return nil
		},
	}})
	tunnel.httpClient.OnAfterResponse(func(_ *resty.Client, res *resty.Response) error {
		tunnel.note(res.Header())
		return nil
	})
	return tunnel, nil
}

func (t *agentVaultSkillsTunnel) note(header http.Header) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.answered = true
	if header.Get(agentvault.HeaderDecision) != "" {
		t.marked = true
	}
}

func (t *agentVaultSkillsTunnel) outcome() (answered, marked bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.answered, t.marked
}

// The proxy was too old to forward the request, and asking Infisical directly failed too.
type agentVaultProxyTooOldError struct {
	proxyAddr string
	err       error
}

func (e *agentVaultProxyTooOldError) Error() string { return e.err.Error() }
func (e *agentVaultProxyTooOldError) Unwrap() error { return e.err }

// The hint for a host that can't reach Infisical. Behind a proxy too old to forward the request, the fix is the proxy.
func agentVaultSkillsUnreachableHintFor(err error) string {
	var tooOld *agentVaultProxyTooOldError
	if errors.As(err, &tooOld) {
		return fmt.Sprintf(" The proxy at %s is too old to pass skills on, so this host asked Infisical directly. Update the Infisical CLI that runs the proxy, or pass --no-skills.", tooOld.proxyAddr)
	}
	return agentVaultSkillsUnreachableHint
}

func (c *agentVaultSkillsClient) retrying(ctx context.Context, fetch func() (api.ListAgentVaultSessionSkillsResponse, error)) (api.ListAgentVaultSessionSkillsResponse, error) {
	listed, err := fetch()
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
		listed, err = fetch()
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
		message := strings.TrimSuffix(strings.TrimSpace(apiErr.ErrorMessage), ".")
		switch {
		// The proxy's own answer names the proxy, so it reads on its own.
		case message != "" && agentvault.IsInfisicalForwardRefusal(apiErr.Name):
			return message
		case message != "":
			return fmt.Sprintf("Infisical answered %d: %s", apiErr.StatusCode, message)
		}
		return fmt.Sprintf("Infisical answered %d", apiErr.StatusCode)
	}
	return err.Error()
}

// installAgentVaultRunSkills fetches the session's skills once and installs them before the agent starts. No
// failure here may keep the agent from starting, so each one becomes a single warning.
func installAgentVaultRunSkills(ctx context.Context, client agentVaultSkillsLister, opts agentvault.InstallOptions, builtin bool) {
	listed, err := client.list(ctx)
	unreachableHint := agentVaultSkillsUnreachableHintFor(err)
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		util.PrintWarning(fmt.Sprintf("Starting without skills: Infisical did not send them within %s.%s", agentVaultSkillsTimeout, unreachableHint))
		return
	case isInfisicalRouteMissing(err):
		util.PrintWarning(fmt.Sprintf("Starting without skills: %s doesn't provide them. Check --domain.", strings.TrimSuffix(config.INFISICAL_URL, "/api")))
		return
	case isAgentVaultSessionInvalid(err):
		util.PrintWarning(agentVaultSessionInvalidWarning(err))
		return
	case err != nil:
		warning := fmt.Sprintf("Starting without skills: %s.", agentVaultSkillsFailureReason(err))
		var apiErr *api.APIError
		if !errors.As(err, &apiErr) {
			warning += unreachableHint
		}
		util.PrintWarning(warning)
		return
	}
	installAgentVaultSkillList(ctx, keepAgentVaultBuiltinSkill(listed.Skills, builtin), opts)
}

// The request already asks Infisical to leave the built-in skill out; this also covers an Infisical that ignores that.
func keepAgentVaultBuiltinSkill(skills []api.AgentVaultSessionSkill, builtin bool) []api.AgentVaultSessionSkill {
	if builtin {
		return skills
	}
	kept := make([]api.AgentVaultSessionSkill, 0, len(skills))
	for _, skill := range skills {
		if skill.Name != agentvault.BuiltinSkillName {
			kept = append(kept, skill)
		}
	}
	return kept
}

func installAgentVaultSkillList(ctx context.Context, skills []api.AgentVaultSessionSkill, opts agentvault.InstallOptions) {
	if len(skills) == 0 {
		return
	}
	result, err := agentvault.InstallSkills(ctx, skills, opts)
	if err != nil {
		names := make([]string, 0, len(skills))
		for _, skill := range skills {
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
// interrupted then tells the caller to exit without starting the agent.
func prepareAgentVaultRunSkills(ctx context.Context, install func(context.Context), onInterrupt func()) (interrupted bool) {
	stepCtx, cancel := context.WithTimeout(ctx, agentVaultSkillsTimeout)
	defer cancel()
	install(stepCtx)
	if ctx.Err() != nil {
		onInterrupt()
		return true
	}
	return false
}
