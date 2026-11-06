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

// The waits before each retry of a list that answered 401 on a minted run. Through a proxy, the last retry comes after
// the proxy stops answering the refusal from memory, so it reaches Infisical again.
var agentVaultSkillsUnauthorizedRetryDelays = []time.Duration{time.Second, 2 * time.Second, 3 * time.Second}

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
	// Asks the proxy's own Infisical through the proxy, which answers with the session's own token, so the agent's host
	// needs to reach only the proxy. Nil asks Infisical directly.
	tunnel *agentVaultSkillsTunnel
	// The proxy didn't say which Infisical it works with, so it is too old to answer for the session.
	proxyTooOld bool
	// Runs before the first request that goes to Infisical directly, which only happens behind a proxy too old to
	// answer for the session.
	beforeDirect func()
}

func (c *agentVaultSkillsClient) list(ctx context.Context) (api.ListAgentVaultSessionSkillsResponse, error) {
	if c.tunnel != nil {
		return c.retrying(ctx, func() (api.ListAgentVaultSessionSkillsResponse, error) {
			return api.CallListAgentVaultSessionSkillsThroughProxy(ctx, c.tunnel.httpClient, c.tunnel.apiURL, c.sessionToken, c.includeBuiltin)
		})
	}
	if c.beforeDirect != nil {
		c.beforeDirect()
	}
	listed, err := c.retrying(ctx, func() (api.ListAgentVaultSessionSkillsResponse, error) {
		return api.CallListAgentVaultSessionSkills(ctx, c.httpClient, c.sessionToken, c.includeBuiltin)
	})
	if err != nil && c.proxyTooOld {
		return listed, &agentVaultProxyTooOldError{err: err}
	}
	return listed, err
}

// askAgentVaultProxyAPIURL asks the proxy which Infisical it works with, so the agent reaches its session's endpoints
// there through the proxy, whatever domain this command uses. An older proxy doesn't say, and "" comes back.
func askAgentVaultProxyAPIURL(proxyAddr, sessionToken string) string {
	ctx, cancel := context.WithTimeout(context.Background(), agentVaultSkillsConnectTimeout)
	defer cancel()
	apiURL, err := agentvault.AskProxyAPIURL(ctx, proxyAddr, sessionToken, agentVaultProxyAPIURLTarget())
	if err != nil {
		return ""
	}
	return apiURL
}

// The CONNECT the question goes out on names this command's own Infisical, usually the proxy's too. The proxy names its
// own whatever the target.
func agentVaultProxyAPIURLTarget() string {
	parsed, err := url.Parse(config.INFISICAL_URL)
	if err != nil || parsed.Hostname() == "" {
		return "app.infisical.com:443"
	}
	port := parsed.Port()
	if port == "" {
		port = map[bool]string{true: "80", false: "443"}[parsed.Scheme == "http"]
	}
	return net.JoinHostPort(parsed.Hostname(), port)
}

// agentVaultSkillsTunnel sends requests to the proxy's own Infisical through the proxy, trusting only the certificate
// authority this run verified.
type agentVaultSkillsTunnel struct {
	httpClient *resty.Client
	// The Infisical API URL the proxy named.
	apiURL string
}

func newAgentVaultSkillsTunnel(proxyAddr, sessionToken, apiURL string, caPEM []byte) (*agentVaultSkillsTunnel, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("the proxy's certificate authority could not be read")
	}
	tunnel := &agentVaultSkillsTunnel{apiURL: apiURL}
	proxyURL := &url.URL{Scheme: "http", Host: proxyAddr, User: url.UserPassword(agentvault.ProxyAuthUsername, sessionToken)}
	// The retries a direct request gets, for a busy Infisical or proxy. INFISICAL_CUSTOM_HEADERS stay behind: they are
	// for Infisical, and the proxy sends its own request there.
	policy := util.DefaultRetryPolicy()
	policy.StatusOnly = true
	tunnel.httpClient = util.GetRestyClientWithoutCustomHeaders(policy)
	// An answer the proxy didn't mark didn't come from the proxy's own Infisical, which asking again won't change, so
	// only a marked one is asked again.
	retryConditions := tunnel.httpClient.RetryConditions
	tunnel.httpClient.RetryConditions = []resty.RetryConditionFunc{func(res *resty.Response, err error) bool {
		if res == nil || res.Header().Get(agentvault.HeaderDecision) == "" {
			return false
		}
		for _, condition := range retryConditions {
			if condition(res, err) {
				return true
			}
		}
		return false
	}}
	tunnel.httpClient.SetTransport(&http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		DialContext:     (&net.Dialer{Timeout: agentVaultSkillsConnectTimeout, KeepAlive: 30 * time.Second}).DialContext,
	})
	return tunnel, nil
}

// The proxy was too old to forward the request, and asking Infisical directly failed too.
type agentVaultProxyTooOldError struct {
	err error
}

func (e *agentVaultProxyTooOldError) Error() string { return e.err.Error() }
func (e *agentVaultProxyTooOldError) Unwrap() error { return e.err }

// The hint for a host that can't reach Infisical. Behind a proxy too old to forward the request, the fix is the proxy.
func agentVaultSkillsUnreachableHintFor(err error) string {
	var tooOld *agentVaultProxyTooOldError
	if errors.As(err, &tooOld) {
		return " The proxy is too old to pass skills on, so this host asked Infisical directly. Update the Infisical CLI that runs the proxy, or pass --no-skills."
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
