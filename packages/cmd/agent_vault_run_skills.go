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
	// Long enough for the proxy's own session lookup, which a CONNECT for a host other than the proxy's Infisical waits on
	// before it is answered.
	agentVaultProxyAPIURLTimeout = 20 * time.Second
	// For confirming the API URL on its own after the skills request didn't, which delays the agent's start.
	agentVaultProxyConfirmTimeout = 10 * time.Second
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

// The only setup error is INFISICAL_CUSTOM_HEADERS that can't be read, and its message repeats the variable's value,
// credentials included, so it is never printed.
var errAgentVaultSessionHTTPClient = errors.New("INFISICAL_CUSTOM_HEADERS couldn't be read; set it as headerKey1=value1 headerKey2=value2")

// newAgentVaultSessionHTTPClient is newAgentVaultSkillsHTTPClient with an error safe to print.
func newAgentVaultSessionHTTPClient() (*resty.Client, error) {
	client, err := newAgentVaultSkillsHTTPClient()
	if err != nil {
		return nil, errAgentVaultSessionHTTPClient
	}
	return client, nil
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
		listed, err := c.retrying(ctx, func() (api.ListAgentVaultSessionSkillsResponse, error) {
			return api.CallListAgentVaultSessionSkillsThroughProxy(ctx, c.tunnel.httpClient, c.tunnel.tlsAPIURL,
				c.includeBuiltin, func(res *resty.Response) error { return c.tunnel.check(res, agentvault.DecisionSkills) })
		})
		// An answer that didn't come from the proxy's own Infisical is dropped, and Infisical is asked directly instead.
		if !errors.Is(err, errAgentVaultProxyAnswerUnconfirmed) {
			return listed, err
		}
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

// services gets the session's services the way list gets its skills: through the proxy's tunnel when there is one, and
// from Infisical directly otherwise or when the tunnel's answer isn't confirmed.
func (c *agentVaultSkillsClient) services(ctx context.Context) (api.ListAgentVaultSessionServicesResponse, error) {
	if c.tunnel != nil {
		listed, err := agentVaultRetrying(ctx, c.retryUnauthorized, func() (api.ListAgentVaultSessionServicesResponse, error) {
			return api.CallListAgentVaultSessionServicesThroughProxy(ctx, c.tunnel.httpClient, c.tunnel.tlsAPIURL,
				func(res *resty.Response) error { return c.tunnel.check(res, agentvault.DecisionDiscovery) })
		})
		if !errors.Is(err, errAgentVaultProxyAnswerUnconfirmed) {
			return listed, err
		}
	}
	if c.beforeDirect != nil {
		c.beforeDirect()
	}
	listed, err := agentVaultRetrying(ctx, c.retryUnauthorized, func() (api.ListAgentVaultSessionServicesResponse, error) {
		return api.CallListAgentVaultSessionServices(ctx, c.httpClient, c.sessionToken)
	})
	if err != nil && c.proxyTooOld {
		return listed, &agentVaultProxyTooOldError{err: err}
	}
	return listed, err
}

// askAgentVaultProxyAPIURL asks the proxy which Infisical it works with, so the agent reaches its session's endpoints
// there through the proxy, whatever domain this command uses. The answer is only a claim until a tunnel confirms it.
// answered is false when the proxy didn't answer in time, which says nothing about its age; a proxy that answered
// without naming one is too old.
func askAgentVaultProxyAPIURL(ctx context.Context, proxyAddr, sessionToken string, minted bool) (claimed string, answered bool, refusal *agentvault.ProxyRefusalError) {
	ctx, cancel := context.WithTimeout(ctx, agentVaultProxyAPIURLTimeout)
	defer cancel()
	claimed, err := agentvault.AskProxyAPIURL(ctx, proxyAddr, sessionToken, agentVaultProxyAPIURLTarget())
	// The proxy names its Infisical only to a session it accepts, and remembers a refusal for a few seconds, such as one
	// from a database replica that hadn't seen a session this run just minted. So a minted session that reads as invalid
	// asks again until the proxy accepts it, for as long as the skills step would. No other refusal clears up by itself.
	if minted {
		for _, delay := range agentVaultSkillsUnauthorizedRetryDelays {
			if !errors.As(err, &refusal) || !agentvault.IsSessionRefusal(refusal.Code) {
				break
			}
			select {
			case <-ctx.Done():
				return "", false, nil
			case <-time.After(delay):
			}
			claimed, err = agentvault.AskProxyAPIURL(ctx, proxyAddr, sessionToken, agentVaultProxyAPIURLTarget())
		}
	}
	refusal = nil
	if errors.As(err, &refusal) {
		return "", true, refusal
	}
	return claimed, err == nil, nil
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

// agentVaultSkillsTunnel sends requests to the proxy's own Infisical through the proxy, always over TLS and trusting
// only the certificate authority this run verified, so nothing between this host and the proxy can change an answer.
type agentVaultSkillsTunnel struct {
	httpClient *resty.Client
	// The API URL the proxy named on its CONNECT answer, which crossed the network in the clear.
	claimedAPIURL string
	// The same host, port and path over https: the proxy answers its session endpoints whatever the scheme.
	tlsAPIURL string
	// An answer from inside TLS named claimedAPIURL (confirmed), or named something else (contradicted).
	confirmed, contradicted bool
}

var errAgentVaultProxyAnswerUnconfirmed = errors.New("the answer through the proxy's tunnel did not come from the proxy's own Infisical")

func newAgentVaultSkillsTunnel(proxyAddr, sessionToken, claimedAPIURL string, caPEM []byte) (*agentVaultSkillsTunnel, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("the proxy's certificate authority could not be read")
	}
	parsed, err := url.Parse(claimedAPIURL)
	if err != nil || parsed.Hostname() == "" {
		return nil, fmt.Errorf("the proxy named an API URL that can't be used: %q", claimedAPIURL)
	}
	port := parsed.Port()
	if port == "" {
		port = map[bool]string{true: "80", false: "443"}[parsed.Scheme == "http"]
	}
	tlsAPIURL := url.URL{Scheme: "https", Host: net.JoinHostPort(parsed.Hostname(), port), Path: parsed.Path}
	tunnel := &agentVaultSkillsTunnel{claimedAPIURL: claimedAPIURL, tlsAPIURL: strings.TrimSuffix(tlsAPIURL.String(), "/")}
	proxyURL := &url.URL{Scheme: "http", Host: proxyAddr, User: url.UserPassword(agentvault.ProxyAuthUsername, sessionToken)}
	// The retries a direct request gets, for a busy Infisical or proxy. INFISICAL_CUSTOM_HEADERS stay behind: they are
	// for Infisical, and the proxy sends its own request there.
	policy := util.DefaultRetryPolicy()
	policy.StatusOnly = true
	tunnel.httpClient = util.GetRestyClientWithoutCustomHeaders(policy)
	// A redirect is never followed, since its target could be outside TLS, where anyone on the way can write the answer.
	// The redirect itself is the answer check sees, and only the proxy's own session endpoints confirm the claim.
	tunnel.httpClient.SetRedirectPolicy(resty.RedirectPolicyFunc(func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}))
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

// check passes an answer from the proxy's own session endpoint for decision. Inside TLS, which only the proxy can speak
// for this host, the proxy names its API URL again: the same URL confirms the CONNECT answer's claim. Whatever the
// status, the answer must carry that endpoint's decision or a refusal the proxy wrote, never one it passed on from a host.
func (t *agentVaultSkillsTunnel) check(res *resty.Response, decision string) error {
	answered := res.Header().Get(agentvault.HeaderDecision)
	apiURL := agentvault.APIURLFromHeader(res.Header().Get(agentvault.HeaderAPIURL))
	// The proxy names no Infisical to a session it has since refused, which neither confirms nor contradicts the claim.
	// The refusal's own code and message still say what to fix, such as a proxy whose token was revoked.
	if apiURL == "" && agentvault.IsProxyRefusal(answered) {
		return api.NewAPIErrorWithResponse("CallAgentVaultSessionEndpointThroughProxy", res, nil)
	}
	if apiURL != t.claimedAPIURL || (answered != decision && !agentvault.IsProxyRefusal(answered)) {
		t.contradicted = true
		return errAgentVaultProxyAnswerUnconfirmed
	}
	t.confirmed = true
	return nil
}

// confirm checks the claimed API URL when no skills request will: it asks the session's services list for its headers
// only.
func (t *agentVaultSkillsTunnel) confirm(ctx context.Context) {
	res, err := t.httpClient.R().SetContext(ctx).Head(t.tlsAPIURL + "/v1/agent-vault/session/services")
	if err == nil {
		_ = t.check(res, agentvault.DecisionDiscovery)
	}
}

// agentVaultRunProxyStep is something the run does through the proxy before the agent starts, such as installing the
// session's skills. tunnel is nil behind a proxy that named no Infisical, which proxyTooOld says is too old rather than
// slow to answer.
type agentVaultRunProxyStep func(ctx context.Context, tunnel *agentVaultSkillsTunnel, proxyTooOld bool)

// prepareAgentVaultRunProxy asks the proxy which Infisical it works with, then runs steps, a nil one skipped, within
// one budget. It returns the API URL the agent's INFISICAL_AGENT_VAULT_URL comes from, or "" unless an answer from
// inside TLS confirmed it.
func prepareAgentVaultRunProxy(ctx context.Context, proxyAddr, sessionToken string, caPEM []byte, minted bool, steps ...agentVaultRunProxyStep) string {
	claimed, answered, refusal := askAgentVaultProxyAPIURL(ctx, proxyAddr, sessionToken, minted)
	// The proxy refuses everything this session sends, so asking Infisical directly would only hide why.
	if refusal != nil {
		util.PrintWarning(fmt.Sprintf("The proxy refused this session (%s), so the agent starts without its skills, MCP servers or %s.",
			refusal.Error(), agentvault.URLEnv))
		return ""
	}
	var tunnel *agentVaultSkillsTunnel
	if claimed != "" {
		tunnel, _ = newAgentVaultSkillsTunnel(proxyAddr, sessionToken, claimed, caPEM)
	}
	stepCtx, cancel := context.WithTimeout(ctx, agentVaultSkillsTimeout)
	defer cancel()
	for _, step := range steps {
		if step != nil {
			step(stepCtx, tunnel, answered && claimed == "")
		}
	}
	if tunnel == nil {
		return ""
	}
	// With no step, or one whose answer failed before its headers were checked, such as one cut short, the services list's
	// headers decide.
	if !tunnel.confirmed && !tunnel.contradicted && ctx.Err() == nil {
		confirmCtx, cancelConfirm := context.WithTimeout(ctx, agentVaultProxyConfirmTimeout)
		tunnel.confirm(confirmCtx)
		cancelConfirm()
	}
	if tunnel.contradicted {
		util.PrintWarning("The proxy's answer from inside TLS didn't name the Infisical it named on its CONNECT answer, so the agent gets no " +
			agentvault.URLEnv + " and no skills came through the proxy. Something between this host and the proxy may be changing its answers.")
	}
	if !tunnel.confirmed {
		return ""
	}
	return claimed
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
	return agentVaultRetrying(ctx, c.retryUnauthorized, fetch)
}

// agentVaultRetrying asks again after a refusal of a session this run just minted (retryUnauthorized), which a database
// replica or the proxy's memory of a refusal can still hold.
func agentVaultRetrying[T any](ctx context.Context, retryUnauthorized bool, fetch func() (T, error)) (T, error) {
	listed, err := fetch()
	if !retryUnauthorized {
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

// prepareAgentVaultRunStartup runs what happens between minting the session and starting the agent, with ctx cancelled
// by Ctrl-C or another termination signal.
// When the operator interrupts it, onInterrupt revokes the session, the same as when the agent exits;
// interrupted then tells the caller to exit without starting the agent.
func prepareAgentVaultRunStartup(ctx context.Context, prepare func(context.Context), onInterrupt func()) (interrupted bool) {
	prepare(ctx)
	if ctx.Err() != nil {
		onInterrupt()
		return true
	}
	return false
}
