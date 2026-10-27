package agentvault

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog/log"
)

var errProxyTokenRequired = errors.New(
	"a proxy token is required: start the proxy with --proxy-token or INFISICAL_AGENT_VAULT_PROXY_TOKEN")

// Env files written for enrollment still set this. It is no longer read, so it only matters when a start fails
// for lack of a token. Remove after 2026-12-21.
func proxyTokenRequired() error {
	if os.Getenv("INFISICAL_AGENT_VAULT_ENROLLMENT_TOKEN") != "" {
		return fmt.Errorf("%w (INFISICAL_AGENT_VAULT_ENROLLMENT_TOKEN is no longer used)", errProxyTokenRequired)
	}
	return errProxyTokenRequired
}

// A file that can't be checked counts as saved state, so loading it reports the real error.
func (s *store) hasSavedState() bool {
	for _, name := range []string{proxyStateFile, caKeyFile, caCertFile} {
		if _, err := os.Lstat(s.path(name)); !os.IsNotExist(err) {
			return true
		}
	}
	return false
}

func loadSavedState(st *store, own *OwnCa) (persistedState, *caManager, error) {
	stored, confFound, stateErr := st.loadState()
	key, cert, caErr := st.loadCa()
	hasCa := caErr == nil && key != nil && cert != nil
	hasToken := stateErr == nil && stored.AccessToken != ""

	if stateErr != nil {
		return persistedState{}, nil, stateErr
	}
	if caErr != nil {
		return persistedState{}, nil, caErr
	}

	switch {
	case !confFound && !hasCa:
		return persistedState{}, nil, proxyTokenRequired()
	case !hasToken && !hasCa:
		// Settings alone: proxy.json is there but holds no token, and there is no certificate authority. Without
		// this arm the state fell through and the proxy came up with a nil CA and an empty fingerprint.
		return persistedState{}, nil, fmt.Errorf(
			"%s in %s has no access token and there is no certificate authority beside it, so this proxy's saved state is incomplete. Start the proxy with a proxy token from the Proxies page",
			proxyStateFile, st.dir)
	case hasCa && !hasToken:
		return persistedState{}, nil, fmt.Errorf(
			"the certificate authority in %s is intact but %s has no access token, so this proxy's saved state is incomplete. Restore %s from a backup to keep the certificate authority, or start the proxy with a proxy token from the Proxies page, which serves a different certificate authority that every agent then has to trust",
			st.dir, proxyStateFile, proxyStateFile)
	case hasToken && !hasCa:
		return persistedState{}, nil, fmt.Errorf(
			"%s in %s holds an access token but the certificate authority (%s, %s) is missing. Restore both files from a backup, or start the proxy with a proxy token from the Proxies page",
			proxyStateFile, st.dir, caKeyFile, caCertFile)
	}

	if err := checkStoredPolicy(st, stored); err != nil {
		return persistedState{}, nil, err
	}

	warnIfOwnCaIgnored(own, cert, st.dir)
	return stored, newCaManager(key, cert), nil
}

// The saved state carries the CA agents already trust, so a different one passed on a later run is not served.
func warnIfOwnCaIgnored(own *OwnCa, saved *x509.Certificate, dir string) {
	if own == nil || bytes.Equal(own.cert.Raw, saved.Raw) {
		return
	}
	log.Warn().Msgf("agent-vault: --ca-cert and --ca-key differ from the certificate authority saved in %s, so they are ignored. Start the proxy with a proxy token to serve them", dir)
}

// Every path that serves persisted state runs this. A file whose policy does not parse must never reach
// the proxy: blocksOffBundle compares against TrafficPolicyBundleHosts, so an empty value blocks nothing
// and a proxy the operator restricted would come up reaching everything.
func checkStoredPolicy(st *store, stored persistedState) error {
	if isTrafficPolicy(stored.Config.TrafficPolicy) {
		return nil
	}
	return fmt.Errorf(
		"%s in %s has an unrecognised trafficPolicy value %q; it must be %s or %s. If the file predates the trafficPolicy rename, start the proxy with a proxy token from the Proxies page",
		proxyStateFile, st.dir, stored.Config.TrafficPolicy, TrafficPolicyAnyHost, TrafficPolicyBundleHosts)
}

func isTrafficPolicy(v string) bool {
	return v == TrafficPolicyAnyHost || v == TrafficPolicyBundleHosts
}

// A 200 with no config in it, from a captive portal or a health page answering in Infisical's place,
// decodes to the zero value. Applying that turns the policy into "" and the poll interval into 0.
func usableProxyConfig(c ProxyConfig) bool {
	return isTrafficPolicy(c.TrafficPolicy) && c.PollInterval > 0
}

type startup struct {
	state   persistedState
	ca      *caManager
	saver   stateSaver
	dataDir string
	legacy  bool
}

// Start loads the proxy's settings and CA, then serves until interrupted.
func Start(opts Options, proxyToken string) error {
	s, err := prepareStart(opts, proxyToken)
	if err != nil {
		return err
	}
	if opts.OnReady != nil {
		opts.OnReady()
	}
	return serve(opts, s)
}

func prepareStart(opts Options, proxyToken string) (startup, error) {
	dataDir := opts.DataDir
	if dataDir == "" {
		dir, err := DefaultDataDir()
		if err != nil && proxyToken == "" {
			return startup{}, err
		}
		if err != nil {
			log.Debug().Err(err).Msg("agent-vault: no data directory, so this proxy's settings are not saved")
		}
		dataDir = dir
	}

	if proxyToken != "" {
		return startFromProxyToken(proxyToken, opts.OwnCa, dataDir, opts.DataDir != "")
	}

	st := newStore(dataDir)
	if !st.hasSavedState() {
		return startup{}, proxyTokenRequired()
	}
	// Read-only support for proxies enrolled before enrollment tokens were removed. Remove after 2026-12-21.
	state, ca, err := loadSavedState(st, opts.OwnCa)
	if err != nil {
		return startup{}, err
	}
	return startup{state: state, ca: ca, saver: st, dataDir: dataDir, legacy: true}, nil
}

// The cache is a fallback for when Infisical can't be reached, never for when it refused the token, so a
// rotated or revoked token can't keep a proxy serving.
func startFromProxyToken(proxyToken string, own *OwnCa, dataDir string, dataDirChosen bool) (startup, error) {
	var cache *tokenCache
	if dataDir != "" {
		cache = newTokenCache(dataDir, proxyToken)
	}

	state, ca, err := loadFromProxyToken(proxyToken, own)
	if errors.Is(err, errBootstrapUnreachable) && cache != nil {
		cachedState, cachedCa, cacheErr := cache.load(proxyToken, own)
		if cacheErr != nil {
			if errors.Is(cacheErr, os.ErrNotExist) {
				log.Debug().Err(cacheErr).Msg("agent-vault: no settings saved for this proxy token")
			} else {
				log.Warn().Err(cacheErr).Msg("agent-vault: the settings saved for this proxy token can't be used")
			}
			return startup{}, err
		}
		served := "the settings and certificate authority saved on this proxy token's last start"
		if own != nil {
			served = "the settings saved on this proxy token's last start, with your own certificate authority"
		}
		log.Warn().Str("dataDir", dataDir).Msgf("agent-vault: can't reach Infisical, so serving %s. Settings update once Infisical answers", served)
		return startup{state: cachedState, ca: cachedCa, saver: cache, dataDir: dataDir}, nil
	}
	if err != nil {
		if errors.Is(err, errProxyTokenRejected) && cache != nil {
			cache.remove()
		}
		return startup{}, err
	}

	if cache == nil {
		return startup{state: state, ca: ca}, nil
	}
	if saveErr := cache.save(state, ca, own != nil); saveErr != nil {
		// The default directory is often read-only in a container, which is no reason to warn on every start.
		event := log.Debug()
		if dataDirChosen {
			event = log.Warn()
		}
		event.Err(saveErr).Str("dataDir", dataDir).Msg("agent-vault: can't save this proxy's settings, so a start while Infisical can't be reached will fail")
		return startup{state: state, ca: ca}, nil
	}
	cache.pruneOtherTokens(state.ProxyID)
	return startup{state: state, ca: ca, saver: cache, dataDir: dataDir}, nil
}

// Tests shorten these so that running out of retries takes milliseconds.
var (
	bootstrapRetryWindow        = 60 * time.Second
	bootstrapUnauthorizedWindow = 10 * time.Second
	bootstrapFirstBackoff       = 1 * time.Second
	bootstrapSleep              = time.Sleep
)

const (
	bootstrapMaxBackoff = 10 * time.Second
	bootstrapMinTimeout = 1 * time.Second
)

var errBootstrapUnreachable = errors.New("can't reach Infisical to load this proxy's settings and CA; not serving")

// A 4xx is Infisical's answer, such as a rotated token, so it ends the run at once. Anything else may be
// Infisical restarting.
func isBootstrapRetryable(err error) bool {
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) {
		return true
	}
	return apiErr.StatusCode >= http.StatusInternalServerError || apiErr.StatusCode == http.StatusTooManyRequests
}

// A zero timeout means no timeout at all to the HTTP client, so a nearly spent window still gets a floor.
func bootstrapAttemptTimeout(remaining time.Duration) time.Duration {
	return max(min(controlPlaneTimeout, remaining), bootstrapMinTimeout)
}

func bootstrap(proxyToken string, own *OwnCa) (api.AgentVaultProxyBootstrapResponse, error) {
	// No client-side retries: this loop owns the retry window, and the client's would stretch it.
	httpClient, err := util.GetRestyClientWithPolicy(util.RetryPolicy{})
	if err != nil {
		return api.AgentVaultProxyBootstrapResponse{}, err
	}
	httpClient.SetAuthToken(proxyToken)

	req := api.AgentVaultProxyBootstrapRequest{}
	if own != nil {
		req.ServedCaCertificate = string(caPEM(own.cert))
	}

	start := time.Now()
	deadline := start.Add(bootstrapRetryWindow)
	// A token minted moments ago may not have reached the replica that answers, so a 401 is retried briefly.
	unauthorizedDeadline := start.Add(bootstrapUnauthorizedWindow)
	backoff := bootstrapFirstBackoff
	// Once Infisical has rejected the token, running out of time is not "unreachable": the caller must not
	// fall back to anything saved for it.
	rejected := false
	giveUp := func(last error) (api.AgentVaultProxyBootstrapResponse, error) {
		log.Warn().Err(last).Msg("agent-vault: failed to load this proxy's settings from Infisical")
		if rejected {
			return api.AgentVaultProxyBootstrapResponse{}, errProxyTokenRejected
		}
		return api.AgentVaultProxyBootstrapResponse{}, errBootstrapUnreachable
	}

	var last error
	for attempt := 1; ; attempt++ {
		remaining := time.Until(deadline)
		if attempt > 1 && remaining <= 0 {
			return giveUp(last)
		}
		httpClient.SetTimeout(bootstrapAttemptTimeout(remaining))
		res, err := api.CallAgentVaultProxyBootstrap(httpClient, req)
		if err == nil {
			return res, nil
		}
		last = err

		wait := backoff
		switch {
		case isTokenRejected(err):
			untilFatal := time.Until(unauthorizedDeadline)
			if untilFatal <= 0 {
				log.Warn().Err(err).Msg("agent-vault: failed to load this proxy's settings from Infisical")
				return api.AgentVaultProxyBootstrapResponse{}, errProxyTokenRejected
			}
			rejected = true
			wait = min(wait, untilFatal)
		case !isBootstrapRetryable(err):
			return api.AgentVaultProxyBootstrapResponse{}, err
		}

		if time.Until(deadline) < wait {
			return giveUp(err)
		}
		log.Warn().Err(err).Dur("retryIn", wait).Msg("agent-vault: failed to load this proxy's settings from Infisical, retrying")
		bootstrapSleep(wait)
		backoff = min(backoff*2, bootstrapMaxBackoff)
	}
}

func loadFromProxyToken(proxyToken string, own *OwnCa) (persistedState, *caManager, error) {
	res, err := bootstrap(proxyToken, own)
	if err != nil {
		return persistedState{}, nil, err
	}

	config := ProxyConfig{
		TrafficPolicy: res.Config.TrafficPolicy,
		AllowedHosts:  res.Config.AllowedHosts,
		PollInterval:  res.Config.PollInterval,
	}
	if !usableProxyConfig(config) {
		return persistedState{}, nil, fmt.Errorf(
			"Infisical's answer carried no usable proxy settings (trafficPolicy %q, pollInterval %d). Check that --domain points at Infisical and not at something answering in its place",
			config.TrafficPolicy, config.PollInterval)
	}

	var ca *caManager
	if own != nil {
		ca = newCaManager(own.key, own.cert)
	} else {
		if res.RootCa == nil {
			return persistedState{}, nil, errors.New("Infisical returned no certificate authority for this proxy; not serving")
		}
		key, cert, err := parseCaPair([]byte(res.RootCa.Certificate), []byte(res.RootCa.PrivateKey))
		if err != nil {
			return persistedState{}, nil, fmt.Errorf("the certificate authority Infisical returned can't be used: %w", err)
		}
		ca = newCaManager(key, cert)
	}

	return persistedState{
		ProxyID:     res.ProxyID,
		ProxyName:   res.Name,
		AccessToken: proxyToken,
		Config:      config,
	}, ca, nil
}

// A settings change the heartbeat brings is saved through this, so a restart while Infisical is down keeps it.
type stateSaver interface {
	saveState(persistedState) error
}

// A nil saver applies settings changes in memory only.
func serve(opts Options, s startup) error {
	state, ca, st := s.state, s.ca, s.saver
	opts.ProxyID = state.ProxyID
	opts.ProxyName = state.ProxyName
	accessToken := state.AccessToken
	opts.ProxyToken = func() string { return accessToken }

	config := state.Config
	if config.PollInterval <= 0 {
		config.PollInterval = 60
	}

	ps := &proxyServer{
		opts:      opts,
		ca:        ca,
		transport: newUpstreamTransport(),
		config:    config,
		persisted: state,
		legacy:    s.legacy,
	}
	resolver, err := newInfisicalResolver(opts.ProxyToken)
	if err != nil {
		return err
	}
	ps.cache = newSessionCache(resolver, ps.pollInterval)

	shipper, err := newSessionLogShipper(opts.ProxyToken)
	if err != nil {
		return err
	}
	ps.sessionLogs = newSessionLogRecorder(state.ProxyID, shipper)

	// Port 0 is not "unset": it is the ordinary ask for any free port, so it is never substituted.
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", opts.Port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", opts.Port, err)
	}

	front := &http.Server{
		Handler:           http.HandlerFunc(ps.dispatch),
		ReadHeaderTimeout: frontReadHeaderTimeout,
		IdleTimeout:       frontIdleTimeout,
		MaxHeaderBytes:    maxRequestHeaderBytes,
	}

	limited := newLimitListener(listener, maxConcurrentConns, func() {
		log.Warn().
			Int("limit", maxConcurrentConns).
			Msg("agent-vault: connection limit reached, new connections are waiting for a slot")
	})

	stop := make(chan struct{})
	fatal := make(chan error, 1)
	go ps.pollLoop(st, stop, fatal)
	go ps.sessionLogs.run(stop)

	serveErr := make(chan error, 1)
	go func() { serveErr <- front.Serve(limited) }()

	// The bound port, not the requested one: they differ whenever port 0 was asked for.
	listening := log.Info().
		Int("port", listener.Addr().(*net.TCPAddr).Port).
		Str("proxyId", state.ProxyID).
		Str("name", state.ProxyName).
		Str("fingerprint", ca.Fingerprint())
	if st != nil {
		listening = listening.Str("dataDir", s.dataDir)
	}
	listening.Msg("agent-vault: proxy listening")

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)

	// Its own budget: in-flight requests can spend all of the shutdown's, and this is the last minute of session logs.
	closeSessionLogs := func() {
		ctx, cancel := context.WithTimeout(context.Background(), sessionLogCloseTimeout)
		defer cancel()
		ps.sessionLogs.close(ctx)
	}

	select {
	case err := <-serveErr:
		close(stop)
		closeSessionLogs()
		ps.cache.close()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-signals:
		log.Info().Msg("agent-vault: shutting down")
		close(stop)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = front.Shutdown(ctx)
		closeSessionLogs()
		ps.cache.close()
		return nil
	case err := <-fatal:
		close(stop)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = front.Shutdown(ctx)
		closeSessionLogs()
		ps.cache.close()
		return err
	}
}

// A 401 on the heartbeat is never transient. A timeout, a 5xx or a 429 rides out the grace window; a
// rejected token does not.
const heartbeatRejectionsBeforeExit = 2

var errProxyTokenRejected = errors.New(
	"Infisical doesn't accept this proxy token. Check that it's the latest token for this Infisical, or generate a new one in Infisical")

var errSavedStateTokenRejected = errors.New(
	"Infisical no longer accepts this proxy's saved access token: its access was revoked or the proxy was deleted. Start the proxy with a proxy token from the Proxies page")

func isTokenRejected(err error) bool {
	var apiErr *api.APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized
}

func (ps *proxyServer) pollLoop(st stateSaver, stop <-chan struct{}, fatal chan<- error) {
	rejections := 0
	onTick := func() bool {
		if ps.tick(st) {
			rejections++
		} else {
			rejections = 0
		}
		if rejections >= heartbeatRejectionsBeforeExit {
			if ps.legacy {
				fatal <- errSavedStateTokenRejected
			} else {
				if cache, ok := st.(*tokenCache); ok {
					cache.remove()
				}
				fatal <- errProxyTokenRejected
			}
			return false
		}
		return true
	}

	if !onTick() {
		return
	}

	for {
		// Re-read the interval each tick rather than using a fixed ticker, so lowering it takes effect from the next tick.
		timer := time.NewTimer(ps.pollInterval())
		select {
		case <-stop:
			timer.Stop()
			return
		case <-timer.C:
			if !onTick() {
				return
			}
		}
	}
}

func (ps *proxyServer) tick(st stateSaver) (tokenRejected bool) {
	httpClient, err := util.GetRestyClientWithCustomHeaders()
	if err == nil {
		httpClient.SetAuthToken(ps.opts.ProxyToken()).SetTimeout(controlPlaneTimeout)
		res, hbErr := api.CallAgentVaultHeartbeat(httpClient)
		if hbErr != nil {
			tokenRejected = isTokenRejected(hbErr)
			log.Warn().Err(hbErr).Msg("agent-vault: heartbeat failed")
		} else {
			next := ProxyConfig{
				TrafficPolicy: res.Config.TrafficPolicy,
				AllowedHosts:  res.Config.AllowedHosts,
				PollInterval:  res.Config.PollInterval,
			}
			if !usableProxyConfig(next) {
				log.Warn().
					Str("trafficPolicy", next.TrafficPolicy).
					Int("pollInterval", next.PollInterval).
					Msg("agent-vault: heartbeat returned no usable settings, keeping the current ones")
			} else if ps.setConfig(next) {
				log.Info().
					Str("trafficPolicy", next.TrafficPolicy).
					Str("allowedHosts", next.AllowedHosts).
					Int("pollInterval", next.PollInterval).
					Msg("agent-vault: settings changed")

				// Persisted so a restart during an Infisical outage keeps the operator's policy rather than coming back up allowing.
				ps.persisted.Config = next
				if st != nil {
					if saveErr := st.saveState(ps.persisted); saveErr != nil {
						log.Warn().Err(saveErr).Msg("agent-vault: failed to persist the new settings")
					}
				}
			}
		}
	}

	ps.cache.refreshInBackground()
	return tokenRejected
}
