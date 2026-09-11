package agentvault

import (
	"context"
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

// enroll commits nothing to disk until the server has answered.
func enroll(st *store, enrollmentToken string) (persistedState, *caManager, error) {
	// The CA subject cannot carry the proxy's name: the certificate has to exist before the enrollment
	// call that returns it.
	key, cert, err := generateRootCa()
	if err != nil {
		return persistedState{}, nil, err
	}

	if err := st.probeWritable(); err != nil {
		return persistedState{}, nil, err
	}

	httpClient, err := util.GetRestyClientWithCustomHeaders()
	if err != nil {
		return persistedState{}, nil, err
	}
	httpClient.SetTimeout(controlPlaneTimeout)

	res, err := api.CallLoginAgentVaultProxy(httpClient, api.LoginAgentVaultProxyRequest{
		Method:            "token",
		Token:             enrollmentToken,
		RootCaCertificate: string(caPEM(cert)),
	})
	if err != nil {
		return persistedState{}, nil, err
	}

	state := persistedState{
		ProxyID:         res.ProxyID,
		ProxyName:       res.Name,
		AccessToken:     res.AccessToken,
		EnrollmentToken: enrollmentToken,
		Config: ProxyConfig{
			UnmatchedHost: res.Config.UnmatchedHost,
			BypassHosts:   res.Config.BypassHosts,
			PollInterval:  res.Config.PollInterval,
		},
	}

	if err := st.saveCa(key, cert); err != nil {
		return persistedState{}, nil, err
	}
	if err := st.saveState(state); err != nil {
		return persistedState{}, nil, err
	}

	return state, newCaManager(key, cert), nil
}

// resolveState decides whether this run enrolls or resumes. Re-passing the same enrollment token that
// already enrolled this box is a no-op.
func resolveState(st *store, enrollmentToken string) (persistedState, *caManager, error) {
	stored, confFound, stateErr := st.loadState()
	key, cert, caErr := st.loadCa()
	hasCa := caErr == nil && key != nil && cert != nil
	hasToken := stateErr == nil && stored.AccessToken != ""

	alreadyEnrolled := hasToken && hasCa

	// A token is checked before the damage errors: the messages for damaged state say to enroll again
	// with a new token, so that has to work on the same damage.
	if enrollmentToken != "" {
		if alreadyEnrolled && stored.EnrollmentToken == enrollmentToken {
			log.Info().Msg("agent-vault: this enrollment token already enrolled this proxy, resuming")
			return stored, newCaManager(key, cert), nil
		}
		// Re-enrolling replaces the certificate authority, so anything holding a copy of the old one stops
		// trusting the proxy. That holds whether or not the rest of the state survived beside it.
		if hasCa || caErr != nil {
			log.Warn().Msg("agent-vault: enrolling with a new token replaces this proxy's certificate authority")
		}
		return enroll(st, enrollmentToken)
	}

	if stateErr != nil {
		return persistedState{}, nil, stateErr
	}
	if caErr != nil {
		return persistedState{}, nil, caErr
	}

	// Only a directory with nothing in it is a first run. Anything else is damage, and saying "not
	// enrolled" would send the operator for a new token, which replaces a certificate authority that may
	// still be intact on disk.
	switch {
	case !confFound && !hasCa:
		return persistedState{}, nil, errors.New(
			"this proxy has not enrolled yet. Run it once with --enrollment-token, using the token shown when the proxy was created")
	case hasCa && !hasToken:
		return persistedState{}, nil, fmt.Errorf(
			"the certificate authority in %s is intact but %s has no access token, so this proxy's state is incomplete. Restore %s from a backup to keep the certificate authority, or enroll again with a new token from the Proxies page, which replaces it and means every agent trusting the old one has to be restarted",
			st.dir, proxyStateFile, proxyStateFile)
	case hasToken && !hasCa:
		return persistedState{}, nil, fmt.Errorf(
			"%s in %s holds an access token but the certificate authority (%s, %s) is missing. Restore both files from a backup, or enroll again with a new token from the Proxies page, which issues a new certificate authority",
			proxyStateFile, st.dir, caKeyFile, caCertFile)
	}

	if !isUnmatchedHostPolicy(stored.Config.UnmatchedHost) {
		return persistedState{}, nil, fmt.Errorf(
			"%s in %s has an unrecognised unmatchedHost value %q; it must be %s or %s. Fix the value or restore the file from a backup",
			proxyStateFile, st.dir, stored.Config.UnmatchedHost, UnmatchedAllow, UnmatchedDeny)
	}

	return stored, newCaManager(key, cert), nil
}

func isUnmatchedHostPolicy(v string) bool { return v == UnmatchedAllow || v == UnmatchedDeny }

// Start enrolls if needed, then serves until interrupted. An empty enrollmentToken means
// "read the persisted state and serve".
func Start(opts Options, enrollmentToken string) error {
	if opts.DataDir == "" {
		dir, err := DefaultDataDir()
		if err != nil {
			return err
		}
		opts.DataDir = dir
	}

	st := newStore(opts.DataDir)
	state, ca, err := resolveState(st, enrollmentToken)
	if err != nil {
		return err
	}

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
	}
	resolver, err := newInfisicalResolver(opts.ProxyToken)
	if err != nil {
		return err
	}
	ps.cache = newSessionCache(resolver, ps.pollInterval)

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

	serveErr := make(chan error, 1)
	go func() { serveErr <- front.Serve(limited) }()

	// The bound port, not the requested one: they differ whenever port 0 was asked for.
	log.Info().
		Int("port", listener.Addr().(*net.TCPAddr).Port).
		Str("proxyId", state.ProxyID).
		Str("name", state.ProxyName).
		Str("fingerprint", ca.Fingerprint()).
		Str("dataDir", opts.DataDir).
		Msg("agent-vault: proxy listening")

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serveErr:
		close(stop)
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
		ps.cache.close()
		return nil
	case err := <-fatal:
		close(stop)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = front.Shutdown(ctx)
		ps.cache.close()
		return err
	}
}

// A 401 on the heartbeat is never transient. A timeout, a 5xx or a 429 rides out the grace window; a
// rejected token does not.
const heartbeatRejectionsBeforeExit = 2

var errProxyTokenRejected = errors.New(
	"Infisical no longer accepts this proxy's token: its access was revoked or the proxy was deleted. Enroll again with a new enrollment token from the Proxies page")

func isTokenRejected(err error) bool {
	var apiErr *api.APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized
}

func (ps *proxyServer) pollLoop(st *store, stop <-chan struct{}, fatal chan<- error) {
	rejections := 0
	onTick := func() bool {
		if ps.tick(st) {
			rejections++
		} else {
			rejections = 0
		}
		if rejections >= heartbeatRejectionsBeforeExit {
			fatal <- errProxyTokenRejected
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

func (ps *proxyServer) tick(st *store) (tokenRejected bool) {
	httpClient, err := util.GetRestyClientWithCustomHeaders()
	if err == nil {
		httpClient.SetAuthToken(ps.opts.ProxyToken()).SetTimeout(controlPlaneTimeout)
		res, hbErr := api.CallAgentVaultHeartbeat(httpClient)
		if hbErr != nil {
			tokenRejected = isTokenRejected(hbErr)
			log.Warn().Err(hbErr).Msg("agent-vault: heartbeat failed")
		} else {
			next := ProxyConfig{
				UnmatchedHost: res.Config.UnmatchedHost,
				BypassHosts:   res.Config.BypassHosts,
				PollInterval:  res.Config.PollInterval,
			}
			if ps.setConfig(next) {
				log.Info().
					Str("unmatchedHost", next.UnmatchedHost).
					Str("bypassHosts", next.BypassHosts).
					Int("pollInterval", next.PollInterval).
					Msg("agent-vault: settings changed")

				// Persisted so a restart during an Infisical outage keeps the operator's policy rather than coming back up allowing.
				ps.persisted.Config = next
				if saveErr := st.saveState(ps.persisted); saveErr != nil {
					log.Warn().Err(saveErr).Msg("agent-vault: failed to persist the new settings")
				}
			}
		}
	}

	ps.cache.refreshInBackground()
	return tokenRejected
}
