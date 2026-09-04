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

// Enroll exchanges a one-time enrollment token for a proxy access token, and commits nothing to disk
// until the server has answered.
//
// The CA is generated in memory first and written only on success, so a failed enrollment leaves no
// half-written data directory behind for the next run to load.
func enroll(st *store, enrollmentToken string) (persistedState, *caManager, error) {
	// The CA subject cannot carry the proxy's name: the certificate has to exist before the enrollment
	// call that tells us what the name is. The fingerprint is the identifier that matters anyway.
	key, cert, err := generateRootCa()
	if err != nil {
		return persistedState{}, nil, err
	}

	httpClient, err := util.GetRestyClientWithCustomHeaders()
	if err != nil {
		return persistedState{}, nil, err
	}

	res, err := api.CallEnrollAgentVaultProxy(httpClient, api.EnrollAgentVaultProxyRequest{
		EnrollmentToken:   enrollmentToken,
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

// resolveState decides whether this run enrolls or resumes.
//
// Re-passing the *same* enrollment token that already enrolled this box is a no-op, following gateway
// enrollment. Without that, an ordinary restart breaks: a Kubernetes Deployment holds the token in its
// spec, so a node drain or an OOM kill would become a crashloop until a human minted a new token. A
// *different* token still re-enrolls from scratch, which is the redeploy and rotate story, and wiping
// the data directory takes the stored token with it — so a spent token in a spec finds nothing to
// compare against, gets a 401, and exits with the disk untouched.
//
// One improvement on gateway's version: it compares only the stored enrollment token, so a directory
// holding the token but no access token would skip enrollment and then fail to serve. Both are checked.
func resolveState(st *store, enrollmentToken string) (persistedState, *caManager, error) {
	stored, err := st.loadState()
	if err != nil {
		return persistedState{}, nil, err
	}

	key, cert, err := st.loadCa()
	if err != nil {
		return persistedState{}, nil, err
	}
	hasCa := key != nil && cert != nil

	alreadyEnrolled := stored.AccessToken != "" && hasCa

	if enrollmentToken != "" {
		if alreadyEnrolled && stored.EnrollmentToken == enrollmentToken {
			log.Info().Msg("agent-vault: this enrollment token already enrolled this proxy, resuming")
			return stored, newCaManager(key, cert), nil
		}
		// A different token, or nothing usable on disk. Re-enrolling replaces the certificate authority,
		// which is the expensive half: anything holding a *copy* of the old one has to be updated. An
		// `av run` on Linux notices nothing because it refetches, but an explicit --ca-fingerprint pin, a
		// Kubernetes Secret mounting the CA, and a macOS keychain entry all break.
		if alreadyEnrolled {
			log.Warn().Msg("agent-vault: enrolling with a new token replaces this proxy's certificate authority")
		}
		return enroll(st, enrollmentToken)
	}

	if !alreadyEnrolled {
		return persistedState{}, nil, errors.New(
			"this proxy has not enrolled yet. Run it once with --enrollment-token, using the token shown when the proxy was created")
	}

	return stored, newCaManager(key, cert), nil
}

// Start is the whole `av proxy` lifecycle: enroll if needed, then serve until interrupted. An empty
// enrollmentToken means "read the persisted state and serve".
func Start(opts Options, enrollmentToken string) error {
	if opts.Port == 0 {
		opts.Port = DefaultPort
	}
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
	if config.UnmatchedHost == "" {
		config.UnmatchedHost = UnmatchedAllow
	}

	ps := &proxyServer{
		opts:      opts,
		ca:        ca,
		transport: newUpstreamTransport(),
		config:    config,
	}
	ps.cache = newSessionCache(newInfisicalResolver(opts.ProxyToken), ps.pollInterval)

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
	go ps.pollLoop(st, stop)

	serveErr := make(chan error, 1)
	go func() { serveErr <- front.Serve(limited) }()

	log.Info().
		Int("port", opts.Port).
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
	}
}

// pollLoop is the single tick that keeps everything current: it heartbeats (which returns the settings
// block) and refreshes every live session. Worst-case staleness for any change an administrator makes is
// one interval, and there is no second place to invalidate.
func (ps *proxyServer) pollLoop(st *store, stop <-chan struct{}) {
	ps.tick(st)

	for {
		// Re-read the interval each time rather than using a fixed ticker: lowering it from 300 to 10
		// takes effect from the next tick, after one more 300s wait.
		timer := time.NewTimer(ps.pollInterval())
		select {
		case <-stop:
			timer.Stop()
			return
		case <-timer.C:
			ps.tick(st)
		}
	}
}

func (ps *proxyServer) tick(st *store) {
	httpClient, err := util.GetRestyClientWithCustomHeaders()
	if err == nil {
		httpClient.SetAuthToken(ps.opts.ProxyToken())
		res, hbErr := api.CallAgentVaultHeartbeat(httpClient)
		if hbErr != nil {
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

				// Persisted so a restart during an Infisical outage keeps the operator's policy. Without
				// this a proxy set to deny would come back up allowing, at exactly the wrong moment.
				stored, loadErr := st.loadState()
				if loadErr == nil {
					stored.Config = next
					if saveErr := st.saveState(stored); saveErr != nil {
						log.Warn().Err(saveErr).Msg("agent-vault: failed to persist the new settings")
					}
				}
			}
		}
	}

	ps.cache.refresh()
}
