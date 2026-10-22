package agentvault

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog/log"
)

var errInfisicalHoldsNoCa = errors.New("upgrade Infisical to use this CLI, or pass --ca-cert/--ca-key")

// A server from before Infisical held the CA requires rootCaCertificate, and rejects the login as a
// validation failure before the token is spent.
func isMissingCaRejection(err error) bool {
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	if apiErr.StatusCode != http.StatusUnprocessableEntity && apiErr.StatusCode != http.StatusBadRequest {
		return false
	}
	return strings.Contains(apiErr.ErrorMessage, "rootCaCertificate")
}

// enroll commits nothing to disk until the server has answered.
func enroll(st *store, enrollmentToken string, own *OwnCa) (persistedState, *caManager, error) {
	if err := st.probeWritable(); err != nil {
		return persistedState{}, nil, err
	}

	httpClient, err := util.GetRestyClientWithCustomHeaders()
	if err != nil {
		return persistedState{}, nil, err
	}
	httpClient.SetTimeout(controlPlaneTimeout)

	req := api.LoginAgentVaultProxyRequest{Method: "token", Token: enrollmentToken}
	if own != nil {
		req.RootCaCertificate = string(caPEM(own.cert))
	}
	res, err := api.CallLoginAgentVaultProxy(httpClient, req)
	if err != nil {
		if own == nil && isMissingCaRejection(err) {
			return persistedState{}, nil, errInfisicalHoldsNoCa
		}
		return persistedState{}, nil, err
	}

	config := ProxyConfig{
		TrafficPolicy: res.Config.TrafficPolicy,
		AllowedHosts:  res.Config.AllowedHosts,
		PollInterval:  res.Config.PollInterval,
	}
	if !usableProxyConfig(config) {
		return persistedState{}, nil, fmt.Errorf(
			"the enrollment response carried no usable proxy settings (trafficPolicy %q, pollInterval %d). Check that --domain points at Infisical and not at something answering in its place. The enrollment token has been used, so take a new one from the Proxies page before trying again",
			config.TrafficPolicy, config.PollInterval)
	}

	var key *ecdsa.PrivateKey
	var cert *x509.Certificate
	if own != nil {
		key, cert = own.key, own.cert
	} else {
		if res.RootCa == nil {
			return persistedState{}, nil, errInfisicalHoldsNoCa
		}
		key, cert, err = parseCaPair([]byte(res.RootCa.Certificate), []byte(res.RootCa.PrivateKey))
		if err != nil {
			return persistedState{}, nil, fmt.Errorf("the certificate authority Infisical returned can't be used: %w", err)
		}
	}

	state := persistedState{
		ProxyID:         res.ProxyID,
		ProxyName:       res.Name,
		AccessToken:     res.AccessToken,
		EnrollmentToken: enrollmentToken,
		Config:          config,
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
func resolveState(st *store, enrollmentToken string, own *OwnCa) (persistedState, *caManager, bool, error) {
	stored, confFound, stateErr := st.loadState()
	key, cert, caErr := st.loadCa()
	hasCa := caErr == nil && key != nil && cert != nil
	hasToken := stateErr == nil && stored.AccessToken != ""

	alreadyEnrolled := hasToken && hasCa

	// A token is checked before the damage errors: the messages for damaged state say to enroll again
	// with a new token, so that has to work on the same damage.
	if enrollmentToken != "" {
		if alreadyEnrolled && stored.EnrollmentToken == enrollmentToken {
			if err := checkStoredPolicy(st, stored); err != nil {
				return persistedState{}, nil, false, err
			}
			log.Info().Msg("agent-vault: this enrollment token already enrolled this proxy, resuming")
			warnIfOwnCaIgnored(own, cert)
			return stored, newCaManager(key, cert), false, nil
		}
		// Re-enrolling replaces the certificate authority, so anything holding a copy of the old one stops
		// trusting the proxy. That holds whether or not the rest of the state survived beside it.
		if hasCa || caErr != nil {
			log.Warn().Msg("agent-vault: enrolling with a new token replaces this proxy's certificate authority")
		}
		state, ca, err := enroll(st, enrollmentToken, own)
		return state, ca, err == nil, err
	}

	if stateErr != nil {
		return persistedState{}, nil, false, stateErr
	}
	if caErr != nil {
		return persistedState{}, nil, false, caErr
	}

	// Only a directory with nothing in it is a first run. Anything else is damage, and saying "not
	// enrolled" would send the operator for a new token, which replaces a certificate authority that may
	// still be intact on disk.
	switch {
	case !confFound && !hasCa:
		return persistedState{}, nil, false, errors.New(
			"this proxy has not enrolled yet. Run it once with --enrollment-token, using the token shown when the proxy was created")
	case !hasToken && !hasCa:
		// Settings alone: proxy.json is there but holds no token, and there is no certificate authority. Without
		// this arm the state fell through and the proxy came up with a nil CA and an empty fingerprint.
		return persistedState{}, nil, false, fmt.Errorf(
			"%s in %s has no access token and there is no certificate authority beside it, so this proxy was never fully enrolled. Enroll with a new token from the Proxies page",
			proxyStateFile, st.dir)
	case hasCa && !hasToken:
		return persistedState{}, nil, false, fmt.Errorf(
			"the certificate authority in %s is intact but %s has no access token, so this proxy's state is incomplete. Restore %s from a backup to keep the certificate authority, or enroll again with a new token from the Proxies page, which replaces it and means every agent trusting the old one has to be restarted",
			st.dir, proxyStateFile, proxyStateFile)
	case hasToken && !hasCa:
		return persistedState{}, nil, false, fmt.Errorf(
			"%s in %s holds an access token but the certificate authority (%s, %s) is missing. Restore both files from a backup, or enroll again with a new token from the Proxies page, which issues a new certificate authority",
			proxyStateFile, st.dir, caKeyFile, caCertFile)
	}

	if err := checkStoredPolicy(st, stored); err != nil {
		return persistedState{}, nil, false, err
	}

	warnIfOwnCaIgnored(own, cert)
	return stored, newCaManager(key, cert), false, nil
}

// Infisical recorded the CA this proxy enrolled with, so a different one passed on a later run is not served.
func warnIfOwnCaIgnored(own *OwnCa, enrolled *x509.Certificate) {
	if own == nil || bytes.Equal(own.cert.Raw, enrolled.Raw) {
		return
	}
	log.Warn().Msg("agent-vault: --ca-cert and --ca-key differ from the certificate authority this proxy enrolled with, so they are ignored. Enroll again with a new token to serve them")
}

// Every path that serves persisted state runs this. A file whose policy does not parse must never reach
// the proxy: blocksOffBundle compares against TrafficPolicyBundleHosts, so an empty value blocks nothing
// and a proxy the operator restricted would come up reaching everything.
func checkStoredPolicy(st *store, stored persistedState) error {
	if isTrafficPolicy(stored.Config.TrafficPolicy) {
		return nil
	}
	return fmt.Errorf(
		"%s in %s has an unrecognised trafficPolicy value %q; it must be %s or %s. If the file predates the trafficPolicy rename, enroll again with a new token from the Proxies page",
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
	state, ca, enrolledNow, err := resolveState(st, enrollmentToken, opts.OwnCa)
	if err != nil {
		return err
	}
	if opts.OnReady != nil {
		opts.OnReady(enrolledNow)
	}

	return serve(opts, st, state, ca)
}

// Tests shorten these so that running out of retries takes milliseconds.
var (
	bootstrapRetryWindow  = 60 * time.Second
	bootstrapFirstBackoff = 1 * time.Second
)

const bootstrapMaxBackoff = 10 * time.Second

var errBootstrapUnreachable = errors.New("can't reach Infisical to load this proxy's settings and CA; not serving")

// A 4xx is Infisical's answer, such as a rotated token or a Standard proxy, so it ends the run at once.
// Anything else may be Infisical restarting.
func isBootstrapRetryable(err error) bool {
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) {
		return true
	}
	return apiErr.StatusCode >= http.StatusInternalServerError || apiErr.StatusCode == http.StatusTooManyRequests
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

	deadline := time.Now().Add(bootstrapRetryWindow)
	backoff := bootstrapFirstBackoff
	for {
		httpClient.SetTimeout(min(controlPlaneTimeout, time.Until(deadline)))
		res, err := api.CallAgentVaultProxyBootstrap(httpClient, req)
		if err == nil || !isBootstrapRetryable(err) {
			return res, err
		}
		if time.Until(deadline) < backoff {
			log.Warn().Err(err).Msg("agent-vault: failed to load this proxy's settings from Infisical")
			return api.AgentVaultProxyBootstrapResponse{}, errBootstrapUnreachable
		}
		log.Warn().Err(err).Dur("retryIn", backoff).Msg("agent-vault: failed to load this proxy's settings from Infisical, retrying")
		time.Sleep(backoff)
		backoff = min(backoff*2, bootstrapMaxBackoff)
	}
}

// StartWithProxyToken serves an HA proxy. Every copy started from the same token loads its settings and
// CA from Infisical, so nothing is read from or written to disk, and nothing is served before Infisical
// has answered.
func StartWithProxyToken(opts Options, proxyToken string) error {
	log.Info().Msg("agent-vault: proxy token mode: nothing is saved to disk")

	state, ca, err := loadFromProxyToken(proxyToken, opts.OwnCa)
	if err != nil {
		return err
	}
	if opts.OnReady != nil {
		opts.OnReady(false)
	}
	return serve(opts, nil, state, ca)
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

// A nil store is proxy token mode: settings changes apply in memory only.
func serve(opts Options, st *store, state persistedState, ca *caManager) error {
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
		listening = listening.Str("dataDir", opts.DataDir)
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
	"Infisical no longer accepts this proxy's token: its access was revoked or the proxy was deleted. Enroll again with a new enrollment token from the Proxies page")

var errHaProxyTokenRejected = errors.New(
	"Infisical no longer accepts this proxy token: it was rotated or revoked, or the proxy was deleted. Restart with the current proxy token from the Proxies page")

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
			if st == nil {
				fatal <- errHaProxyTokenRejected
			} else {
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
