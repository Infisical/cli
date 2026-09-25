package agent

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	pam "github.com/Infisical/infisical-merge/packages/pam/local"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

// ErrSessionProviderClosed is returned when a session is requested after shutdown has begun. A
// connection accepted during teardown must not be able to create a session we would never end.
var ErrSessionProviderClosed = errors.New("session provider is shut down")

// isShutdownError reports whether a session could not be created because the run is ending, which
// is an ordinary race with teardown rather than a failure worth reporting.
func isShutdownError(err error) bool {
	return errors.Is(err, ErrSessionProviderClosed) || errors.Is(err, context.Canceled)
}

// trackedSession is one PAM session plus the connections currently streaming through it. A session
// is only ended once nothing is using it, so retiring the session one connection found unusable
// cannot cut off another connection mid-transfer.
type trackedSession struct {
	session pam.LiveSession
	users   int
	// retired means the session will not be handed out again; it ends when its last user releases.
	retired bool
	// ended means termination has already been started, so it never happens twice.
	ended bool
}

// LazySessionProvider creates a PAM session the first time one is needed and reuses it until its
// deadline passes, at which point the next request creates a fresh one. Accounts that are never
// connected to never create a session at all, so they leave no session record behind.
//
// Every session it stops handing out is terminated, so no session it abandons stays live in the
// org until its own deadline passes.
type LazySessionProvider struct {
	httpClient *resty.Client
	path       string
	reason     string
	duration   time.Duration

	// terminate ends one session. Set by the proxy that owns this provider, because the preferred
	// termination path goes through the relay and gateway the proxy knows how to dial.
	terminate func(pam.LiveSession)
	// createSession is the API call that mints a session, indirected so the lifecycle around it can
	// be exercised without one.
	createSession func() (*api.PAMAccessResponse, error)
	// raiseApproval submits an access request for this account, indirected for the same reason.
	raiseApproval func() (string, error)

	// requestApproval allows raising an access request when the API gates this account behind one.
	requestApproval bool
	// approvalRaised records that a request is in flight for the gate currently being waited on, so a
	// burst of connections submits one request rather than one per connection. It is cleared as soon
	// as a session is created: grants are time-bounded, and the grant that opened this gate expiring
	// has to raise a fresh request rather than wait on the one it already consumed.
	approvalRaised bool

	mu      sync.Mutex
	current *trackedSession
	// retired holds sessions that are no longer handed out but are still in use, keyed by session
	// ID, so shutdown can end them even if their last user never releases.
	retired map[string]*trackedSession
	closed  bool

	// pending tracks in-flight terminations so shutdown can wait for them.
	pending sync.WaitGroup
}

func NewLazySessionProvider(httpClient *resty.Client, path, reason string, duration time.Duration, requestApproval bool) *LazySessionProvider {
	provider := &LazySessionProvider{
		httpClient:      httpClient,
		path:            path,
		reason:          reason,
		duration:        duration,
		requestApproval: requestApproval,
		retired:         make(map[string]*trackedSession),
	}
	provider.createSession = func() (*api.PAMAccessResponse, error) {
		// No target host: Windows AD is the only account type that picks one, and it is withheld from
		// the agent flow.
		return pam.CreateSession(provider.httpClient, provider.path, provider.reason, "", provider.duration)
	}
	provider.raiseApproval = func() (string, error) {
		return raiseAccessRequest(provider.httpClient, provider.path, provider.reason, provider.duration)
	}
	return provider
}

// SetTerminator installs the function used to end sessions this provider gives up on. Without it a
// retired session is only dropped locally, so proxies must set it at construction.
func (l *LazySessionProvider) SetTerminator(terminate func(pam.LiveSession)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.terminate = terminate
}

// Ensure returns the live session, creating one if there is not already a usable one.
// Concurrent callers serialize here, so a burst of first connections produces one session.
//
// The caller is not registered as a user of the session, so it may be terminated underneath a
// long-running caller. Anything holding the session for the length of a connection wants Acquire.
func (l *LazySessionProvider) Ensure(ctx context.Context) (pam.LiveSession, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	tracked, err := l.ensureLocked(ctx)
	if err != nil {
		return pam.LiveSession{}, err
	}
	return tracked.session, nil
}

// Acquire returns the live session along with a release function the caller must call when it is
// done with it. The session stays alive until every acquirer has released it, so ending a session
// abandoned by one connection cannot break another that is still streaming through it.
func (l *LazySessionProvider) Acquire(ctx context.Context) (pam.LiveSession, func(), error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	tracked, err := l.ensureLocked(ctx)
	if err != nil {
		return pam.LiveSession{}, func() {}, err
	}

	tracked.users++

	var once sync.Once
	release := func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.releaseLocked(tracked)
		})
	}
	return tracked.session, release, nil
}

func (l *LazySessionProvider) ensureLocked(ctx context.Context) (*trackedSession, error) {
	if l.closed {
		return nil, ErrSessionProviderClosed
	}
	// Also checked after taking the lock: shutdown, or the client that wanted this session, may
	// have gone away while we waited behind another caller's session creation.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if l.current != nil {
		if time.Now().Before(l.current.session.Expiry) {
			return l.current, nil
		}
		// Our deadline has passed, so this session can't be handed out again. It still gets retired
		// and terminated: the API caps duration at the account's maximum, so a session we consider
		// expired may still be live server-side.
		l.retireCurrentLocked()
	}

	log.Debug().Str("account", l.path).Msg("Creating PAM session on demand")

	response, err := l.createSession()
	if err != nil {
		// An approval gate isn't a failure to report and move past. It is the moment the access
		// request gets raised, and every later connection is a retry that succeeds once approved.
		if isApprovalGate(err) {
			return nil, l.handleApprovalGateLocked(err)
		}
		return nil, fmt.Errorf("failed to create PAM session for %s: %w", l.path, err)
	}

	l.current = &trackedSession{session: pam.NewLiveSession(response, time.Now().Add(l.duration))}

	// Whatever gate this account was behind is open now, and the request that opened it is spent. A
	// grant is time-bounded, so when it runs out the next refusal has to raise a new request; leaving
	// this set would leave the account waiting forever on an approval it already used.
	l.approvalRaised = false

	log.Info().Str("account", l.path).Str("sessionId", l.current.session.SessionId).Msg("PAM session created")
	return l.current, nil
}

// handleApprovalGateLocked raises the access request for an account the API has just refused, and
// reports what the caller is now waiting for.
//
// The request is raised here rather than when the run starts, for the same reason sessions are
// created here: an account the agent never touches should cost a reviewer nothing. A run over fifty
// accounts must not put fifty requests in front of somebody for the two the agent will use.
//
// This is reached for a first approval and for a grant that has since run out, and treats them the
// same: raise a request, keep the port, come back to life on the first connection after approval.
// The proxy is meant to outlive any single grant, so a grant expiring is a normal part of a long run
// rather than the end of the account.
//
// Everything except "a request is already in flight" is read from the refusal each time rather than
// remembered, so approvers added to a folder part-way through a run take effect on the next
// connection instead of needing the run restarted.
func (l *LazySessionProvider) handleApprovalGateLocked(cause error) error {
	gate := readApprovalGate(cause)

	if !l.requestApproval {
		return fmt.Errorf("%s requires approval, and --no-approval-request was set", l.path)
	}

	// A folder with no approvers can never grant a request, so say that instead of submitting one
	// nobody is able to act on.
	if !gate.hasApprovalPolicy {
		return fmt.Errorf(
			"%s requires approval, but its folder has no approvers configured. "+
				"Ask a folder admin to add approvers under the folder's Approvals tab", l.path)
	}

	// One request per gate. A burst of connections to a gated account arrives here once each, and a
	// second submission would only be rejected as a duplicate.
	if l.approvalRaised || gate.hasPendingRequest {
		l.approvalRaised = true
		return awaitingApprovalError(l.path, gate.expired)
	}

	requestID, err := l.raiseApproval()
	if err != nil {
		// Deliberately left retryable: approval is a human process measured in minutes and the agent
		// will reach for this account again, so a submission that failed on a blip shouldn't sink the
		// account for the rest of the run.
		log.Error().Err(err).Str("account", l.path).Msg("Failed to raise access request")
		return fmt.Errorf("%s requires approval and the access request could not be raised: %s",
			l.path, approvalErrorText(err))
	}

	l.approvalRaised = true
	log.Info().Str("account", l.path).Str("requestId", requestID).Bool("regrant", gate.expired).
		Msg("Access request raised on demand, awaiting approval")

	return awaitingApprovalError(l.path, gate.expired)
}

// Current returns the live session without creating one.
func (l *LazySessionProvider) Current() (pam.LiveSession, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.current == nil {
		return pam.LiveSession{}, false
	}
	return l.current.session, true
}

// Discard retires the given session so the next connection creates a fresh one, and terminates it
// once its last user releases it. Used when a connection finds the session unusable.
//
// A session another connection has already replaced is left alone: whoever replaced it owns ending
// it, and terminating it again would end a session we no longer hold.
func (l *LazySessionProvider) Discard(session pam.LiveSession) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.current == nil || l.current.session.SessionId != session.SessionId {
		return
	}
	l.retireCurrentLocked()
}

// Close stops the provider from handing out or creating any further session, and retires the
// current one. Sessions still in use are ended by their last release; Drain finishes the job.
func (l *LazySessionProvider) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.closed = true
	l.retireCurrentLocked()
}

// Drain ends any retired session still held by a connection that outlived shutdown, then waits for
// every termination to finish. Called after waiting for connections, so that a connection which
// refused to close cannot leave a live privileged session behind when the process exits.
func (l *LazySessionProvider) Drain(timeout time.Duration) {
	l.mu.Lock()
	for _, tracked := range l.retired {
		log.Debug().Str("account", l.path).Str("sessionId", tracked.session.SessionId).
			Msg("Ending PAM session still held at shutdown")
		l.endLocked(tracked)
	}
	l.mu.Unlock()

	done := make(chan struct{})
	go func() {
		l.pending.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		log.Warn().Str("account", l.path).Msg("Timed out ending PAM sessions; they will expire on their own")
	}
}

func (l *LazySessionProvider) releaseLocked(tracked *trackedSession) {
	tracked.users--
	if tracked.users <= 0 && tracked.retired {
		l.endLocked(tracked)
	}
}

// retireCurrentLocked stops handing out the cached session, ending it now if nothing is using it.
func (l *LazySessionProvider) retireCurrentLocked() {
	tracked := l.current
	if tracked == nil {
		return
	}

	l.current = nil
	tracked.retired = true

	if tracked.users <= 0 {
		l.endLocked(tracked)
		return
	}
	l.retired[tracked.session.SessionId] = tracked
}

// endLocked starts terminating a session, at most once. Termination dials the relay, so it runs in
// the background, leaving the lock free for the connections waiting on it.
func (l *LazySessionProvider) endLocked(tracked *trackedSession) {
	delete(l.retired, tracked.session.SessionId)

	if tracked.ended {
		return
	}
	tracked.ended = true

	if l.terminate == nil {
		log.Warn().Str("account", l.path).Str("sessionId", tracked.session.SessionId).
			Msg("No terminator configured; PAM session will expire on its own")
		return
	}

	terminate := l.terminate
	session := tracked.session

	l.pending.Add(1)
	go func() {
		defer l.pending.Done()
		terminate(session)
	}()
}
