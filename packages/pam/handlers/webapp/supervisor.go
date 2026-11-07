package webapp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
)

type surface struct {
	capture atomic.Pointer[captureSettings]
	ready   bool

	Seq        uint32 `json:"surfaceSeq"`
	URL        string `json:"url"`
	Title      string `json:"title"`
	target     string
	session    string
	configured chan struct{}
}

var errReadinessRefused = errors.New("readiness-refused")
var errExpired = errors.New("expired")

type queuedAction struct {
	stream  *liveStream
	message message
	input   bool
}
type reportReply struct {
	api.PAMWebStateResponse
	refused bool
}

type webRecording interface {
	Done() <-chan struct{}

	LogSessionEvent(session.SessionEvent) error
	Close() error
	ChunkCount() int
	Finish(api.PAMWebFinal, string) error
}

type Supervisor struct {
	metricsReadyAt     time.Time
	probeMu            sync.Mutex
	probeCancel        context.CancelFunc
	probeInvalidated   string
	probeInvalidations int
	pendingFrame       *deferredFrame
	frameTimer         *time.Timer
	appOpened          bool

	droppedLive  uint64
	reportDone   chan struct{}
	terminalDone chan struct{}
	dpr          float64

	createMu      sync.Mutex
	controllerGen uint32

	recordMu        sync.Mutex
	loggerClosed    bool
	recordingFailed atomic.Bool
	failureUs       int64

	mu                                          sync.Mutex
	allocMu                                     sync.Mutex
	registry                                    *Registry
	id                                          string
	alloc                                       allocation
	credentials                                 *session.PAMCredentials
	started                                     time.Time
	ctx                                         context.Context
	cancel                                      context.CancelFunc
	clock                                       *leaseClock
	connector                                   *worker
	browser                                     *worker
	cdp                                         *cdpClient
	recorder                                    webRecording
	controller                                  *liveStream
	highestGen                                  uint32
	ready                                       bool
	ending                                      bool
	endOnce                                     sync.Once
	ended                                       chan struct{}
	provisioned                                 chan struct{}
	connectorStopped                            chan struct{}
	deregister                                  func()
	grace                                       *time.Timer
	actions                                     chan queuedAction
	surfaces                                    map[uint32]*surface
	nextSurface                                 uint32
	active                                      uint32
	startSurface                                uint32
	viewportGen                                 uint32
	frameViewportGen                            uint32
	width, height                               int
	frameSeq                                    uint32
	lastInput                                   uint32
	lastFrame                                   time.Time
	lastMove                                    time.Time
	droppedCapture, droppedMoves, droppedInputs uint64
	lastLiveFrame                               []byte
	dialog                                      map[string]any
	dialogSeq                                   uint32
	heldKeys                                    map[string]message
	heldButtons                                 map[string]message
	gaps                                        []api.PAMWebGap
	reportNotify                                chan struct{}
	reportWaiters                               map[uint64]chan reportReply
}

func newSupervisor(r *Registry, id string, a allocation, credentials *session.PAMCredentials) *Supervisor {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Supervisor{reportDone: make(chan struct{}), terminalDone: make(chan struct{}), registry: r, id: id, alloc: a, credentials: credentials, started: time.Now(), ctx: ctx, cancel: cancel, clock: newLeaseClock(credentials.ExpiresAt, credentials.LeaseDeadline, 0), ended: make(chan struct{}), provisioned: make(chan struct{}), connectorStopped: make(chan struct{}), actions: make(chan queuedAction, 600), surfaces: map[uint32]*surface{}, viewportGen: 1, width: 1280, height: 720, dpr: 1, heldKeys: map[string]message{}, heldButtons: map[string]message{}, reportNotify: make(chan struct{}, 1), reportWaiters: map[uint64]chan reportReply{}}
	return s
}

func (s *Supervisor) saveAllocLocked() error {
	state := s.alloc
	state.PendingReports = append([]api.PAMWebStateRequest{}, s.alloc.PendingReports...)
	for i := range state.PendingReports {
		state.PendingReports[i].UploadToken = ""
	}
	b, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return session.AtomicWrite(allocPath(s.id), b)
}
func (s *Supervisor) checkCancelled() error {
	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	default:
	}
	if _, err := os.Stat(tombPath(s.id)); err == nil {
		return errors.New("session cancelled")
	}
	return nil
}

func (s *Supervisor) record(v any) error {
	s.recordMu.Lock()
	defer s.recordMu.Unlock()
	if s.loggerClosed {
		return nil
	}
	if s.recorder == nil {
		return errors.New("recorder unavailable")
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	err = s.recorder.LogSessionEvent(session.SessionEvent{Timestamp: time.Now(), EventType: session.SessionEventWeb, ChannelType: session.SessionChannelWeb, Data: b, ElapsedTime: time.Since(s.started).Seconds()})
	if err != nil {
		if !s.recordingFailed.Load() {
			s.recordingFailed.Store(true)
			s.failureUs = time.Since(s.started).Microseconds()
		}
		s.allocMu.Lock()
		s.alloc.RecordingFailed = true
		_ = s.saveAllocLocked()
		s.allocMu.Unlock()
		go s.End("recording-failed")
	}
	return err
}

func (s *Supervisor) lifecycle(phase, reason string) error {
	return s.record(map[string]any{"type": "lifecycle", "phase": phase, "reason": reason, "imageDigest": s.registry.Options.Image, "allocationGen": s.alloc.AllocationGen})
}

func (s *Supervisor) send(v any) {
	if s.controller != nil {
		s.controller.send(v)
	}
}

func (s *Supervisor) queueReport(state, reason string) <-chan reportReply {
	s.mu.Lock()
	defer s.mu.Unlock()
	if state == "active" && s.controller == nil {
		state = "detached"
	}
	if s.ending && state != "ending" && state != "stop-unconfirmed" && state != "stopped" {
		ch := make(chan reportReply, 1)
		ch <- reportReply{PAMWebStateResponse: api.PAMWebStateResponse{Cancel: true}, refused: true}
		return ch
	}
	gen, frame := s.controllerGen, s.frameSeq
	s.allocMu.Lock()
	defer s.allocMu.Unlock()
	if state != "detached" || s.appOpened {
		s.alloc.State = state
	}
	s.alloc.ReportSeq++
	seq := s.alloc.ReportSeq
	secrets := s.registry.Credentials.GetRecordingSecrets(s.id)
	token := ""
	if secrets != nil {
		token = secrets.UploadToken
	}
	count := 0
	if s.recorder != nil {
		count = s.recorder.ChunkCount()
	}
	s.alloc.PendingReports = append(s.alloc.PendingReports, api.PAMWebStateRequest{ReportSeq: seq, AllocationGen: s.alloc.AllocationGen, ControllerGen: gen, State: state, Reason: truncate(reason, 500), ChunksEmitted: count, LastFrameSeq: frame, UploadToken: token})
	ch := make(chan reportReply, 1)
	s.reportWaiters[seq] = ch
	if err := s.saveAllocLocked(); err != nil {
		go s.End("recording-failed")
	}
	select {
	case s.reportNotify <- struct{}{}:
	default:
	}
	return ch
}

func (s *Supervisor) resolveReport(req api.PAMWebStateRequest, response api.PAMWebStateResponse, status int, deadline time.Time) error {
	s.allocMu.Lock()
	defer s.allocMu.Unlock()
	s.alloc.PendingReports = s.alloc.PendingReports[1:]
	if status != 0 {
		s.alloc.LastRefusedReport = req.ReportSeq
		s.alloc.LastReportStatus = status
	} else {
		if !(req.State == "detached" && (s.alloc.ReportedState == "" || s.alloc.ReportedState == "provisioning" || s.alloc.ReportedState == "provisioned" || s.alloc.ReportedState == "recording-ready")) {
			s.alloc.ReportedState = req.State
		}
		if !deadline.IsZero() {
			s.alloc.LeaseUntil = deadline
		}
	}
	waiter := s.reportWaiters[req.ReportSeq]
	delete(s.reportWaiters, req.ReportSeq)
	err := s.saveAllocLocked()
	if waiter != nil {
		waiter <- reportReply{PAMWebStateResponse: response, refused: status != 0}
	}
	return err
}

func (s *Supervisor) reportLoop() {
	defer close(s.reportDone)
	backoff := 5 * time.Second
	var retryAt time.Time
	for {
		s.allocMu.Lock()
		if len(s.alloc.PendingReports) == 0 {
			stopped := s.alloc.State == "stopped"
			s.allocMu.Unlock()
			if stopped {
				return
			}
			select {
			case <-s.reportNotify:
			case <-time.After(5 * time.Second):
			}
			continue
		}
		req := s.alloc.PendingReports[0]
		s.allocMu.Unlock()
		if wait := time.Until(retryAt); wait > 0 {
			<-time.After(wait)
		}
		if req.UploadToken == "" {
			if s.registry.Credentials.GetRecordingSecrets(s.id) == nil {
				if err := s.registry.Credentials.RestoreWebRecordingSecrets(s.id); err != nil && !os.IsNotExist(err) {
					retryAt = time.Now().Add(backoff)
					backoff = min(backoff*2, 5*time.Minute)
					continue
				}
			}
			if secrets := s.registry.Credentials.GetRecordingSecrets(s.id); secrets != nil {
				req.UploadToken = secrets.UploadToken
			}
		}
		req.Reason = truncate(req.Reason, 500)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		var response api.PAMWebStateResponse
		err := api.CallPAMWebReport(ctx, s.registry.Client, s.id, "web-app/state", req, &response)
		received := time.Now()
		cancel()
		status, refused := api.PAMReportRefusal(err)
		if err != nil && !refused {
			retryAt = time.Now().Add(backoff)
			backoff = min(backoff*2, 5*time.Minute)
			continue
		}
		backoff = 5 * time.Second
		retryAt = time.Time{}
		if refused {
			log.Warn().Int("status", status).Str("state", req.State).Str("sessionId", s.id).Msg("PAM browser state report refused")
			if err := s.resolveReport(req, api.PAMWebStateResponse{Cancel: true}, status, time.Time{}); err != nil {
				go s.End("recording-failed")
			}
			if req.State == "stopped" {
				return
			}
			if (status == 401 || status == 403) && req.State != "recording-ready" {
				go s.End("access-lost")
			}
			continue
		}
		if !response.Cancel && (response.ExpiresAt.IsZero() || response.ExpiresAt.After(s.credentials.ExpiresAt) || response.LeaseUntil.After(response.ExpiresAt) || response.LeaseSeconds <= 0 || response.LeaseSeconds > 45) {
			_ = s.resolveReport(req, api.PAMWebStateResponse{Cancel: true}, 400, time.Time{})
			go s.End("invalid-lease")
			if req.State == "stopped" {
				return
			}
			continue
		}
		var deadline time.Time
		if !response.Cancel {
			deadline = received.Add(time.Duration(response.LeaseSeconds) * time.Second)
		}
		if err := s.resolveReport(req, response, 0, deadline); err != nil {
			go s.End("recording-failed")
		}
		if response.Cancel {
			if response.LeaseSeconds == 0 {
				go s.End("expired")
			} else if req.State != "recording-ready" {
				go s.End("cancelled")
			}
		} else {
			s.clock.Renew(deadline)
			s.mu.Lock()
			s.credentials.LeaseUntil = response.LeaseUntil
			s.credentials.LeaseDeadline = deadline
			s.credentials.LeaseSeconds = response.LeaseSeconds
			s.send(map[string]any{"t": "deadline", "expiresAt": s.credentials.ExpiresAt, "leaseUntil": response.LeaseUntil})
			connector, browser := s.connector, s.browser
			s.mu.Unlock()
			for _, worker := range []*worker{connector, browser} {
				if worker != nil {
					remaining := max(0, int(time.Until(deadline)/time.Second))
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					_ = worker.control(ctx, map[string]any{"c": "lease", "leaseSeconds": remaining})
					cancel()
				}
			}
		}
		if req.State == "stopped" {
			return
		}
	}
}

func (s *Supervisor) run() {
	go func() {
		select {
		case <-s.clock.done:
			reason := "lease-expired"
			if !time.Now().Before(s.credentials.ExpiresAt) {
				reason = "expired"
			}
			s.End(reason)
		case <-s.ended:
		}
	}()
	if err := s.provision(); err != nil {
		if errors.Is(err, errExpired) {
			s.End("expired")
			return
		}
		if errors.Is(err, errReadinessRefused) {
			s.queueReport("failed", "readiness-refused")
			s.End("readiness-refused")
			return
		}
		if s.ctx.Err() != nil {
			s.End("cancelled")
			return
		}
		if s.recorder != nil {
			_ = s.lifecycle("failed", err.Error())
		}
		s.queueReport("failed", "provisioning-failed")
		s.End("provisioning-failed")
		return
	}
	go s.dispatchLoop()
	go s.monitor()
	close(s.provisioned)
}

func (s *Supervisor) createWorker(role string) (*worker, error) {
	s.createMu.Lock()
	defer s.createMu.Unlock()
	if err := s.checkCancelled(); err != nil {
		return nil, err
	}
	s.allocMu.Lock()
	if s.alloc.ContainerNames == nil {
		s.alloc.ContainerNames = map[string]string{}
	}
	s.alloc.ContainerNames[role] = "pam-" + s.id + "-" + role
	intentErr := s.saveAllocLocked()
	s.allocMu.Unlock()
	if intentErr != nil {
		return nil, intentErr
	}
	args := containerArgs(s.registry.Options, s.registry.GatewayID, s.id, s.alloc.Volume, role, s.alloc.AllocationGen, s.credentials.ExpiresAt, s.clock.Deadline(), s.width, s.height)
	id, err := s.registry.Docker.Command(s.ctx, args...)
	if err != nil {
		return nil, err
	}
	s.allocMu.Lock()
	s.alloc.ContainerIDs[role] = id
	err = s.saveAllocLocked()
	s.allocMu.Unlock()
	if err != nil {
		return nil, err
	}
	if err := s.checkCancelled(); err != nil {
		return nil, err
	}
	return s.registry.Docker.Start(s.ctx, id)
}

func (s *Supervisor) provision() error {
	if err := s.checkCancelled(); err != nil {
		return err
	}
	s.createMu.Lock()
	_, volumeErr := s.registry.Docker.Command(s.ctx, "volume", "create", "--label", "infisical.pam.gateway="+s.registry.GatewayID, "--label", "infisical.pam.session="+s.id, s.alloc.Volume)
	s.createMu.Unlock()
	if volumeErr != nil {
		return volumeErr
	}
	connector, err := s.createWorker("connector")
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.connector = connector
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(s.ctx, 20*time.Second)
	defer cancel()
	hostCtx, hostCancel := context.WithTimeout(ctx, 2*time.Second)
	hosts := discoverHostAddresses(hostCtx, nil)
	hostCancel()
	policy := ConnectorPolicy{C: "policy", AllowedDestinations: s.credentials.WebConnection.AllowedDestinations, DenyCIDRs: s.credentials.WebConnection.ExtraDenyCIDRs, HostAddresses: hosts}
	if err := connector.control(ctx, policy); err != nil {
		return err
	}
	if _, err := connector.ready(ctx); err != nil {
		return err
	}
	go s.connectorEvents()
	browser, err := s.createWorker("browser")
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.browser = browser
	s.cdp = browser.cdp
	s.mu.Unlock()
	version, err := browser.ready(ctx)
	if err != nil {
		return err
	}
	if !supportedBrowser(version) {
		return errors.New("unsupported-browser")
	}
	if err := s.checkCancelled(); err != nil {
		return err
	}
	s.createMu.Lock()
	if err := s.checkCancelled(); err != nil {
		s.createMu.Unlock()
		return err
	}
	recorder, err := session.NewWebRecording(s.id, s.credentials.ExpiresAt, s.registry.Credentials, s.registry.Client)
	if err != nil {
		s.createMu.Unlock()
		return err
	}
	s.recordMu.Lock()
	s.recorder = recorder
	s.recordMu.Unlock()
	s.createMu.Unlock()
	if err := s.lifecycle("provisioning", ""); err != nil {
		return err
	}
	s.queueReport("provisioning", "")
	if err := s.record(map[string]any{"type": "lifecycle", "phase": "provisioned", "browserVersion": version, "imageDigest": s.registry.Options.Image, "allocationGen": s.alloc.AllocationGen}); err != nil {
		return err
	}
	s.queueReport("provisioned", "")
	go s.browserEvents()
	for _, call := range []struct {
		method string
		params any
	}{{"Target.setDiscoverTargets", map[string]any{"discover": true}}, {"Target.setAutoAttach", map[string]any{"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true}}, {"Browser.setDownloadBehavior", map[string]any{"behavior": "deny"}}} {
		if err := s.call("", call.method, call.params, nil); err != nil {
			return err
		}
	}
	var target struct {
		TargetID string `json:"targetId"`
	}
	if err := s.call("", "Target.createTarget", map[string]any{"url": "about:blank"}, &target); err != nil {
		return err
	}
	var start *surface
	for start == nil {
		s.mu.Lock()
		for _, v := range s.surfaces {
			if v.target == target.TargetID {
				start = v
				break
			}
		}
		s.mu.Unlock()
		if start != nil {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	select {
	case <-start.configured:
		if !start.ready {
			return errors.New("start surface configuration failed")
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	s.mu.Lock()
	var initialTargets []string
	for _, v := range s.surfaces {
		if v != start && v.URL == "about:blank" {
			initialTargets = append(initialTargets, v.target)
		}
	}
	s.mu.Unlock()
	for _, id := range initialTargets {
		if err := s.call("", "Target.closeTarget", map[string]any{"targetId": id}, nil); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.active = start.Seq
	s.startSurface = start.Seq
	s.mu.Unlock()
	if err := s.startCapture(start); err != nil {
		return err
	}
	for {
		s.mu.Lock()
		seen := s.frameSeq > 0
		s.mu.Unlock()
		if seen {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := s.captureProbe(); err != nil {
		return err
	}
	if err := s.lifecycle("recording-ready", ""); err != nil {
		return err
	}
	response := s.queueReport("recording-ready", "")
	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	case reply := <-response:
		if reply.Cancel {
			if reply.refused {
				return errReadinessRefused
			}
			if reply.LeaseSeconds == 0 {
				return errExpired
			}
			return errReadinessRefused
		}
	}
	if err := s.checkCancelled(); err != nil {
		return err
	}
	s.mu.Lock()
	s.ready = true
	s.send(map[string]any{"t": "phase", "phase": "opening-app", "elapsedMs": time.Since(s.started).Milliseconds()})
	s.mu.Unlock()
	if s.credentials.AuthMethod == "basic-auth" {
		if err := s.call(start.session, "Fetch.enable", map[string]any{"patterns": []any{map[string]any{"urlPattern": "*"}}, "handleAuthRequests": true}, nil); err != nil {
			return err
		}
	}
	return s.call(start.session, "Page.navigate", map[string]any{"url": s.credentials.WebConnection.StartURL}, nil)
}

func (s *Supervisor) call(target, method string, params, result any) error {
	ctx, cancel := context.WithTimeout(s.ctx, 2*time.Second)
	defer cancel()
	return s.cdp.call(ctx, target, method, params, result)
}

func (s *Supervisor) monitor() {
	heartbeat := time.NewTicker(5 * time.Second)
	defer heartbeat.Stop()
	probe := time.NewTicker(10 * time.Second)
	defer probe.Stop()
	lease := time.NewTicker(15 * time.Second)
	defer lease.Stop()
	for {
		select {
		case <-s.ended:
			return
		case <-s.browser.done:
			s.mu.Lock()
			ending := s.ending
			s.mu.Unlock()
			if ending {
				return
			}
			s.queueReport("failed", "worker-lost")
			s.End("worker-lost")
			return
		case <-s.connector.done:
			s.mu.Lock()
			ending := s.ending
			s.mu.Unlock()
			if ending {
				return
			}
			s.queueReport("failed", "connector-lost")
			s.End("connector-lost")
			return
		case <-probe.C:
			if err := s.captureProbe(); err != nil {
				s.recordingFailure(err)
				return
			}
		case <-lease.C:
			s.mu.Lock()
			state := "detached"
			if !s.appOpened {
				s.allocMu.Lock()
				state = s.alloc.State
				s.allocMu.Unlock()
			} else if s.controller != nil {
				state = "active"
			}
			s.mu.Unlock()
			s.queueReport(state, "")
		case <-heartbeat.C:
			s.mu.Lock()
			dropped := s.droppedLive
			if s.controller != nil {
				dropped += s.controller.droppedFrames()
			}
			health := map[string]any{"type": "health", "recording": "ok", "egress": "ok", "droppedLiveFrames": dropped, "droppedCaptureFrames": s.droppedCapture}
			_ = s.record(health)
			health["t"] = "health"
			delete(health, "type")
			s.send(health)
			err := s.record(map[string]any{"type": "heartbeat", "lastFrameSeq": s.frameSeq, "lastInputSeq": s.lastInput, "chunksEmitted": s.recorder.ChunkCount(), "droppedCaptureFrames": s.droppedCapture, "droppedMoves": s.droppedMoves})
			s.mu.Unlock()
			if err != nil {
				s.End("recording-failed")
				return
			}
			var size int64
			_ = filepath.WalkDir(session.GetSessionRecordingDir(), func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !d.IsDir() {
					if info, err := d.Info(); err == nil {
						size += info.Size()
					}
				}
				return nil
			})
			if size > s.registry.Options.SpoolMaxBytes {
				s.recordingFailure(errors.New("recording spool limit exceeded"))
				return
			}
		}
	}
}

func (s *Supervisor) recordingFailure(err error) {
	s.mu.Lock()
	ending := s.ending
	s.mu.Unlock()
	if ending {
		return
	}
	log.Error().Err(err).Str("sessionId", s.id).Msg("PAM browser recording failed")
	s.recordMu.Lock()
	s.recordingFailed.Store(true)
	s.failureUs = time.Since(s.started).Microseconds()
	s.recordMu.Unlock()
	s.allocMu.Lock()
	s.alloc.RecordingFailed = true
	_ = s.saveAllocLocked()
	s.allocMu.Unlock()
	s.mu.Lock()
	elapsed := time.Since(s.started).Microseconds()
	gap := api.PAMWebGap{FromElapsedUs: max(0, elapsed-10_000_000), ToElapsedUs: elapsed, Reason: "capture-failed"}
	gap.FromElapsedUs = max(0, elapsed-10_000_000)
	s.gaps = append(s.gaps, gap)
	_ = s.record(map[string]any{"type": "gap", "fromElapsedUs": gap.FromElapsedUs, "toElapsedUs": gap.ToElapsedUs, "reason": gap.Reason})
	s.send(map[string]any{"t": "health", "recording": "failed", "egress": "ok", "droppedLiveFrames": 0, "droppedCaptureFrames": s.droppedCapture})
	s.mu.Unlock()
	s.End("recording-failed")
}

func (s *Supervisor) End(reason string) {
	s.endOnce.Do(func() {
		s.mu.Lock()
		s.ending = true
		if reason == "worker-lost" || reason == "connector-lost" {
			s.gaps = append(s.gaps, api.PAMWebGap{FromElapsedUs: max(0, s.lastFrame.Sub(s.started).Microseconds()), ToElapsedUs: max(0, time.Since(s.started).Microseconds()), Reason: reason})
		}
		controller := s.controller
		s.send(map[string]any{"t": "ending", "reason": reason})
		s.mu.Unlock()
		_ = session.AtomicWrite(tombPath(s.id), []byte(reason))
		if s.connector != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			err := s.connector.control(ctx, map[string]string{"c": "shutdown"})
			if err == nil {
				select {
				case <-s.connectorStopped:
				case <-ctx.Done():
					err = ctx.Err()
				}
			}
			cancel()
			if err != nil {
				_, _ = s.registry.Docker.Command(context.Background(), "kill", s.connector.id)
			}
		}
		if s.cdp != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = s.cdp.call(ctx, "", "Browser.close", map[string]any{}, nil)
			cancel()
		}
		s.cancel()
		s.clock.Stop()
		s.cleanupContainers()
		if s.recorder != nil {
			_ = s.lifecycle("ending", reason)
		}
		s.queueReport("ending", reason)
		go func() {
			defer close(s.terminalDone)
			for {
				if s.cleanupContainers() {
					break
				}
				s.queueReport("stop-unconfirmed", reason)
				time.Sleep(15 * time.Second)
			}
			terminal := false
			if s.recorder != nil {
				s.recordMu.Lock()
				failed := s.recordingFailed.Load()
				from := s.failureUs
				s.recordMu.Unlock()
				if failed {
					gap := api.PAMWebGap{FromElapsedUs: from, ToElapsedUs: time.Since(s.started).Microseconds(), Reason: "recording-failed"}
					s.mu.Lock()
					s.gaps = append(s.gaps, gap)
					s.mu.Unlock()
					_ = s.record(map[string]any{"type": "gap", "fromElapsedUs": gap.FromElapsedUs, "toElapsedUs": gap.ToElapsedUs, "reason": gap.Reason})
				}
				terminal = s.lifecycle("ended", reason) == nil
				s.recordMu.Lock()
				if err := s.recorder.Close(); err != nil {
					s.recordingFailed.Store(true)
				}
				s.loggerClosed = true
				s.recordMu.Unlock()
			}
			s.mu.Lock()
			final := api.PAMWebFinal{RecordingFailed: s.recordingFailed.Load(), Gaps: s.gaps, DroppedCaptureFrames: s.droppedCapture, DroppedMoves: s.droppedMoves, TerminalEventIncluded: terminal}
			if s.recorder == nil {
				final.RecordingFailed = s.alloc.RecordingFailed
				final.Gaps = append(final.Gaps, api.PAMWebGap{FromElapsedUs: 0, ToElapsedUs: max(0, time.Since(s.alloc.CreatedAt).Microseconds()), Reason: "worker-lost"})
			}
			s.allocMu.Lock()
			s.alloc.TerminalEventIncluded = terminal
			s.alloc.RecordingFailed = final.RecordingFailed
			s.alloc.Gaps = final.Gaps
			s.alloc.DroppedCaptureFrames = final.DroppedCaptureFrames
			s.alloc.DroppedMoves = final.DroppedMoves
			s.alloc.EndReason = truncate(reason, 64)
			_ = s.saveAllocLocked()
			s.allocMu.Unlock()
			s.mu.Unlock()
			stopped := s.queueReport("stopped", reason)
			s.mu.Lock()
			if controller != nil {
				controller.send(map[string]any{"t": "ended", "reason": reason, "confirmed": true})
				go controller.flushClose()
			}
			s.mu.Unlock()
			if s.deregister != nil {
				s.deregister()
			}
			s.registry.mu.Lock()
			delete(s.registry.sessions, s.id)
			if s.registry.reportRecoveries == nil {
				s.registry.reportRecoveries = map[string]bool{}
			}
			s.registry.reportRecoveries[s.id] = true
			s.registry.mu.Unlock()
			defer func() {
				s.registry.mu.Lock()
				delete(s.registry.reportRecoveries, s.id)
				s.registry.mu.Unlock()
			}()
			close(s.ended)
			<-stopped
			if s.recorder != nil {
				if s.recorder.Finish(final, truncate(reason, 64)) == nil {
					<-s.recorder.Done()
				}
			} else {
				if recovered, err := session.RecoverWebRecording(s.id, s.registry.Credentials, s.registry.Client, final, truncate(reason, 64)); err == nil && recovered != nil {
					<-recovered.Done()
				}
			}
		}()
	})
}

func (s *Supervisor) cleanupContainers() bool {
	s.createMu.Lock()
	discoveryErr := s.recoverContainerIDs()
	s.allocMu.Lock()
	ids := make([]string, 0, len(s.alloc.ContainerIDs))
	for _, id := range s.alloc.ContainerIDs {
		ids = append(ids, id)
	}
	volume := s.alloc.Volume
	s.allocMu.Unlock()
	s.createMu.Unlock()
	if discoveryErr != nil {
		log.Warn().Err(discoveryErr).Str("sessionId", s.id).Msg("PAM browser container reconciliation failed")
	}
	for _, id := range ids {
		_, _ = s.registry.Docker.Command(context.Background(), "kill", id)
		_, _ = s.registry.Docker.Command(context.Background(), "rm", "--force", id)
	}
	_, _ = s.registry.Docker.Command(context.Background(), "volume", "rm", volume)
	confirmed := discoveryErr == nil
	for _, resource := range append(ids, volume) {
		output, err := s.registry.Docker.Command(context.Background(), "inspect", resource)
		if err == nil || !strings.Contains(strings.ToLower(output), "no such object") {
			confirmed = false
		}
	}
	return confirmed
}

func (s *Supervisor) recoverContainerIDs() error {
	s.allocMu.Lock()
	names := map[string]string{}
	for role, name := range s.alloc.ContainerNames {
		if s.alloc.ContainerIDs[role] == "" {
			names[role] = name
		}
	}
	s.allocMu.Unlock()
	if len(names) == 0 {
		return nil
	}
	output, err := s.registry.Docker.Command(context.Background(), "ps", "--all", "--filter", "label=infisical.pam.gateway="+s.registry.GatewayID, "--filter", "label=infisical.pam.session="+s.id, "--format", "{{.ID}} {{.Names}}")
	if err != nil {
		return err
	}
	s.allocMu.Lock()
	defer s.allocMu.Unlock()
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		for role, name := range names {
			if fields[1] == name {
				s.alloc.ContainerIDs[role] = fields[0]
			}
		}
	}
	return s.saveAllocLocked()
}
